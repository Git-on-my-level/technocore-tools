#!/usr/bin/env python3
"""lockfree-audit — continuous, lock-free background integrity verification
for live JSONL audit trails (seq/ts/from/nonce, like evidence/raw/<room>.jsonl).

DEMAND: evidence/suggestions/tools-services/2026-09-08.md (top theme, 10 of
17 samples) — "Continuous background data-integrity verification ... without
locking production tables":
  - "Auditing data integrity across a monotonic nonce without locking
    production tables" (10:08, 11:21, 11:45) -> "Scheduled nonce-integrity
    audit job with lock-free snapshot queries"
  - ...same ask for signature chains, pagination cursors, did:key identity,
    concatenated payloads -> read-replica/continuity/binding audits.
  Ancestor ask in 2026-09-07.md: "Auditing data integrity across an atomic
  file replace without locking production tables | Explain how to perform
  continuous background verification" -> "non-blocking, background audit
  trails ... with lock-free integrity checks".

What it does (reader NEVER opens the trail for write; zero locks):
  - audit_pass(): opens O_RDONLY, resumes from the last certified byte
    offset, verifies only the delta (O(delta) work per pass), and rolls a
    chained SHA-256 over certified bytes — incremental digest == cold
    full-scan digest, so history stays provable across passes.
  - Torn-tail tolerance: a final line without a newline is an in-flight
    writer flush — excluded this pass, certified next pass. A concurrent
    writer never fails the audit.
  - Per-record invariants: seq present and strictly increasing (global);
    per-sender nonce monotone (ms/ns clocks jitter but never regress);
    per-sender timestamp monotone; JSON must parse. --strict-seq additionally
    requires gapless +1 continuity (pagination-cursor audits).
  - Tamper surface: head-window digest (first 4 KiB of the certified
    region) catches in-place rewrites; size < certified offset is a
    TRUNCATED violation (rotation/tamper — acknowledge with --reset);
    both force an explicit re-baseline, never a silent blessing.
  - State (offset/digest/last-seq/per-sender trackers) persists via
    --state PATH, so a cron/systemd job verifies each new delta cheaply;
    --watch SEC runs passes in-process for continuous background mode.

Usage:
  python3 lockfree-audit.py lobby.jsonl                     # one cold pass
  python3 lockfree-audit.py lobby.jsonl --state lobby.lfa.json   # delta pass
  python3 lockfree-audit.py lobby.jsonl --state s.json --watch 5 --max-passes 0
  python3 lockfree-audit.py lobby.jsonl --state s.json --strict-seq --json

Exit: 0 clean · 1 integrity violations · 2 usage/IO error.

VERIFY: self-test — python3 lockfree-audit.py --self-test
  Real behavior on fixtures: incremental==cold digest identity, delta-only
  resume, torn-tail exclusion then later certification, per-sender nonce/ts
  overwrite, truncation re-baseline, state round-trip, and a live threaded
  writer appending 300 records DURING auditing (zero false violations,
  everything eventually certified). Asserts, prints OK.
"""
import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone

ZERO = hashlib.sha256(b"").hexdigest()
HEAD_WINDOW = 4096          # bytes of certified prefix kept under digest watch
MAX_SENDERS = 200_000       # bound per-sender trackers; beyond: new senders untracked
CHUNK = 4 << 20             # streaming read size: memory stays bounded


def parse_ts(v):
    """ISO timestamp -> epoch float, or None if unparseable/absent."""
    if not isinstance(v, str) or not v:
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def new_state():
    return {"v": 1, "offset": 0, "digest": ZERO, "head": None,
            "last_seq": None, "lines": 0, "passes": 0, "rebaselines": 0,
            "senders": {}}


def load_state(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            st = json.load(fh)
    except (OSError, ValueError):
        return new_state()
    base = new_state()
    base.update({k: st[k] for k in base if k in st})
    return base


def save_state(path, st):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(st, fh)
    os.replace(tmp, path)          # atomic: crash never corrupts audit state


def _rebaseline(st):
    """Drop the certified frontier (rotation/overwrite); counts start a new
    epoch so total_lines always means 'records certified in the live chain'."""
    st.update(offset=0, digest=ZERO, head=None, last_seq=None, senders={},
              lines=0)
    st["rebaselines"] += 1




def audit_pass(path, st, strict_seq=False):
    """One lock-free pass over the delta since st['offset'].

    Returns a report dict; mutates st to the new certified frontier. Never
    raises on file shrink/overwrite — reports and re-baselines instead.
    """
    rep = {"new_lines": 0, "pending_bytes": 0, "rebaseline": False,
           "violations": [], "offset": None, "digest": None}
    viol = rep["violations"]
    try:
        fh = open(path, "rb")
    except OSError as e:
        return {"error": f"open: {e}", "violations": ["IO_ERROR"]}
    with fh:
        size = os.fstat(fh.fileno()).st_size
        if st["offset"] > size:
            viol.append(f"TRUNCATED: file shrank below certified offset "
                        f"{st['offset']} -> {size} (rotation or tail loss; "
                        "acknowledge with --reset)")
            _rebaseline(st)
            rep["rebaseline"] = True
        elif st["offset"] > 0:
            fh.seek(0)
            head = hashlib.sha256(fh.read(min(st["offset"], HEAD_WINDOW)))
            if st["head"] and head.hexdigest() != st["head"]:
                viol.append("HEAD_OVERWRITE: certified prefix rewritten "
                            "(first %d B digest changed)" % HEAD_WINDOW)
                _rebaseline(st)
                rep["rebaseline"] = True
        fh.seek(st["offset"])
        senders = st["senders"]
        dig = bytes.fromhex(st["digest"])       # per-line chain: resumable
        frag = b""                              # trailing bytes w/o newline
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            data = frag + chunk if frag else chunk
            cut = data.rfind(b"\n") + 1
            if not cut:                         # newline still ahead of us
                frag = data
                continue
            block, frag = data[:cut], data[cut:]
            for raw in block.splitlines():
                st["offset"] += len(raw) + 1
                dig = hashlib.sha256(dig + raw + b"\n").digest()
                rep["new_lines"] += 1
                st["lines"] += 1
                try:
                    rec = json.loads(raw)
                    assert isinstance(rec, dict)
                except (ValueError, AssertionError):
                    viol.append("MALFORMED: offset %d is not a JSON object"
                                % (st["offset"] - len(raw) - 1))
                    continue
                sender = rec.get("from")
                if not isinstance(sender, str) or not sender:
                    viol.append("SCHEMA: record at offset %d lacks 'from'"
                                % (st["offset"] - len(raw) - 1))
                    sender = "\x00unknown"
                seq = rec.get("seq")
                if not isinstance(seq, int) or isinstance(seq, bool):
                    viol.append("SCHEMA: seq missing/non-int at offset %d"
                                % (st["offset"] - len(raw) - 1))
                else:
                    if st["last_seq"] is not None:
                        if seq <= st["last_seq"]:
                            viol.append("SEQ_REGRESSION: %d after %d"
                                        % (seq, st["last_seq"]))
                        elif strict_seq and seq != st["last_seq"] + 1:
                            viol.append("SEQ_GAP: %d after %d (--strict-seq)"
                                        % (seq, st["last_seq"]))
                    st["last_seq"] = seq
                if len(senders) < MAX_SENDERS:
                    trk = senders.setdefault(sender, {"n": None, "t": None})
                else:
                    trk = senders.get(sender)
                if trk is not None:
                    nonce = rec.get("nonce")
                    if isinstance(nonce, int) and not isinstance(nonce, bool):
                        if trk["n"] is not None and nonce < trk["n"]:
                            viol.append("NONCE_REGRESSION: sender %s nonce "
                                        "%d after %d"
                                        % (sender[:24], nonce, trk["n"]))
                        trk["n"] = nonce if trk["n"] is None \
                            else max(trk["n"], nonce)
                    ts = parse_ts(rec.get("ts"))
                    if ts is None and rec.get("ts") is not None:
                        viol.append("TS_BAD: unparseable ts from %s"
                                    % sender[:24])
                    elif ts is not None:
                        if trk["t"] is not None and ts < trk["t"]:
                            viol.append("TS_REGRESSION: sender %s ts went "
                                        "backwards" % sender[:24])
                        trk["t"] = ts if trk["t"] is None \
                            else max(trk["t"], ts)
        rep["pending_bytes"] = len(frag)         # torn tail, if any
        st["digest"] = dig.hex()
        st["passes"] += 1
        if st["offset"] > 0:
            fh.seek(0)
            st["head"] = hashlib.sha256(
                fh.read(min(st["offset"], HEAD_WINDOW))).hexdigest()
    rep["offset"] = st["offset"]
    rep["digest"] = st["digest"]
    rep["total_lines"] = st["lines"]
    rep["senders_tracked"] = len(st["senders"])
    rep["head_ok"] = not any(v.startswith("HEAD_OVERWRITE") for v in viol)
    return rep


def fmt_pass(n, rep):
    if "error" in rep:
        return f"pass {n}: ERROR {rep['error']}"
    v = rep["violations"]
    vs = "none" if not v else f"{len(v)} violation(s): " + "; ".join(v[:3])
    if len(v) > 3:
        vs += f" (+{len(v) - 3} more)"
    return (f"pass {n}: +{rep['new_lines']} lines "
            f"(total {rep.get('total_lines', 0)}, "
            f"pending {rep['pending_bytes']}B, "
            f"digest {rep['digest'][:12]}…) {vs}"
            + (" [REBASELINED]" if rep["rebaseline"] else ""))


def main():
    ap = argparse.ArgumentParser(
        description="Continuous lock-free integrity audit of a live JSONL "
                    "trail: delta-only passes, torn-tail tolerance, chained "
                    "digest, no locking of the audited file.")
    ap.add_argument("path", nargs="?",
                    help="JSONL trail to audit (read-only)")
    ap.add_argument("--state", metavar="PATH",
                    help="persist certified frontier here (enables cheap "
                         "delta passes across runs); default: cold full pass")
    ap.add_argument("--strict-seq", action="store_true",
                    help="require gapless +1 seq continuity (cursor audits)")
    ap.add_argument("--watch", type=float, metavar="SEC",
                    help="continuous background mode: one pass every SEC")
    ap.add_argument("--max-passes", type=int, default=1000,
                    help="pass bound in --watch (0 = unbounded; default 1000)")
    ap.add_argument("--json", action="store_true",
                    help="print one JSON report object per pass")
    ap.add_argument("--reset", action="store_true",
                    help="start from a fresh state (acknowledge rotation)")
    ap.add_argument("--self-test", action="store_true",
                    help="run built-in verification and exit")
    a = ap.parse_args()
    if a.self_test:
        self_test()
        return
    if not a.path:
        print("error: a trail path is required (or --self-test)",
              file=sys.stderr)
        raise SystemExit(2)
    if not os.path.isfile(a.path):
        print(f"error: no such file: {a.path}", file=sys.stderr)
        raise SystemExit(2)
    if a.watch is not None and a.watch <= 0:
        print("error: --watch interval must be > 0", file=sys.stderr)
        raise SystemExit(2)
    if a.reset and a.state:
        try:
            os.unlink(a.state)
        except FileNotFoundError:
            pass
    st = load_state(a.state) if a.state and not a.reset else new_state()
    any_viol = False
    n = 0
    while True:
        n += 1
        rep = audit_pass(a.path, st, a.strict_seq)
        if "error" in rep:
            print(fmt_pass(n, rep), file=sys.stderr)
            raise SystemExit(2)
        print(json.dumps(rep, ensure_ascii=False) if a.json else fmt_pass(n, rep))
        any_viol = any_viol or bool(rep["violations"])
        if a.state:
            save_state(a.state, st)
        if a.watch is None or (a.max_passes and n >= a.max_passes):
            break
        time.sleep(a.watch)
    if any_viol:
        raise SystemExit(1)


def _w(path, lines):
    with open(path, "ab") as fh:
        for ln in lines:
            fh.write(json.dumps(ln, ensure_ascii=False).encode() + b"\n")


def self_test():
    import tempfile
    import threading
    checks = 0
    d = tempfile.mkdtemp(prefix="lfa-")
    p = os.path.join(d, "live.jsonl")
    mk = lambda seq, frm, nonce, ts: {"seq": seq, "ts": ts, "from": frm,
                                      "text": f"m{seq}", "nonce": nonce}
    t0 = "2026-09-08T10:00:00Z"
    _w(p, [mk(1, "did:key:A", 100, t0), mk(2, "did:key:A", 101, t0),
           mk(3, "did:key:B", 500, t0)])
    # cold pass, then delta pass: digest identity + delta-only work
    st = new_state()
    r1 = audit_pass(p, st)
    assert r1["new_lines"] == 3 and not r1["violations"], r1
    checks += 1
    _w(p, [mk(4, "did:key:A", 102, t0), mk(5, "did:key:B", 501, t0)])
    r2 = audit_pass(p, st)
    assert r2["new_lines"] == 2 and r2["total_lines"] == 5, r2
    assert not r2["violations"], r2
    cold = new_state()
    rc = audit_pass(p, cold)
    assert rc["digest"] == r2["digest"], "incremental digest != cold digest"
    checks += 1
    # torn tail: excluded, not a violation; certified once complete
    with open(p, "ab") as fh:
        fh.write(b'{"seq": 6, "ts": "2026-09-08T10:00:01Z", "from')
    r3 = audit_pass(p, st)
    assert r3["pending_bytes"] > 0 and not r3["violations"], r3
    assert r3["total_lines"] == 5, r3
    with open(p, "ab") as fh:
        fh.write(b': "did:key:A", "text": "m6", "nonce": 103}\n')
    r4 = audit_pass(p, st)
    assert r4["new_lines"] == 1 and r4["total_lines"] == 6, r4
    checks += 1
    # violations: seq regression, per-sender nonce + ts regression, gap, bad JSON
    p2 = os.path.join(d, "bad.jsonl")
    _w(p2, [mk(10, "did:key:C", 7, t0), mk(9, "did:key:C", 6, "2026-09-08T09:00:00Z")])
    with open(p2, "ab") as fh:
        fh.write(b'{"seq": 12, "ts": "%s", "from": "did:key:C", "nonce": 8}\n' % t0.encode())
        fh.write(b"not-json\n")
    rb = audit_pass(p2, new_state())
    kinds = " ".join(rb["violations"])
    for want in ("SEQ_REGRESSION", "NONCE_REGRESSION", "TS_REGRESSION", "MALFORMED"):
        assert want in kinds, (want, rb["violations"])
    checks += 1
    pg = os.path.join(d, "gap.jsonl")
    _w(pg, [mk(1, "did:key:D", 1, t0), mk(3, "did:key:D", 2, t0)])
    rg = audit_pass(pg, new_state(), strict_seq=True)
    assert any("SEQ_GAP" in v for v in rg["violations"]), rg
    assert not audit_pass(pg, new_state())["violations"], "gap must need --strict-seq"
    checks += 1
    # head-window overwrite: certified prefix rewritten -> violation + re-baseline
    data = open(p, "rb").read()
    with open(p, "wb") as fh:
        fh.write(data.replace(b'"m1"', b'"X1"', 1))
    ro = audit_pass(p, st)
    assert ro["rebaseline"] and any("HEAD_OVERWRITE" in v for v in ro["violations"]), ro
    assert ro["total_lines"] == 6, ro          # re-baseline recertified all
    checks += 1
    # truncation: shrink below offset -> TRUNCATED violation, then recovery
    with open(p, "wb") as fh:
        fh.write(data[:data.index(b"\n") + 1])
    rt = audit_pass(p, st)
    assert rt["rebaseline"] and any("TRUNCATED" in v for v in rt["violations"]), rt
    _w(p, [mk(99, "did:key:Z", 1, t0)])
    rt2 = audit_pass(p, st)
    assert rt2["new_lines"] == 1 and rt2["total_lines"] == 2, rt2
    checks += 1
    # state round-trip preserves the frontier
    sp = os.path.join(d, "st.json")
    save_state(sp, st)
    st2 = load_state(sp)
    assert st2["offset"] == st["offset"] and st2["digest"] == st["digest"], st2
    assert audit_pass(p, st2)["new_lines"] == 0, "resume must be delta-only"
    checks += 1
    # lock-free headline: threaded writer appends 300 records DURING auditing
    p3 = os.path.join(d, "concurrent.jsonl")
    _w(p3, [mk(0, "did:key:W", 0, t0)])
    done = threading.Event()

    def writer():
        for i in range(1, 301):
            _w(p3, [mk(i, "did:key:W", 1000 + i, f"2026-09-08T10:{i // 60:02d}:{i % 60:02d}Z")])
            time.sleep(0.001)
        with open(p3, "ab") as fh:            # leave one torn tail behind
            fh.write(b'{"seq": 301, "ts": "2026-09-08T10:05:00Z", "fr')
        done.set()

    st3 = new_state()
    th = threading.Thread(target=writer)
    th.start()
    passes = 0
    while (not done.is_set() and th.is_alive()) or passes == 0:
        rp = audit_pass(p3, st3)
        assert not rp["violations"], rp         # concurrent writes never fail us
        passes += 1
    th.join()
    rp = audit_pass(p3, st3)                    # picks up everything but the tail
    assert rp["total_lines"] == 301 and rp["pending_bytes"] > 0, rp
    assert not rp["violations"], rp
    cold3 = new_state()
    rc3 = audit_pass(p3, cold3)
    assert rc3["digest"] == st3["digest"] and cold3["lines"] == 301, rc3
    checks += 1
    # fmt_pass renders a readable line for a clean and a dirty report
    line = fmt_pass(1, {"new_lines": 0, "pending_bytes": 4, "rebaseline": False,
                        "violations": [], "digest": "ab" * 32, "total_lines": 1})
    assert "pass 1" in line and line.rstrip().endswith("none"), line
    checks += 1
    print(f"self-test OK ({checks} assertions)")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
