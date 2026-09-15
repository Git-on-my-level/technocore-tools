#!/usr/bin/env python3
"""seq-trail-audit — monotonic sequence-number audit for signed-message
trails: per-DID gap detection, same-seq body conflicts, cross-receiver
history forks, timestamp regressions, and a walkable trail reconstruction.

DEMAND: evidence/suggestions/tools-services/2026-09-15.md
  - 09:50 run: "Sequence-gap / monotonic-sequence-number verification" —
    evidence: "ULnx's gap-audit point is the most concrete thing said here
    today." / "Signatures prove origin, not causal order. Without monotonic
    sequence numbers or parent state hashes, peer can fork history across
    receivers undetected." — proposed service: "Gap-detection service that
    flags missing sequence numbers or detects forking of history across
    receivers."
  - 03:44 run: "Need ability to audit agent contribution history and DID
    trails more easily" — evidence: "every signed message returns a seq
    number. Read the room with --since <seq> and you can walk an agent's
    full trail." — proposed service: "audit trail visualization tool for
    agent history and DID verification."
  - 03:44 run: "audit trail timestamp issues causing proof rejections" —
    "two proofs bounce ... because the timestamp chain didn't line up" —
    covered by the ts-regression detector.

Input: one or more JSONL captures. Each line: {"seq": int, "ts": ISO-8601
or epoch, "from": did, "text"?, "nonce"?, "room"?, "receiver"?}. A capture
file is one receiver's view of the trail (label = file basename); a
record-level "receiver" field overrides, so merged exports also work. Body
identity = sha256 over canonical [from, text, nonce] — two records with the
same (from, seq) but different bodies is a rewrite/replay (one receiver) or
a history fork (different receivers), the exact undetectable-fork failure
the demand describes. Pure parsing: no network, no subprocess. Stdlib only.

Findings (rc 1 if any, 0 clean, 2 usage/IO):
  history-fork   BLOCK  same (did,seq), different bodies in different views
  seq-conflict   BLOCK  same (did,seq), different bodies in ONE view
  seq-gap        WARN   missing seq numbers inside a view's span
  divergent-view WARN   overlap span where two receivers saw different sets
  ts-regression  WARN   ts goes backwards as seq rises (timestamp chain)
  dup-record     INFO   identical (did,seq,body) seen again in a view
  malformed-line INFO   unparsable line / missing seq|from|ts

Usage:
  seq-trail-audit.py recvA.jsonl recvB.jsonl     # cross-receiver audit
  seq-trail-audit.py --did did:key:z6Mk... . cap.jsonl   # walk one trail
  seq-trail-audit.py --json merged.jsonl         # machine blob
Knobs: --gap-min N (ignore gaps smaller than N, default 1),
       --regress-secs S (tolerate <=S seconds of ts regression, default 0).

VERIFY: self-test — python3 seq-trail-audit.py --self-test
  Hand-computed fixtures for every detector; benign trail asserted fully
  silent with the exact row dict; gap arithmetic (1,2,5,6 -> missing 3-4);
  dup folding (4 lines -> 3 msgs); conflict vs fork split by view; overlap
  divergence survives --gap-min that silences the per-view gap; ts
  regression delta hand-checked incl. ISO-vs-epoch equivalence; malformed
  hand-counted; DID isolation; receiver-field override; CLI rc contract +
  json/report shape; deep-dive gap markers. Mutation probe: a forced-fail
  assert appended after the __main__ block must make rc nonzero.
"""
import argparse
import datetime as dt
import hashlib
import json
import sys


def parse_ts(v):
    """ISO-8601 string or epoch number -> float seconds; None if unfit."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        s = v.strip()
        if s.replace(".", "", 1).isdigit():
            return float(s)
        try:
            d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
            return d.timestamp()
        except ValueError:
            return None
    return None


def body_fp(frm, text, nonce):
    canon = json.dumps([frm, text, nonce], ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def load_views(paths):
    """paths (files or '-') -> ({receiver: [rec,...]}, malformed count).

    Receiver label: record's "receiver" field wins; else the file's
    basename ('stdin' for -); colliding basenames get a #N suffix.
    rec = {"seq": int, "ts": float, "did": str, "fp": str, "room": str}
    """
    views, malformed = {}, 0
    labels = {}
    for i, path in enumerate(paths):
        base = "stdin" if path == "-" else path.rsplit("/", 1)[-1]
        label = base
        if label in labels:
            label = f"{base}#{labels[base]}"
        labels[base] = labels.get(base, 1) + 1
        fh = sys.stdin if path == "-" else open(path, errors="replace")
        with fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    seq = obj["seq"]
                    ts = parse_ts(obj["ts"])
                    frm = obj["from"]
                    if not isinstance(seq, int) or isinstance(seq, bool) \
                            or ts is None or not isinstance(frm, str):
                        raise ValueError
                except (ValueError, KeyError, TypeError):
                    malformed += 1
                    continue
                rec = {"seq": seq, "ts": ts, "did": frm,
                       "fp": body_fp(frm, obj.get("text"),
                                     obj.get("nonce")),
                       "room": str(obj.get("room", "-"))}
                recv_field = obj.get("receiver")
                recv = recv_field if isinstance(recv_field, str) \
                    and recv_field else label
                views.setdefault(recv, []).append(rec)
    return views, malformed


def gap_ranges(seqs):
    """Sorted unique seqs -> list of missing inclusive ranges inside span."""
    gaps = []
    for a, b in zip(seqs, seqs[1:]):
        if b > a + 1:
            gaps.append((a + 1, b - 1))
    return gaps


def _fmt_ranges(gaps):
    return ", ".join(str(a) if a == b else f"{a}-{b}" for a, b in gaps)


def analyze(views, malformed, gap_min=1, regress_secs=0.0):
    """-> (findings, rows). findings: {code,sev,did,detail}; rows per DID."""
    findings = []

    def add(code, sev, did, detail):
        findings.append({"code": code, "sev": sev, "did": did,
                         "detail": detail})

    if malformed:
        add("malformed-line", "INFO", "-", f"{malformed} unparsable line(s)")

    # per (receiver, did) view: dedup dups, flag conflicts/gaps/regressions
    per_did = {}  # did -> {recv: {seq: [fp,...]}} plus ts/fp of first entry
    meta = {}     # (did, recv, seq) -> (ts, room) of first arrival
    for recv in sorted(views):
        dids = {}
        for rec in views[recv]:
            dids.setdefault(rec["did"], []).append(rec)
        for did in sorted(dids):
            by_seq = {}
            for rec in dids[did]:
                by_seq.setdefault(rec["seq"], []).append(rec)
            for seq, recs in sorted(by_seq.items()):
                fps = {r["fp"] for r in recs}
                if len(fps) > 1:
                    add("seq-conflict", "BLOCK", did,
                        f"seq {seq}: {len(fps)} distinct bodies in {recv}")
                elif len(recs) > 1:
                    add("dup-record", "INFO", did,
                        f"seq {seq}: {len(recs) - 1} duplicate(s) in {recv}")
                first = sorted(recs, key=lambda r: r["ts"])[0]
                meta[(did, recv, seq)] = (first["ts"], first["room"])
                per_did.setdefault(did, {}).setdefault(recv, {})[seq] = \
                    sorted(fps)
            seqs = sorted(by_seq)
            gaps = [(a, b) for a, b in gap_ranges(seqs)
                    if b - a + 1 >= gap_min]
            if gaps:
                n = sum(b - a + 1 for a, b in gaps)
                add("seq-gap", "WARN", did,
                    f"{recv}: missing {n}: {_fmt_ranges(gaps)}")
            for a, b in zip(seqs, seqs[1:]):
                ta, tb = meta[(did, recv, a)][0], meta[(did, recv, b)][0]
                if tb < ta - regress_secs:
                    add("ts-regression", "WARN", did,
                        f"{recv}: seq {a}->{b} ts {ta:g} -> {tb:g} "
                        f"({tb - ta:g}s)")

    # cross-receiver: forks + divergent overlap
    for did in sorted(per_did):
        rv = per_did[did]
        if len(rv) < 2:
            continue
        allseq = sorted({s for m in rv.values() for s in m})
        for seq in allseq:
            holders = [(r, fp) for r in sorted(rv) if seq in rv[r]
                       for fp in rv[r][seq]]
            pair = next(((r1, f1, r2, f2)
                         for r1, f1 in holders
                         for r2, f2 in holders
                         if r1 < r2 and f1 != f2), None)
            if pair:
                r1, f1, r2, f2 = pair
                add("history-fork", "BLOCK", did,
                    f"seq {seq}: {r1} body {f1[:8]} vs {r2} body {f2[:8]}")
        recvs = sorted(rv)
        for i, r1 in enumerate(recvs):
            for r2 in recvs[i + 1:]:
                s1, s2 = set(rv[r1]), set(rv[r2])
                lo = max(min(s1), min(s2))
                hi = min(max(s1), max(s2))
                miss2 = sorted(s for s in s1 if lo <= s <= hi and s not in s2)
                miss1 = sorted(s for s in s2 if lo <= s <= hi and s not in s1)
                for who, other, miss in ((r2, r1, miss2), (r1, r2, miss1)):
                    if miss:
                        shown = ", ".join(map(str, miss[:3]))
                        more = f" (+{len(miss) - 3} more)" \
                            if len(miss) > 3 else ""
                        add("divergent-view", "WARN", did,
                            f"{who} missing {len(miss)} of {other}'s "
                            f"seqs in overlap {lo}-{hi}: {shown}{more}")

    rows = []
    for did in sorted(per_did):
        rv = per_did[did]
        allseq = sorted({s for m in rv.values() for s in m})
        gaps = gap_ranges(allseq)
        rooms = {meta[(did, r, s)][1] for r in rv for s in rv[r]}
        tss = [meta[(did, r, s)][0] for r in rv for s in rv[r]]
        conflicts = sum(1 for f in findings if f["did"] == did
                        and f["sev"] == "BLOCK")
        rows.append({"did": did, "views": len(rv), "msgs": len(allseq),
                     "span": f"{allseq[0]}-{allseq[-1]}",
                     "missing": sum(b - a + 1 for a, b in gaps),
                     "rooms": len(rooms), "conflicts": conflicts,
                     "first_ts": min(tss), "last_ts": max(tss)})
    return findings, rows


def deep_dive(views, did):
    """Walkable trail for one DID: per-view seq lines with gap markers."""
    out = [f"trail {did}"]
    dids = {}
    for recv in sorted(views):
        recs = [r for r in views[recv] if r["did"] == did]
        if not recs:
            continue
        dids[recv] = recs
    for recv, recs in dids.items():
        by_seq = {}
        for r in recs:
            by_seq.setdefault(r["seq"], []).append(r)
        out.append(f"  view {recv}: {len(by_seq)} msg(s)")
        prev = None
        for seq in sorted(by_seq):
            if prev is not None and seq > prev + 1:
                out.append(f"    ... gap {prev + 1}-{seq - 1} "
                           f"({seq - prev - 1} missing) ...")
            for r in sorted(by_seq[seq], key=lambda r: r["ts"]):
                out.append(f"    seq {seq}  ts {r['ts']:g}  "
                           f"room {r['room']}  fp {r['fp'][:8]}")
            prev = seq
    if len(out) == 1:
        out.append("  (no records)")
    return "\n".join(out)


def fmt_report(findings, rows, nviews, malformed):
    sev_rank = {"BLOCK": 0, "WARN": 1, "INFO": 2}
    lines = [f"seq-trail-audit: {nviews} view(s), {len(rows)} DID(s), "
             f"{malformed} malformed line(s)",
             f"{'DID':<28} {'views':>5} {'msgs':>5} {'span':>9} "
             f"{'miss':>4} {'rooms':>5} {'conf':>4}"]
    for r in rows:
        lines.append(f"{r['did'][:28]:<28} {r['views']:>5} {r['msgs']:>5} "
                     f"{r['span']:>9} {r['missing']:>4} {r['rooms']:>5} "
                     f"{r['conflicts']:>4}")
    if findings:
        lines.append("findings:")
        for f in sorted(findings,
                        key=lambda f: (sev_rank[f["sev"]], f["did"],
                                       f["code"])):
            lines.append(f"[{f['sev']}] {f['code']} did={f['did'][:24]} "
                         f"{f['detail']}")
    else:
        lines.append("no findings: every view is gap-free, body-consistent, "
                     "and in timestamp order")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="monotonic seq-number / history-fork audit for signed "
                    "message trails (JSONL captures)")
    ap.add_argument("paths", nargs="+", help="JSONL capture(s) or '-'")
    ap.add_argument("--gap-min", type=int, default=1,
                    help="ignore gaps smaller than N seqs (default 1)")
    ap.add_argument("--regress-secs", type=float, default=0.0,
                    help="tolerate <=S seconds of ts regression (default 0)")
    ap.add_argument("--did", help="deep-dive one DID's trail")
    ap.add_argument("--json", action="store_true", help="machine output")
    args = ap.parse_args(argv)

    try:
        views, malformed = load_views(args.paths)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    findings, rows = analyze(views, malformed, args.gap_min,
                             args.regress_secs)
    if args.json:
        print(json.dumps({"views": sorted(views), "dids": rows,
                          "findings": findings}, ensure_ascii=False))
    elif args.did:
        print(deep_dive(views, args.did))
        findings = [f for f in findings if f["did"] == args.did]
        for f in findings:
            print(f"[{f['sev']}] {f['code']} {f['detail']}")
    else:
        print(fmt_report(findings, rows, len(views), malformed))
    return 1 if findings else 0


def self_test():
    import io
    import os
    import tempfile
    from contextlib import redirect_stdout

    def _rec(seq, ts, frm="did:key:A", text=None, nonce=None, room="meta",
             receiver=None):
        r = {"seq": seq, "ts": ts, "from": frm}
        if text is not None:
            r["text"] = text
        if nonce is not None:
            r["nonce"] = nonce
        if room is not None:
            r["room"] = room
        if receiver is not None:
            r["receiver"] = receiver
        return r
    def run(caps, extra=()):
        """caps: list of captures (each a list of records/strings) -> files."""
        paths = []
        try:
            for cap in caps:
                with tempfile.NamedTemporaryFile(
                        "w", suffix=".jsonl", delete=False) as tf:
                    for rec in cap:
                        tf.write((rec if isinstance(rec, str)
                                  else json.dumps(rec)) + "\n")
                    paths.append(tf.name)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main([*paths, *extra])
            return rc, buf.getvalue()
        finally:
            for p in paths:
                os.unlink(p)

    def codes(out_json):
        return [f["code"] for f in json.loads(out_json)["findings"]]

    # 1. benign trail: fully silent, exact row dict hand-computed
    rc, out = run([[_rec(1, 100), _rec(2, 110), _rec(3, 120)]])
    assert rc == 0 and "no findings" in out, (rc, out)
    doc = json.loads(run([[_rec(1, 100), _rec(2, 110), _rec(3, 120)]],
                         ["--json"])[1])
    assert doc["findings"] == [] and doc["dids"] == [{
        "did": "did:key:A", "views": 1, "msgs": 3, "span": "1-3",
        "missing": 0, "rooms": 1, "conflicts": 0,
        "first_ts": 100.0, "last_ts": 120.0}], doc

    # 2. gap: 1,2,5,6 -> missing {3,4} = 2; silent at --gap-min 3
    cap = [_rec(1, 100), _rec(2, 110), _rec(5, 140), _rec(6, 150)]
    rc, out = run([cap], ["--json"])
    assert rc == 1 and codes(out) == ["seq-gap"], out
    assert "missing 2: 3-4" in out, out
    rc, out = run([cap], ["--json", "--gap-min", "3"])
    assert rc == 0 and codes(out) == [], out

    # 3. dup: seq 2 twice, identical body -> INFO; rows count 3 msgs
    cap = [_rec(1, 100), _rec(2, 110), _rec(2, 110), _rec(3, 120)]
    rc, out = run([cap], ["--json"])
    assert rc == 1 and codes(out) == ["dup-record"], out
    assert "1 duplicate" in out and json.loads(out)["dids"][0]["msgs"] == 3

    # 4. seq-conflict: one view, seq 2 with two bodies -> BLOCK
    cap = [_rec(1, 100), _rec(2, 110, text="x"), _rec(2, 115, text="y")]
    rc, out = run([cap], ["--json"])
    assert rc == 1 and codes(out) == ["seq-conflict"], out
    assert "2 distinct bodies" in out and json.loads(
        out)["dids"][0]["conflicts"] == 1

    # 5. history-fork: recvA seq2="x" vs recvB seq2="y" -> exactly one
    #    BLOCK, no within-view conflict, no divergence
    a = [_rec(1, 100, receiver="recvA"), _rec(2, 110, text="x",
                                               receiver="recvA"),
         _rec(3, 120, receiver="recvA")]
    b = [_rec(1, 101, receiver="recvB"), _rec(2, 111, text="y",
                                               receiver="recvB"),
         _rec(3, 121, receiver="recvB")]
    rc, out = run([a, b], ["--json"])
    assert rc == 1 and codes(out) == ["history-fork"], out
    assert "recvA body " in out and "recvB body " in out, out
    assert json.loads(out)["dids"][0]["views"] == 2
    # three views: first/last alpha share a body, middle diverges —
    # must cite a pair that actually differs (not recvA vs recvC)
    a = [_rec(2, 110, text="x", receiver="recvA")]
    b = [_rec(2, 111, text="y", receiver="recvB")]
    c = [_rec(2, 112, text="x", receiver="recvC")]
    rc, out = run([a, b, c], ["--json"])
    assert codes(out) == ["history-fork"], out
    detail = json.loads(out)["findings"][0]["detail"]
    hx = body_fp("did:key:A", "x", None)[:8]
    hy = body_fp("did:key:A", "y", None)[:8]
    assert hx in detail and hy in detail and "recvB" in detail, detail
    # intra-view conflict: extra body dropped by fps[0] still forks
    a = [_rec(2, 110, text="x", receiver="recvA"),
         _rec(2, 115, text="y", receiver="recvA")]
    b = [_rec(2, 111, text="y", receiver="recvB")]
    rc, out = run([a, b], ["--json"])
    assert set(codes(out)) == {"seq-conflict", "history-fork"}, out
    assert hx in out and hy in out, out

    # 6. divergent overlap: recvB lacks 3 of 1..5; survives --gap-min 2
    #    (which silences recvB's own per-view gap)
    a = [_rec(s, 100 + 10 * s, receiver="recvA") for s in range(1, 6)]
    b = [_rec(s, 101 + 10 * s, receiver="recvB") for s in (1, 2, 4, 5)]
    rc, out = run([a, b], ["--json"])
    assert set(codes(out)) == {"seq-gap", "divergent-view"}, out
    assert "recvB: missing 1: 3" in out, out
    assert "recvB missing 1 of recvA's seqs in overlap 1-5: 3" in out, out
    rc, out = run([a, b], ["--json", "--gap-min", "2"])
    assert codes(out) == ["divergent-view"], out

    # 7. ts-regression: seq2 ts 90 after seq1 ts 100 -> -10s; tolerant knob;
    #    ISO spelling equivalent
    cap = [_rec(1, 100), _rec(2, 90)]
    rc, out = run([cap], ["--json"])
    assert rc == 1 and codes(out) == ["ts-regression"], out
    assert "-10s" in out, out
    rc, _ = run([cap], ["--json", "--regress-secs", "15"])
    assert rc == 0
    iso = [_rec(1, "2026-09-15T10:00:00Z"), _rec(2, "2026-09-15T09:59:50Z")]
    rc, out = run([iso], ["--json"])
    assert codes(out) == ["ts-regression"] and "-10s" in out, out

    # 8. malformed: junk + missing from + non-int seq -> 3 counted
    cap = ['{"broken', {"seq": 5, "ts": 1}, _rec("x", 1)]
    rc, out = run([cap], ["--json"])
    assert rc == 1 and "3 unparsable" in out, out

    # 9. DID isolation: gapped A, clean B -> findings name A only
    cap = [_rec(1, 100, frm="did:key:A"), _rec(3, 120, frm="did:key:A"),
           _rec(1, 100, frm="did:key:B"), _rec(2, 110, frm="did:key:B")]
    rc, out = run([cap], ["--json"])
    assert codes(out) == ["seq-gap"] and 'did:key:A' in out, out
    assert json.loads(out)["dids"][1]["did"] == "did:key:B"

    # 10. receiver-field override: one file, two embedded views -> fork
    cap = [_rec(1, 100, receiver="r1"), _rec(2, 110, text="x",
                                             receiver="r1"),
           _rec(1, 101, receiver="r2"), _rec(2, 111, text="y",
                                             receiver="r2")]
    rc, out = run([cap], ["--json"])
    assert codes(out) == ["history-fork"] and '"r1"' in out, out

    # 11. deep dive: gap marker + seq lines + per-finding echo
    cap = [_rec(1, 100), _rec(2, 110), _rec(5, 140, room="lobby")]
    rc, out = run([cap], ["--did", "did:key:A"])
    assert rc == 1 and "gap 3-4" in out and "seq 5" in out, out
    assert "room lobby" in out and "[WARN] seq-gap" in out, out
    # clean DID walk must not inherit another DID's gap or malformed-line
    cap = [_rec(1, 100), _rec(2, 110), _rec(3, 120),
           _rec(1, 200, frm="did:key:B"), _rec(3, 220, frm="did:key:B"),
           '{"nope']
    rc, out = run([cap], ["--did", "did:key:A"])
    assert rc == 0 and "[WARN]" not in out and "[INFO]" not in out, (rc, out)
    assert "trail did:key:A" in out, out

    # 12. CLI contract: rc 2 unreadable; report columns; views listed
    assert main(["/nonexistent.jsonl"]) == 2
    rc, out = run([[_rec(1, 100)]], [])
    assert rc == 0 and "miss" in out and "conf" in out, out
    rc, out = run([[_rec(1, 100, receiver="capX")]], ["--json"])
    assert json.loads(out)["views"] == ["capX"], out
    cap = [{"seq": 1, "ts": 1, "from": "did:key:A", "receiver": None}]
    rc, out = run([cap], ["--json"])
    vs = json.loads(out)["views"]
    assert len(vs) == 1 and vs[0].endswith(".jsonl"), vs  # null -> file label

    print("seq-trail-audit self-test OK (12 groups: benign row, gap+knob, "
          "dup folding, conflict-vs-fork split, divergent overlap, "
          "ts-regression incl. ISO, malformed count, DID isolation, "
          "receiver override, deep dive, CLI contract)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this line)
    else:
        raise SystemExit(main())
