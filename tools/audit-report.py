#!/usr/bin/env python3
"""audit-report — render one self-contained HTML audit status document
(dashboard + standardized proof export) from a room/event JSONL export
(records with seq/ts/from/text/nonce, like evidence/raw/<room>.jsonl).

DEMAND: evidence/suggestions/tools-services/2026-08-31.md
  - "为用户提供审计状态仪表盘或可视化界面，以监控序列连续性和时间戳
    完整性" — users need an audit status dashboard/visualization to monitor
    sequence continuity and timestamp integrity; "开发一个Web仪表盘，实时
    显示验证状态、完整性指标和异常警报" — show verification status,
    integrity metrics, anomaly alerts. (10:03 run)
  - "生成符合监管要求的标准化审计报告或证明文件" — generate standardized,
    regulator-facing audit reports / proof documents; "可配置的报告导出
    功能，生成PDF或结构化数据格式的审计证明" — configurable export as a
    structured-data audit attestation. (--json emits exactly that.)
  - "An integrity checker that verifies sequence IDs and timestamp
    ordering, then emits a signed audit proof" (21:09 run); "cheaper
    verifiability — when every step is signed and auditable" (2026-09-01):
    one shareable file anyone can open — no server, no dependencies.

What it does (read-only; the export is data, never interpreted or run):
  - streams the export once: audit-chain-compatible hash chain + merkle
    root, sequence continuity (duplicates/gaps/reorders), timestamp
    integrity (invalid/regressions), per-sender nonce regressions,
    malformed lines, sender and template-flood stats.
  - seal check: auto-loads FILE.seal.json (or --seal) written by
    audit-chain.py and recomputes chain head / merkle root / counts —
    verdict INTACT or TAMPERED (which fields diverge). No seal file →
    chain anchors are still embedded in the document.
  - attestation check: auto-loads FILE.attest.json (or --attest) written
    by offline-verify.py and re-hashes the file — MATCH or MISMATCH
    (file changed since it was attested). Signature checking stays with
    offline-verify.py; this reports digest agreement only.
  - writes OUT.html (default <FILE>.report.html): status badges, metric
    cards, anomaly tables, top senders/templates, and an embedded
    machine-readable proof block so the single file serves as both
    dashboard and standardized proof document.
  - --json prints the proof object instead of writing HTML.
  All room content is HTML-escaped; the document is static — no scripts
  run when opened. Exit 0 clean / 1 anomalies-or-tamper / 2 usage, I/O.

Usage:
  python3 audit-report.py evidence/raw/validators.jsonl
  python3 audit-report.py lobby.jsonl --seal lobby.jsonl.seal.json -o s.html
  python3 audit-report.py lobby.jsonl --attest lobby.jsonl.attest.json
  python3 audit-report.py lobby.jsonl --json > proof.json

VERIFY: self-test — python3 audit-report.py --self-test
  Real behavior on fixtures: exact seq/ts/nonce/unparsable counts; chain
  head and merkle root independently re-derived with inline hashlib; seal
  intact/tampered/diverged-field verdicts; attestation match and
  post-edit mismatch; HTML escaping of hostile text; embedded proof JSON
  round-trip; --json output; clean=exit 0, anomaly=exit 1. Asserts, OK.
"""
import argparse
import hashlib
import html
import json
import os
import re
import sys
import tempfile
from datetime import datetime

GENESIS = "0" * 64
EXAMPLES = 8                # max examples kept per anomaly class
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T[0-9:.]+Z?")
_DID = re.compile(r"did:\w+:[A-Za-z0-9]{8,}")
_HEX = re.compile(r"0x[0-9a-fA-F]{4,}")
_NUM = re.compile(r"\d+(?:[.,]\d+)*")
GOOD = ("PASS", "INTACT", "MATCH", "OK", "NONE")


def canonical(rec):
    return json.dumps(rec, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"))


def parse_ts(ts):
    if not isinstance(ts, str) or not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def template(text):
    """Message with volatile payload tokens masked (flood templates)."""
    t = _TS.sub("<ts>", _DID.sub("<did>", _HEX.sub("<hex>", str(text))))
    return " ".join(_NUM.sub("<n>", t).split())[:100]


def analyze(path):
    """One pass: chain anchors + every integrity metric the report shows."""
    r = {"records": 0, "unparsable": 0, "chain_head": None, "merkle_root": None,
         "seq": {"duplicates": 0, "gaps": 0, "reorders": 0, "examples": []},
         "ts": {"invalid": 0, "regressions": 0, "examples": []},
         "nonce": {"regressions": 0, "examples": []},
         "senders": 0, "first_ts": None, "last_ts": None,
         "top_templates": [], "top_senders": []}
    head, blob = bytes.fromhex(GENESIS), bytearray()
    tc, sc, last_seq, last_dt, last_nonce = {}, {}, None, None, {}

    def note(kind, msg):
        if len(r[kind]["examples"]) < EXAMPLES:
            r[kind]["examples"].append(msg)

    with open(path, encoding="utf-8", errors="replace") as fh:
        for i, raw in enumerate(fh):
            s = raw.strip()
            if not s:
                continue
            r["records"] += 1
            try:
                rec = json.loads(s)
                d = hashlib.sha256(canonical(rec).encode()).digest()
            except ValueError:
                r["unparsable"] += 1
                note("ts", f"line {i}: not JSON")
                rec, d = None, hashlib.sha256(raw.encode()).digest()
            head = hashlib.sha256(head + d).digest()
            blob += d
            if rec is None:
                continue
            seq, ts, who = rec.get("seq"), rec.get("ts"), rec.get("from")
            if isinstance(seq, int) and isinstance(last_seq, int):
                if seq == last_seq:
                    r["seq"]["duplicates"] += 1
                    note("seq", f"line {i}: seq {seq} repeats")
                elif seq < last_seq:
                    r["seq"]["reorders"] += 1
                    note("seq", f"line {i}: seq {seq} after {last_seq}")
                elif seq > last_seq + 1:
                    r["seq"]["gaps"] += 1
                    note("seq", f"line {i}: seq jumps {last_seq}->{seq}")
            if isinstance(seq, int) or last_seq is None:
                last_seq = seq if isinstance(seq, int) else last_seq
            dt = parse_ts(ts)
            if dt is None:
                if ts is not None:
                    r["ts"]["invalid"] += 1
                    note("ts", f"line {i}: bad ts {ts!r}")
            else:
                r["first_ts"] = r["first_ts"] or ts
                r["last_ts"] = ts
                if last_dt is not None and dt < last_dt:
                    r["ts"]["regressions"] += 1
                    note("ts", f"line {i}: ts {ts} before previous")
                last_dt = dt
            if isinstance(who, str):
                sc[who] = sc.get(who, 0) + 1
            nonce = rec.get("nonce")
            if isinstance(who, str) and isinstance(nonce, int):
                prev = last_nonce.get(who)
                if prev is not None and nonce <= prev:
                    r["nonce"]["regressions"] += 1
                    note("nonce", f"line {i} (seq {seq}): {who[:24]} "
                                  f"nonce {nonce} <= {prev}")
                last_nonce[who] = nonce if prev is None else max(prev, nonce)
            tmpl = template(rec.get("text", ""))
            tc[tmpl] = tc.get(tmpl, 0) + 1
    r["chain_head"] = head.hex()
    r["merkle_root"] = merkle(blob)
    r["senders"] = len(sc)
    r["top_templates"] = sorted(tc.items(), key=lambda kv: -kv[1])[:10]
    r["top_senders"] = sorted(sc.items(), key=lambda kv: -kv[1])[:10]
    return r


def merkle(blob):
    """Merkle root over 32-byte leaves; odd level duplicates last leaf."""
    if not blob:
        return hashlib.sha256(b"").hexdigest()
    cur, cnt = bytes(blob), len(blob) // 32
    while cnt > 1:
        if cnt % 2:
            cur += cur[-32:]
            cnt += 1
        cur = b"".join(hashlib.sha256(cur[i:i + 64]).digest()
                       for i in range(0, cnt * 32, 64))
        cnt //= 2
    return cur.hex()


def check_seal(path, seal):
    """Compare a fresh scan against an audit-chain seal. -> verdict dict."""
    if not isinstance(seal, dict) or "chain_head" not in seal:
        return {"status": "UNREADABLE", "diverged": ["seal format"]}
    got = analyze(path)
    want = {"chain_head": seal.get("chain_head"),
            "merkle_root": seal.get("merkle_root"),
            "records": seal.get("records"),
            "unparsable": seal.get("unparsable")}
    bad = [k for k in want if want[k] is not None and want[k] != got[k]]
    return {"status": "INTACT" if not bad else "TAMPERED", "diverged": bad}


def check_attest(path, attest):
    """Digest agreement with an offline-verify attestation. -> verdict."""
    try:
        data = open(path, "rb").read()
    except OSError:
        return {"status": "UNREADABLE", "detail": "cannot read file"}
    if not isinstance(attest, dict) or "sha256" not in attest:
        return {"status": "UNREADABLE", "detail": "attest format"}
    ok = hashlib.sha256(data).hexdigest() == attest["sha256"] \
        and attest.get("bytes") in (None, len(data))
    return {"status": "MATCH" if ok else "MISMATCH",
            "detail": "" if ok else "file changed since attestation "
            "(re-run offline-verify.py for the signature verdict)"}


def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def proof_of(src, a, seal_v, attest_v):
    """The machine-readable standardized audit object."""
    return {"tool": "audit-report", "version": 1, "source": src,
            "generated": datetime.now().astimezone().isoformat(timespec="seconds"),
            "records": a["records"], "unparsable": a["unparsable"],
            "chain_head": a["chain_head"], "merkle_root": a["merkle_root"],
            "integrity": {"seq": a["seq"], "ts": a["ts"], "nonce": a["nonce"],
                          "senders": a["senders"], "first_ts": a["first_ts"],
                          "last_ts": a["last_ts"]},
            "seal_check": seal_v or {"status": "NONE"},
            "attestation_check": attest_v or {"status": "NONE"}}


def esc(x):
    return html.escape(str(x), quote=True)


def badge(name, value):
    cls = "ok" if value in GOOD else "bad"
    return f'<span class="b {cls}">{esc(name)}: {esc(value)}</span>'


def card(name, value):
    return (f'<div class="c"><div class="v">{esc(value)}</div>'
            f'<div class="k">{esc(name)}</div></div>')


def rows_of(pairs):
    return "".join(f"<tr><td>{esc(a)}</td><td>{esc(b)}</td></tr>"
                   for a, b in pairs) or "<tr><td>—</td><td>none</td></tr>"


def render(src, a, seal_v, attest_v):
    """Self-contained static HTML: badges, metrics, anomalies, floods, proof."""
    clean = not any([a["seq"]["duplicates"], a["seq"]["gaps"],
                     a["seq"]["reorders"], a["ts"]["invalid"],
                     a["ts"]["regressions"], a["nonce"]["regressions"],
                     a["unparsable"]])
    tamper = [v["status"] for v in (seal_v, attest_v)
              if v and v["status"] in ("TAMPERED", "MISMATCH", "UNREADABLE")]
    badges = [badge("Overall", "PASS" if clean and not tamper else "ALERT"),
              badge("Seal", (seal_v or {}).get("status", "NONE")),
              badge("Attestation", (attest_v or {}).get("status", "NONE")),
              badge("Sequence", "OK" if not (a["seq"]["duplicates"]
                     or a["seq"]["gaps"] or a["seq"]["reorders"]) else "ANOMALY"),
              badge("Timestamps", "OK" if not (a["ts"]["invalid"]
                     or a["ts"]["regressions"]) else "ANOMALY")]
    cards = "".join([card("Records", a["records"]), card("Senders", a["senders"]),
                     card("Seq dup/gap/reorder",
                          f'{a["seq"]["duplicates"]}/{a["seq"]["gaps"]}/'
                          f'{a["seq"]["reorders"]}'),
                     card("Ts invalid/regressed",
                          f'{a["ts"]["invalid"]}/{a["ts"]["regressions"]}'),
                     card("Unparsable lines", a["unparsable"]),
                     card("Chain head", a["chain_head"][:16] + "…"),
                     card("Merkle root", a["merkle_root"][:16] + "…")] +
                    ([card("Seal diverged", ", ".join(seal_v["diverged"]))]
                     if seal_v and seal_v.get("diverged") else []))
    anomalies = [(k, m) for k in ("seq", "ts", "nonce")
                 for m in a[k]["examples"]]
    p = proof_of(src, a, seal_v, attest_v)
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Audit report — {esc(src)}</title><style>
body{{font:15px/1.45 -apple-system,sans-serif;margin:2rem;color:#1b1b1f}}
h1{{font-size:1.3rem;margin:.2rem 0}} h2{{font-size:1.05rem;margin-top:1.6rem}}
.b{{display:inline-block;padding:.2rem .7rem;margin:.2rem .4rem .2rem 0;
border-radius:1rem;font-weight:600}}
.ok{{background:#e2f5e6;color:#116029}} .bad{{background:#fde2e2;color:#8a1f1f}}
.g{{display:flex;flex-wrap:wrap;gap:.8rem;margin:1.2rem 0}}
.c{{border:1px solid #d9d9df;border-radius:.5rem;padding:.6rem .9rem;min-width:
9rem}} .v{{font-weight:700}} .k{{color:#666;font-size:.8rem}}
table{{border-collapse:collapse;margin:.6rem 0 1.4rem;max-width:60rem}}
td{{border:1px solid #d9d9df;padding:.25rem .6rem;font-size:.86rem}}
p{{max-width:60rem}}</style></head><body>
<h1>Audit status report — {esc(src)}</h1>
<p>Generated {esc(p["generated"])} by audit-report.py — static document,
no scripts run, room content escaped as data.</p>
<div>{''.join(badges)}</div><div class="g">{cards}</div>
<h2>Anomalies</h2><table>{rows_of(anomalies)}</table>
<h2>Most active senders</h2><table>{rows_of(a["top_senders"])}</table>
<h2>Template floods</h2><table>{rows_of(a["top_templates"])}</table>
<h2>Machine-readable proof</h2>
<script type="application/json" id="audit-proof">
{json.dumps(p, ensure_ascii=False, indent=1)}
</script>
<p>Verify independently: recompute with audit-chain.py / offline-verify.py —
the chain head and merkle root above anchor the exact bytes of the export.</p>
</body></html>"""


def selftest():
    td = tempfile.mkdtemp(prefix="audit-report-")
    room = os.path.join(td, "room.jsonl")
    recs = [
        {"seq": 1, "ts": "2026-08-31T10:00:00Z", "from": "did:key:z6MkA",
         "text": "Gas 10.4 Gwei block 21914327", "nonce": 5},
        {"seq": 2, "ts": "2026-08-31T10:00:01Z", "from": "did:key:z6MkA",
         "text": "Gas 11.2 Gwei block 21914328", "nonce": 6},
        {"seq": 2, "ts": "2026-08-31T10:00:02Z", "from": "did:key:z6MkB",
         "text": "<script>alert(1)</script>", "nonce": 9},
        {"seq": 5, "ts": "bad-ts", "from": "did:key:z6MkB", "text": "x",
         "nonce": 3},
        {"seq": 6, "ts": "2026-08-31T09:59:00Z", "from": "did:key:z6MkA",
         "text": "Gas 9.9 Gwei block 21914330", "nonce": 4},
        {"seq": 7, "ts": "2026-08-31T10:00:05Z", "from": "did:key:z6MkA",
         "text": "Gas 12 Gwei block 21914331", "nonce": 7},
        "not json at all\n",
    ]
    with open(room, "w", encoding="utf-8") as fh:
        for r in recs:
            fh.write(r if isinstance(r, str) else json.dumps(r) + "\n")
    a = analyze(room)
    assert a["records"] == 7 and a["unparsable"] == 1, a
    assert a["seq"]["duplicates"] == 1 and a["seq"]["gaps"] == 1, a["seq"]
    assert a["seq"]["reorders"] == 0 and a["senders"] == 2, a
    assert a["ts"]["invalid"] == 1 and a["ts"]["regressions"] == 1, a["ts"]
    assert a["nonce"]["regressions"] == 2, a["nonce"]  # B's 3, then A's 4
    # chain head re-derived independently (leaf = sha256 of canonical JSON,
    # unparsable line hashed raw) — matches audit-chain.py's algorithm
    h = bytes.fromhex(GENESIS)
    for r in recs:
        leaf = hashlib.sha256(r.encode()).digest() if isinstance(r, str) \
            else hashlib.sha256(canonical(r).encode()).digest()
        h = hashlib.sha256(h + leaf).digest()
    assert a["chain_head"] == h.hex(), (a["chain_head"], h.hex())
    # merkle root re-derived independently (odd level duplicates last leaf)
    leaves = [hashlib.sha256(r.encode()).digest() if isinstance(r, str)
              else hashlib.sha256(canonical(r).encode()).digest() for r in recs]
    cur, cnt = leaves[:], len(leaves)
    while cnt > 1:
        if cnt % 2:
            cur, cnt = cur + [cur[-1]], cnt + 1
        cur = [hashlib.sha256(cur[i] + cur[i + 1]).digest()
               for i in range(0, cnt, 2)]
        cnt //= 2
    assert a["merkle_root"] == cur[0].hex()
    # seal verdicts
    good = {"chain_head": a["chain_head"], "merkle_root": a["merkle_root"],
            "records": a["records"], "unparsable": a["unparsable"]}
    assert check_seal(room, good)["status"] == "INTACT"
    v = check_seal(room, dict(good, chain_head="f" * 64))
    assert v["status"] == "TAMPERED" and v["diverged"] == ["chain_head"], v
    assert check_seal(room, dict(good, records=3))["diverged"] == ["records"]
    assert check_seal(room, "junk")["status"] == "UNREADABLE"
    # attestation verdicts
    att = {"sha256": hashlib.sha256(open(room, "rb").read()).hexdigest(),
           "bytes": os.path.getsize(room), "signer": "did:key:z6MkA"}
    assert check_attest(room, att)["status"] == "MATCH"
    with open(room, "a", encoding="utf-8") as fh:
        fh.write('{"seq": 8}\n')
    assert check_attest(room, att)["status"] == "MISMATCH"
    a = analyze(room)  # post-append state for render checks below
    # HTML: hostile text escaped, proof embedded and parseable, badges
    doc = render(room, a, None, None)
    assert "&lt;script&gt;" in doc and "<script>alert" not in doc
    block = doc.split('id="audit-proof">')[1].split("</script>")[0]
    assert json.loads(block)["chain_head"] == a["chain_head"]
    assert "Seal: NONE" in doc and "Timestamps: ANOMALY" in doc
    # clean room -> --json proof, exit 0; anomalous -> exit 1
    clean = os.path.join(td, "clean.jsonl")
    with open(clean, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"seq": 1, "ts": "2026-08-31T10:00:00Z",
                             "from": "did:key:z6MkA", "text": "hi",
                             "nonce": 1}) + "\n")
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main([clean, "--json"])
    assert rc == 0 and json.loads(buf.getvalue())["records"] == 1
    out = os.path.join(td, "r.html")
    assert main([room, "-o", out,
                 "--seal", os.path.join(td, "nope.json")]) == 1
    page = open(out, encoding="utf-8").read()
    assert "Overall: ALERT" in page and "Seal diverged" in page
    print("OK audit-report self-test: analysis counts, chain+merkle "
          "re-derivation, seal intact/tampered, attest match/mismatch, "
          "escaping, embedded proof, --json, exit codes")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="audit-report")
    ap.add_argument("file", help="room JSONL export")
    ap.add_argument("-o", "--out", help="default <file>.report.html")
    ap.add_argument("--seal", help="seal JSON (default <file>.seal.json)")
    ap.add_argument("--attest", help="attestation (default <file>.attest.json)")
    ap.add_argument("--json", action="store_true",
                    help="print machine-readable proof, write nothing")
    args = ap.parse_args(argv)
    try:
        a = analyze(args.file)
    except OSError as e:
        print(f"audit-report: {e}", file=sys.stderr)
        return 2
    seal_obj = load_json(args.seal or f"{args.file}.seal.json")
    if seal_obj is not None:
        seal_v = check_seal(args.file, seal_obj)
    elif args.seal:  # explicitly requested => surface it, never skip
        seal_v = {"status": "UNREADABLE",
                  "diverged": [f"cannot load {args.seal}"]}
    else:
        seal_v = None
    att_obj = load_json(args.attest or f"{args.file}.attest.json")
    if att_obj is not None:
        attest_v = check_attest(args.file, att_obj)
    elif args.attest:
        attest_v = {"status": "UNREADABLE",
                    "detail": f"cannot load {args.attest}"}
    else:
        attest_v = None
    src = os.path.basename(args.file)
    if args.json:
        print(json.dumps(proof_of(src, a, seal_v, attest_v),
                         ensure_ascii=False, indent=1))
    else:
        out = args.out or f"{args.file}.report.html"
        doc = render(src, a, seal_v, attest_v)
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(doc)
        print(f"audit-report: wrote {out} ({len(doc)} bytes)")
    alert = any([a["seq"]["duplicates"], a["seq"]["gaps"], a["seq"]["reorders"],
                 a["ts"]["invalid"], a["ts"]["regressions"],
                 a["nonce"]["regressions"], a["unparsable"],
                 seal_v and seal_v["status"] in ("TAMPERED", "UNREADABLE"),
                 attest_v and attest_v["status"] in ("MISMATCH", "UNREADABLE")])
    return 1 if alert else 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        selftest()
    else:
        try:
            raise SystemExit(main())
        except BrokenPipeError:
            raise SystemExit(2)
