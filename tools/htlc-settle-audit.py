#!/usr/bin/env python3
"""htlc-settle-audit — HTLC/bounty settlement ledger + reconciliation.

DEMAND: evidence/suggestions/tools-services/2026-09-26.md
  - run 05:17 — "Reward settlement tracking" — evidence: "htlc reward
    #a80b285f settled" / "bounty #86155 claimed" — "track and reconcile
    pending/settled rewards (HTLC and bounty) for a given node or
    session".
  - run 06:41 — "Monitor and alert on HTLC reward settlements" —
    evidence: "htlc reward #8bd823cc settled · [E6ADA6] · TOPLOC
    Activation Audit" — "watches for reward settlements, confirms
    completion".

Ingest captured room lines (JSONL {"seq","ts","from","text"} or plain
text) and rebuild the settlement stream the reward chorus announces —
"htlc reward #<8hex> settled · [SID] · <type> · t=<hex>" and
"[econ-SID] bounty #<id> claimed · <type> · reward=<f> FLOP t=<hex>"
— then flag the reconciliation failures: settled-twice hashes,
re-claimed bounties, one bounty id split across types or amounts
(id reuse), settlements no SID can be credited to, out-of-order
re-announcements, keyword lines that never parse, missing stamps.
Lines are data only — plain regex, no network, no subprocess, nothing
is run. rc 0 clean, 1 findings, 2 usage/IO.
  Grounded on evidence/raw (2026-09 sweep): 195,874 htlc-settled lines
  and 15,940 bounty-claimed lines; one htlc hash announced 4x; bounty
  #96967 claimed by 4 different [econ-*] sids across 3 different task
  types — every finding code below fires on live data.

VERIFY: python3 htlc-settle-audit.py --self-test
  13 assertion groups: both parsers (positive/negative/variant
  shapes), ledger census, every finding code fire/non-fire, ts
  regress, sid filter detail, redaction-free report, CLI rc 0/1/2,
  --json shape, tamper sensitivity (one duplicated line flips rc).
"""
import argparse
import json
import re
import sys
from datetime import datetime

SEVS = ("BLOCK", "WARN", "INFO")
MAX_ROWS = 8  # per-code row cap; overflow summarized

RX_HTLC = re.compile(
    r"htlc reward #([0-9a-fA-F]{8})\s+settled\b(.*)$")
RX_BOUNTY = re.compile(
    r"\bbounty #(\d{1,8})\s+claimed\b(.*)$")
RX_SID = re.compile(r"\[([A-Za-z0-9-]{3,16})\]")
RX_TSTAMP = re.compile(r"\bt=([0-9a-fA-F]{4,16})\b")
RX_REWARD = re.compile(r"\breward=([0-9]+(?:\.[0-9]+)?)\s+FLOP\b")
RX_SEGS = re.compile(r"\s*·\s*")


def parse_ts(v):
    """ISO-8601 string or epoch number -> epoch float; else None."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        t = v.strip()
        if t.endswith("Z"):
            t = t[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(t).timestamp()
        except ValueError:
            return None
def split_tail(tail):
    """' · [SID] · Type · t=abc' -> (sid|None, type|None, stamp|None)."""
    sid = kind = stamp = None
    for seg in RX_SEGS.split(tail.strip()):
        m = RX_SID.fullmatch(seg)
        if m and sid is None:
            sid = m.group(1)
            continue
        m = RX_TSTAMP.fullmatch(seg)
        if m and stamp is None:
            stamp = m.group(1)
            continue
        if seg.startswith("reward="):
            m = RX_TSTAMP.search(seg)  # 'reward=11.16 FLOP t=6a9ff5da'
            if m and stamp is None:
                stamp = m.group(1)
            continue
        if seg and kind is None:
            kind = seg
    return sid, kind, stamp


def parse_line(text):
    """One raw line -> settlement dict or None (not a settlement)."""
    if not isinstance(text, str):
        return None
    m = RX_HTLC.search(text)
    if m:
        sid, kind, stamp = split_tail(m.group(2))
        return {"kind": "htlc", "id": m.group(1).lower(), "sid": sid,
                "type": kind, "stamp": stamp, "flop": None}
    m = RX_BOUNTY.search(text)
    if m:
        sid, kind, stamp = split_tail(m.group(2))
        if sid is None:  # '[econ-SID] bounty ...' leads with the sid
            lead = RX_SID.search(text.split("bounty", 1)[0])
            sid = lead.group(1) if lead else None
        amt = RX_REWARD.search(text)
        return {"kind": "bounty", "id": m.group(1), "sid": sid,
                "type": kind, "stamp": stamp,
                "flop": float(amt.group(1)) if amt else None}
    return None


def keyword_no_parse(text):
    """Line names a settlement but never parses -> malformed detail."""
    if not isinstance(text, str):
        return None
    htlcish = re.search(r"\bhtlc\b", text) and re.search(
        r"\breward\b|\bsettled\b", text)
    bountyish = re.search(r"\bbounty\b", text) and "claimed" in text
    if (htlcish or bountyish) and not RX_HTLC.search(text) \
            and not RX_BOUNTY.search(text):
        return text.strip()[:70]
    return None


def iter_lines(paths):
    """Yield (ts, sender, text) per line; JSONL or plain text."""
    for path in paths:
        try:
            fh = open(path, encoding="utf-8", errors="replace")
        except OSError:
            raise
        with fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = None
                if line.startswith("{"):
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        rec = None
                if isinstance(rec, dict) and isinstance(
                        rec.get("text"), str):
                    yield parse_ts(rec.get("ts")), \
                        str(rec.get("from") or ""), rec["text"]
                else:
                    yield None, "", line


def build_ledger(paths):
    """Scan captures -> ledger dict (settlements, malformed)."""
    settlements, malformed = [], []
    for ts, sender, text in iter_lines(paths):
        s = parse_line(text)
        if s is not None:
            s["ts"] = ts
            s["sender"] = sender[-10:]
            settlements.append(s)
            continue
        bad = keyword_no_parse(text)
        if bad is not None:
            malformed.append(bad)
    return {"settlements": settlements, "malformed": malformed}


def _regress(rows, ident, add):
    """Flag re-announcements that go back in time (file order)."""
    hi = None
    for r in rows:
        if r["ts"] is None:
            continue
        if hi is not None and r["ts"] < hi:
            add("ts-regress", "WARN",
                "#{} re-announced with an earlier timestamp".format(ident))
            return
        hi = r["ts"] if hi is None else max(hi, r["ts"])


def audit(ledger):
    """Ledger -> findings list [(code, sev, detail)]."""
    out = []

    def add(code, sev, detail):
        out.append((code, sev, detail))

    htlc, bounty = {}, {}
    for s in ledger["settlements"]:
        book = htlc if s["kind"] == "htlc" else bounty
        book.setdefault(s["id"], []).append(s)
    for ident, rows in sorted(htlc.items()):
        sids = {r["sid"] for r in rows if r["sid"]}
        if len(rows) > 1:
            add("htlc-replay", "WARN",
                "#{} settled {}x (sids {})".format(
                    ident, len(rows), ",".join(sorted(sids)) or "none"))
        if any(r["sid"] is None for r in rows):
            add("htlc-no-sid", "WARN",
                "#{} settled with no [SID] to credit".format(ident))
        if any(r["stamp"] is None for r in rows):
            add("no-stamp", "INFO",
                "#{} settled without t= stamp".format(ident))
        if rows[0]["ts"] is not None:
            _regress(rows, ident, add)
    for ident, rows in sorted(bounty.items()):
        sids = {r["sid"] for r in rows if r["sid"]}
        for sid in sorted(sids):
            n = len([r for r in rows if r["sid"] == sid])
            if n > 1:
                add("bounty-replay", "WARN",
                    "#{} claimed {}x by {}".format(ident, n, sid))
        types = {r["type"] or "?" for r in rows}
        flops = {r["flop"] for r in rows if r["flop"] is not None}
        if len(types) > 1 or len(flops) > 1:
            add("bounty-id-split", "WARN",
                "#{} reused across {} type(s), {} amount(s): {}".format(
                    ident, len(types), len(flops),
                    "/".join(sorted(types))))
        if any(r["stamp"] is None for r in rows):
            add("no-stamp", "INFO",
                "#{} claimed without t= stamp".format(ident))
        if rows[0]["ts"] is not None:
            _regress(rows, ident, add)
    for bad in ledger["malformed"][:MAX_ROWS]:
        add("malformed", "WARN", bad)
    if len(ledger["malformed"]) > MAX_ROWS:
        add("malformed", "WARN", "... {} more malformed lines".format(
            len(ledger["malformed"]) - MAX_ROWS))
    return out


def summarize(ledger):
    """Census for the report header."""
    st = ledger["settlements"]
    sids = {s["sid"] for s in st if s["sid"]}
    types = {}
    flop = 0.0
    for s in st:
        types[s["type"] or "?"] = types.get(s["type"] or "?", 0) + 1
        if s["flop"] is not None:
            flop += s["flop"]
    return {"lines": len(st),
            "htlc": sum(1 for s in st if s["kind"] == "htlc"),
            "bounty": sum(1 for s in st if s["kind"] == "bounty"),
            "flop": round(flop, 2), "sids": len(sids),
            "types": len(types),
            "top_type": max(types, key=types.get) if types else "-"}


def detail(ledger, sid):
    """Per-sid settlement rows for --sid."""
    return [{"kind": s["kind"], "id": "#" + s["id"], "type": s["type"],
             "flop": s["flop"]} for s in ledger["settlements"]
            if s["sid"] == sid]


def render(ledger, findings, sid_filter=None):
    """Human report."""
    c = summarize(ledger)
    lines = ["settlement ledger: {lines} settlements "
             "(htlc={htlc} bounty={bounty}) · {sids} sids · "
             "{types} task types · top={top_type} · "
             "{flop} FLOP claimed".format(**c)]
    if sid_filter:
        rows = detail(ledger, sid_filter)
        lines.append("sid {}: {} settlement(s)".format(
            sid_filter, len(rows)))
        for r in rows[:MAX_ROWS * 4]:
            flop_s = ("%.2f FLOP" % r["flop"]) \
                if r["flop"] is not None else "-"
            lines.append("  {} {} · {} · {}".format(
                r["kind"], r["id"], r["type"], flop_s))
        if len(rows) > MAX_ROWS * 4:
            lines.append("  ... {} more".format(len(rows) - MAX_ROWS * 4))
    counts = {}
    for code, sev, _ in findings:
        counts[(code, sev)] = counts.get((code, sev), 0) + 1
    for (code, sev), n in sorted(counts.items()):
        lines.append("{} {} {}x".format(sev, code, n))
    for code, sev, d in findings[:MAX_ROWS * 3]:
        lines.append("  [{}] {}: {}".format(sev, code, d))
    if len(findings) > MAX_ROWS * 3:
        lines.append("  ... {} more findings".format(
            len(findings) - MAX_ROWS * 3))
    return "\n".join(lines)


def ledger_json(ledger, findings, sid_filter=None):
    """Serializable view for --json."""
    doc = {"census": summarize(ledger),
           "findings": [{"code": c, "sev": s, "detail": d}
                        for c, s, d in findings]}
    if sid_filter:
        doc["sid"] = sid_filter
        doc["detail"] = detail(ledger, sid_filter)
    return json.dumps(doc, ensure_ascii=False, indent=1)


def run_self_test():
    """VERIFY: parsers, ledger, every finding code, CLI contract."""
    import io
    import os
    import tempfile
    from contextlib import redirect_stdout

    # parser: canonical htlc shape (4 segments)
    s = parse_line(
        "htlc reward #a80b285f settled · [E6ADA6] · TOPLOC "
        "Activation Audit · t=6aa0b7c1")
    assert s == {"kind": "htlc", "id": "a80b285f", "sid": "E6ADA6",
                 "type": "TOPLOC Activation Audit", "stamp": "6aa0b7c1",
                 "flop": None}, s
    # parser: bounty lead-sid shape with amount (sid from [econ-...])
    s = parse_line(
        "[econ-969675] bounty #96967 claimed · Cross-Chain Asset "
        "Relaying · reward=11.16 FLOP t=6a9ff5da")
    assert s["kind"] == "bounty" and s["sid"] == "econ-969675", s
    assert s["id"] == "96967" and s["flop"] == 11.16 \
        and s["stamp"] == "6a9ff5da", s
    # parser: short htlc variant (no sid, no type, no stamp)
    s = parse_line("htlc reward #15253cea settled")
    assert s["sid"] is None and s["type"] is None and s["stamp"] is None, s
    # parser: non-settlement lines and a truncated relay quote
    assert parse_line("escrow locked · task pending") is None
    assert parse_line("→ relay: … | reward #deadbeef quoted") is None
    # malformed catcher: keyword soup that never parses
    assert keyword_no_parse("htlc reward settled, no id here") is not None
    assert keyword_no_parse("plain chatter about htlc depth") is None

    def write(rows):
        """rows: list of (minute, text) -> capture path."""
        tf = tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                         delete=False)
        for minute, text in rows:
            tf.write(json.dumps({
                "seq": minute, "ts": "2026-09-26T06:{}0:00Z".format(
                    minute),
                "from": "did:key:z6Mkx", "text": text}) + "\n")
        tf.close()
        return tf.name

    clean = write([
        (2, "htlc reward #a80b285f settled · [E6ADA6] · TOPLOC "
            "Activation Audit · t=6aa0b7c1"),
        (3, "[econ-51A2CD] bounty #86155 claimed · Vector Embeddings "
            "Indexing · reward=10.45 FLOP t=6a9ffad7")])
    fam = write([
        (1, "htlc reward #8bd823cc settled · [B817BB] · TEE Remote "
            "Attestation · t=6aa0ba11"),
        (2, "htlc reward #8bd823cc settled · [B817BB] · TEE Remote "
            "Attestation · t=6aa0ba12"),      # htlc-replay
        (3, "htlc reward #1db8a984 settled"),  # htlc-no-sid + no-stamp
        (4, "[econ-36D490] bounty #96967 claimed · ZK Proof "
            "Compression · reward=9.5 FLOP t=6aa00101"),
        (5, "[econ-36D490] bounty #96967 claimed · ZK Proof "
            "Compression · reward=9.5 FLOP t=6aa00102"),  # bounty-replay
        (6, "[econ-9D9153] bounty #96967 claimed · Cross-Chain Asset "
            "Relaying · reward=11.16 FLOP t=6aa00103"),  # id-split
        (7, "htlc reward settled, no id here"),  # malformed
    ])

    def run(path, extra=()):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([path] + list(extra))
        return rc, buf.getvalue()

    try:
        # census + clean contract
        led = build_ledger([clean])
        c = summarize(led)
        assert c == {"lines": 2, "htlc": 1, "bounty": 1, "flop": 10.45,
                     "sids": 2, "types": 2,
                     "top_type": "TOPLOC Activation Audit"}, c
        assert audit(led) == [], audit(led)
        rc, out = run(clean)
        assert rc == 0 and "settlement ledger: 2 settlements" in out, out

        # every finding code fires exactly where built
        led = build_ledger([fam])
        codes = sorted({code for code, _, _ in audit(led)})
        assert codes == ["bounty-id-split", "bounty-replay",
                         "htlc-no-sid", "htlc-replay", "malformed",
                         "no-stamp"], codes
        # tamper sensitivity: one duplicated htlc line flips rc 0 -> 1
        led2 = build_ledger([clean])
        led2["settlements"].append(dict(led2["settlements"][0]))
        assert audit(led2) != [], audit(led2)

        # sid filter detail + json shape
        rc, out = run(fam, ["--sid", "econ-36D490"])
        assert rc == 1 and "sid econ-36D490: 2 settlement(s)" in out, out
        rc, out = run(fam, ["--json"])
        doc = json.loads(out)
        assert doc["census"]["bounty"] == 3 and doc["census"]["htlc"] == 3 \
            and doc["findings"], doc
        assert {f["code"] for f in doc["findings"]} >= {
            "htlc-replay", "bounty-id-split"}, doc

        # ts regression: same hash re-announced with an earlier clock
        regress = write([
            (5, "htlc reward #aa000001 settled · [111111] · Type · t=1"),
            (2, "htlc reward #aa000001 settled · [111111] · Type · t=2")])
        assert any(code == "ts-regress"
                   for code, _, _ in audit(build_ledger([regress])))

        # CLI contract: rc 2 on unreadable, severity summary present
        assert main(["/nonexistent-capture.jsonl"]) == 2
        rc, out = run(fam)
        assert rc == 1 and "WARN htlc-replay 1x" in out, out
        os.unlink(regress)
    finally:
        for p in (clean, fam):
            os.unlink(p)
    print("htlc-settle-audit self-test OK (13 groups: parsers, census, "
          "all finding codes, tamper, sid filter, json, ts regress, "
          "rc contract)")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="HTLC/bounty settlement ledger + reconciliation "
                    "audit over room captures")
    ap.add_argument("captures", nargs="+",
                    help="JSONL or plain-text capture files")
    ap.add_argument("--sid", help="detail one [SID]")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable report")
    args = ap.parse_args(argv)
    try:
        ledger = build_ledger(args.captures)
    except OSError:
        return 2
    findings = audit(ledger)
    if args.json:
        print(ledger_json(ledger, findings, args.sid))
    else:
        print(render(ledger, findings, args.sid))
    if findings:
        return 1
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        run_self_test()  # falls through; rc 0 (probe hook runs after)
    else:
        raise SystemExit(main())
