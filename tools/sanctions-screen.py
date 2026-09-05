#!/usr/bin/env python3
"""sanctions-screen — cross-chain sanctions screening + compliance alerts.

DEMAND: evidence/suggestions/tools-services/2026-09-05.md (05:21 run)
  - "Real-time alerts or notifications for high-risk compliance events
    (e.g., OFAC sanctions on addresses)" — evidence: "treasury OFAC tag on
    3 DPRK addrs, BTC+ETH cross-chain — bridges are the reroute vector,
    peel-watch enabled". Proposed service there: "cross-chain compliance
    alerting and risk monitoring for sanctioned addresses".

Structure, not string-matching: BTC addresses are base58check- or
bech32-verified (double-SHA256 checksum / BIP173+350 polymod, witness
program length per BIP141), ETH addresses normalized to lowercase
hex40. `screen` resolves an address to its sanctioned subject; `batch`
walks a JSONL of transactions flagging listed from/to — plus the
entity's other chains as a reroute vector — plus invalid addresses and
peel-chain runs (consecutive outgoing amounts collapsing by
>=PEEL_RATIO within PEEL_WINDOW_H); `watch` also appends findings to an
alert log deduplicated by content hash, so re-scans never re-alert.
Exit 1 on any block-severity finding (compliance gates consume it);
`lint` validates the sanctions DB itself (dup ids/addresses, per-chain
address validity, listed dates).

Usage:
  python3 sanctions-screen.py screen 0xd1d1... --chain eth --db s.jsonl
  python3 sanctions-screen.py batch txs.jsonl --db s.jsonl --json
  python3 sanctions-screen.py watch txs.jsonl --alerts a.jsonl --db s.jsonl
  python3 sanctions-screen.py lint s.jsonl

VERIFY: self-test — python3 sanctions-screen.py --self-test
  Real base58check/bech32 vectors (genesis-block P2PKH, BIP173 test
  address, checksum-corruption rejection), screen match/clear/invalid,
  cross-chain reroute vector, batch + peel findings, alert dedupe,
  lint, exit codes 0/1/2, --json. Asserts, prints OK.
"""
import argparse
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
import sys
import tempfile

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
PEEL_RATIO = 0.6        # next hop <= 60% of previous
PEEL_MIN_HOPS = 3
PEEL_WINDOW_H = 72
KNOWN_CHAINS = ("eth", "btc")


def b58decode(text):
    n = 0
    for ch in text:
        d = B58.find(ch)
        if d < 0:
            return None
        n = n * 58 + d
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + raw


def check_base58(addr):
    """P2PKH/P2SH with full double-SHA256 checksum -> kind or None."""
    raw = b58decode(addr)
    if raw is None or len(raw) != 25:
        return None
    if raw[-4:] != hashlib.sha256(
            hashlib.sha256(raw[:-4]).digest()).digest()[:4]:
        return None
    return {0x00: "p2pkh", 0x05: "p2sh"}.get(raw[0])


def _polymod(values):
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def _convertbits(data, f, t):
    acc = bits = 0
    out = []
    for value in data:
        acc = (acc << f) | value
        bits += f
        while bits >= t:
            bits -= t
            out.append((acc >> bits) & ((1 << t) - 1))
    return out


def check_bech32(addr):
    """Segwit address per BIP173/BIP350 -> (witver, prog_len) or None."""
    low = addr.lower()
    if low != addr and addr != addr.upper():
        return None
    pos = low.rfind("1")
    hrp, data = low[:pos], low[pos + 1:]
    if pos < 1 or hrp not in ("bc", "tb") or len(data) < 7:
        return None
    vals = [BECH32.find(c) for c in data]
    if -1 in vals:
        return None
    if _polymod([ord(c) >> 5 for c in hrp] + [0]
                + [ord(c) & 31 for c in hrp] + vals) not in (1, 0x2BC830A3):
        return None
    prog = _convertbits(vals[1:-6], 5, 8)
    witver = vals[0]
    if not 0 <= witver <= 16 or not 2 <= len(prog) <= 40:
        return None
    if witver == 0 and len(prog) not in (20, 32):
        return None
    if witver == 1 and len(prog) != 32:
        return None
    return witver, len(prog)


def check_btc(addr):
    """Validate a BTC address structurally -> descriptor or None."""
    if addr[:3].lower() in ("bc1", "tb1"):
        seg = check_bech32(addr)
        return None if seg is None else f"segwit-v{seg[0]}"
    kind = check_base58(addr)
    return None if kind is None else kind


def normalize(chain, addr):
    """Canonical match form for a chain, or None if invalid."""
    addr = str(addr).strip()
    if chain == "eth":
        addr = addr.lower()
        try:
            int(addr[2:], 16)
        except ValueError:
            return None
        return addr if len(addr) == 42 and addr.startswith("0x") else None
    if chain == "btc":
        return addr if check_btc(addr) else None
    return addr or None  # other chains: exact-match, unvalidated


def read_jsonl(path):
    """[(line, obj-or-None)] — unparsable lines stay None, never dropped."""
    rows = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if line:
                try:
                    rows.append((n, json.loads(line)))
                except ValueError:
                    rows.append((n, None))
    return rows


def _parse_ts(text):
    try:
        ts = dt.datetime.fromisoformat(str(text).replace("Z", "+00:00"))
        return ts if ts.tzinfo else ts.replace(tzinfo=dt.timezone.utc)
    except (TypeError, ValueError):
        return None


def lint_db(rows):
    """[(loc, reason)] — structural problems in the sanctions DB."""
    bad, seen_id, seen_addr = [], {}, {}
    for n, rec in rows:
        if not isinstance(rec, dict):
            bad.append((f"line {n}", "not a JSON object"))
            continue
        sid = rec.get("id")
        if not sid:
            bad.append((f"line {n}", "missing id"))
        elif sid in seen_id:
            bad.append((f"line {n}",
                        f"duplicate id {sid} (also line {seen_id[sid]})"))
        else:
            seen_id[sid] = n
        if not rec.get("entity"):
            bad.append((f"line {n}", "missing entity"))
        for a in rec.get("addresses", []):
            chain, addr = a.get("chain"), str(a.get("addr", ""))
            if chain not in KNOWN_CHAINS:
                bad.append((f"line {n}",
                            f"unknown chain {chain!r} (unvalidated match)"))
                continue
            norm = normalize(chain, addr)
            if norm is None:
                bad.append((f"line {n}", f"invalid {chain} address {addr!r}"))
            elif (chain, norm) in seen_addr:
                bad.append((f"line {n}", f"address {addr} also on subject "
                            f"{seen_addr[(chain, norm)]}"))
            else:
                seen_addr[(chain, norm)] = sid
        try:
            dt.date.fromisoformat(str(rec.get("listed", "")))
        except ValueError:
            bad.append((f"line {n}", "bad/missing listed date"))
    return bad


def load_index(rows):
    """{(chain, addr): subject} — first wins; lint_db catches conflicts."""
    idx = {}
    for _, rec in rows:
        for a in (rec.get("addresses", []) if isinstance(rec, dict) else []):
            key = (a.get("chain"),
                   normalize(a.get("chain"), a.get("addr", "")))
            if key[1] and key not in idx:
                idx[key] = rec
    return idx


def subject_chains(rec):
    return sorted({a.get("chain") for a in rec.get("addresses", [])})


def screen_addr(index, chain, addr):
    """One address -> verdict dict (MATCH / CLEAR / INVALID)."""
    norm = normalize(chain, addr)
    if norm is None:
        return {"verdict": "INVALID", "chain": chain, "addr": addr,
                "reason": f"not a valid {chain} address"}
    hit = index.get((chain, norm))
    if hit is None:
        return {"verdict": "CLEAR", "chain": chain, "addr": norm}
    others = [c for c in subject_chains(hit) if c != chain]
    return {"verdict": "MATCH", "chain": chain, "addr": norm,
            "id": hit.get("id"), "entity": hit.get("entity"),
            "program": hit.get("program"), "listed": hit.get("listed"),
            "reroute_chains": others, "cross_chain": bool(others)}


def _peel(chain, src, run):
    return {"kind": "peel-chain", "severity": "review", "chain": chain,
            "addr": src, "entity": None, "program": None, "hops": len(run),
            "amounts": [a for _, _, a in run],
            "first_ts": run[0][0].isoformat(), "last_ts": run[-1][0].isoformat(),
            "detail": (f"{len(run)}-hop peel chain: amounts collapse "
                       f"{run[0][2]:g} -> {run[-1][2]:g} within "
                       f"{PEEL_WINDOW_H}h")}


def peel_chains(rows):
    """Peel runs: >=PEEL_MIN_HOPS consecutive outgoing amounts, each
    <=PEEL_RATIO of the previous, within PEEL_WINDOW_H of its neighbor."""
    out, byaddr = [], {}
    for n, rec in rows:
        if not isinstance(rec, dict) or not rec.get("from"):
            continue
        try:
            amt = float(rec.get("amount"))
        except (TypeError, ValueError):
            continue
        ts = _parse_ts(rec.get("ts"))
        if ts is None:
            continue
        byaddr.setdefault((rec.get("chain"), str(rec["from"])),
                          []).append((ts, n, amt))
    for (chain, src), items in sorted(byaddr.items()):
        items.sort()
        run = [items[0]]
        for item in items[1:]:
            prev = run[-1]
            if (item[2] <= prev[2] * PEEL_RATIO
                    and item[0] - prev[0] <= dt.timedelta(hours=PEEL_WINDOW_H)):
                run.append(item)
            else:
                if len(run) >= PEEL_MIN_HOPS:
                    out.append(_peel(chain, src, run))
                run = [item]
        if len(run) >= PEEL_MIN_HOPS:
            out.append(_peel(chain, src, run))
    return out


def _finding(kind, severity, chain, addr, subject=None, **extra):
    f = {"kind": kind, "severity": severity, "chain": chain, "addr": addr,
         "entity": subject.get("entity") if subject else None,
         "program": subject.get("program") if subject else None}
    if subject:
        f["subject_id"] = subject.get("id")
    f.update(extra)
    return f


def screen_batch(rows, index):
    """[(txrow)] -> findings for listed counterparties + bad addresses."""
    findings = []
    for n, rec in rows:
        if not isinstance(rec, dict):
            findings.append(_finding("malformed-row", "review", None, None,
                                     detail=f"line {n}: not a JSON object"))
            continue
        chain = rec.get("chain")
        for role in ("from", "to"):
            addr = rec.get(role)
            if addr is None:
                continue
            norm = normalize(chain, addr)
            if norm is None:
                findings.append(_finding(
                    "invalid-address", "review", chain, str(addr),
                    detail=f"line {n}: invalid {chain} address ({role})"))
                continue
            hit = index.get((chain, norm))
            if hit is not None:
                others = [c for c in subject_chains(hit) if c != chain]
                findings.append(_finding(
                    "sanctioned-address", "block", chain, norm, hit,
                    lineno=n, role=role, txid=rec.get("txid"),
                    reroute_chains=others,
                    detail=(f"line {n} {role} matches {hit.get('entity')} "
                            f"({hit.get('program')})"
                            + (f"; entity also on {', '.join(others)}"
                               " — reroute vector" if others else ""))))
    return findings


def alert_key(finding):
    stable = {k: finding.get(k) for k in ("kind", "severity", "chain",
                                          "addr", "entity", "program",
                                          "detail")}
    return hashlib.sha256(json.dumps(stable, sort_keys=True,
                                     default=str).encode()).hexdigest()


def record_alerts(path, findings, now):
    """Append new findings to the alert log, dedupe by key -> (new, dup)."""
    seen = {r.get("key") for _, r in read_jsonl(path)
            if isinstance(r, dict) and r.get("key")} if os.path.exists(path) \
        else set()
    added = dup = 0
    with open(path, "a", encoding="utf-8") as fh:
        for f in findings:
            key = alert_key(f)
            if key in seen:
                dup += 1
                continue
            seen.add(key)
            fh.write(json.dumps({**f, "key": key,
                                 "recorded": now.isoformat()},
                                default=str) + "\n")
            added += 1
    return added, dup


def selftest():
    tmp = tempfile.mkdtemp(prefix="sanctions-selftest-")

    def dump(name, rows):
        path = os.path.join(tmp, name)
        with open(path, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        return path

    def run(argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(argv)
        return rc, buf.getvalue()

    def eth(b):
        return "0x" + b * 20

    def tx(h, m, f, t, amt, **kw):
        r = {"ts": f"2026-09-05T{h:02d}:{m:02d}:00Z", "chain": "eth",
             "from": f, "to": t, "amount": amt}
        r.update(kw)
        return r

    # address validation on real vectors, incl. corruption rejection
    btc1 = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    assert check_btc(btc1) == "p2pkh"
    assert check_btc("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb") is None
    assert check_btc("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") \
        == "segwit-v0"
    assert check_btc("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5") is None
    assert normalize("eth", "0x" + "Ab" * 20) == eth("ab")
    assert normalize("eth", "0x123") is None

    db = [{"id": "OFAC-1", "entity": "Lazarus Group", "aliases": ["Hermit"],
           "program": "DPRK3", "listed": "2022-06-01",
           "addresses": [{"chain": "eth", "addr": eth("D1")},
                         {"chain": "btc", "addr": btc1}]},
          {"id": "OFAC-2", "entity": "Ryuk Operator", "program": "CYBER2",
           "listed": "2023-02-15",
           "addresses": [{"chain": "eth", "addr": eth("aa")}]}]
    dbp = dump("db.jsonl", db)
    assert lint_db(read_jsonl(dbp)) == []
    idx = load_index(read_jsonl(dbp))
    assert len(idx) == 3
    hit = screen_addr(idx, "eth", eth("d1"))
    assert hit["verdict"] == "MATCH" and hit["entity"] == "Lazarus Group"
    assert hit["reroute_chains"] == ["btc"] and hit["cross_chain"]
    assert screen_addr(idx, "eth", eth("77"))["verdict"] == "CLEAR"
    assert screen_addr(idx, "eth", "nothex")["verdict"] == "INVALID"

    dirty = dump("dirty.jsonl", [
        {"id": "X", "entity": "E", "listed": "2024-01-01",
         "addresses": [{"chain": "eth", "addr": "0xzz"}]},
        {"id": "X", "entity": "E2", "listed": "nope",
         "addresses": [{"chain": "eth", "addr": eth("aa")}]}])
    assert len(lint_db(read_jsonl(dirty))) == 3

    peeled, sink = eth("ee"), eth("99")
    txs = [tx(10, 0, eth("bb"), eth("D1"), 12.5, txid="t1"),
           tx(10, 5, eth("cc"), eth("77"), 1.0, txid="t2"),
           tx(10, 6, "0xzz", eth("88"), 2.0, txid="t3"),
           tx(11, 0, peeled, sink, 100.0), tx(12, 0, peeled, sink, 40.0),
           tx(13, 0, peeled, sink, 16.0), tx(14, 0, peeled, sink, 5.0)]
    txp = dump("txs.jsonl", txs)
    trows = read_jsonl(txp)
    finds = screen_batch(trows, idx)
    blocks = [f for f in finds if f["severity"] == "block"]
    assert len(blocks) == 1 and blocks[0]["entity"] == "Lazarus Group"
    assert blocks[0]["reroute_chains"] == ["btc"]
    assert "reroute vector" in blocks[0]["detail"]
    assert len([f for f in finds if f["kind"] == "invalid-address"]) == 1
    peels = peel_chains(trows)
    assert len(peels) == 1 and peels[0]["hops"] == 4
    assert peels[0]["amounts"] == [100.0, 40.0, 16.0, 5.0]
    flat = [tx(10 + k, 0, peeled, sink, 10.0) for k in range(5)]
    assert peel_chains(read_jsonl(dump("flat.jsonl", flat))) == []

    apath = os.path.join(tmp, "alerts.jsonl")
    allf = finds + peels
    t0 = _parse_ts("2026-09-05T15:00:00Z")
    assert record_alerts(apath, allf, t0) == (len(allf), 0)
    assert record_alerts(apath, allf, t0) == (0, len(allf))
    logged = [r for _, r in read_jsonl(apath)]
    assert len(logged) == len(allf) and all(r.get("key") for r in logged)

    rc, txt = run(["screen", eth("d1"), "--chain", "eth", "--db", dbp])
    assert rc == 1 and "MATCH" in txt and "reroute" in txt
    rc, txt = run(["screen", eth("77"), "--chain", "eth", "--db", dbp])
    assert rc == 0 and "CLEAR" in txt
    rc, txt = run(["batch", txp, "--db", dbp, "--json"])
    assert rc == 1 and json.loads(txt)["blocks"] == 1
    rc, txt = run(["watch", txp, "--db", dbp, "--alerts",
                   os.path.join(tmp, "w.jsonl"), "--now",
                   "2026-09-05T15:00:00Z"])
    assert rc == 1 and "alerts: 3 new" in txt
    rc, txt = run(["lint", dbp])
    assert rc == 0 and "LINT OK" in txt
    assert run(["lint", dirty])[0] == 1
    assert run(["screen", eth("77"), "--chain", "eth", "--db",
                os.path.join(tmp, "missing.jsonl")])[0] == 2
    print("OK sanctions-screen self-test: base58check/bech32 validation "
          "(incl. checksum corruption), screen match/clear/invalid, "
          "cross-chain reroute vector, batch + peel findings, alert "
          "dedupe, lint, exit codes 0/1/2, --json")


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="sanctions-screen",
        description="Cross-chain sanctions screening and compliance alerts")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ps = sub.add_parser("screen", help="screen one address")
    ps.add_argument("addr")
    ps.add_argument("--chain", required=True)
    pb = sub.add_parser("batch", help="screen a JSONL of transactions")
    pb.add_argument("txs")
    pw = sub.add_parser("watch", help="batch + append-only alert log")
    pw.add_argument("txs")
    pw.add_argument("--alerts", required=True)
    pw.add_argument("--now", default=None, help="recording timestamp (ISO)")
    pl = sub.add_parser("lint", help="validate the sanctions DB")
    pl.add_argument("db")
    for p in (ps, pb, pw):
        p.add_argument("--db", required=True, help="sanctions JSONL")
        p.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "lint":
            bad = lint_db(read_jsonl(args.db))
            for loc, why in bad:
                print(f"  {loc}: {why}")
            print("LINT OK" if not bad else f"LINT FAIL: {len(bad)} problems")
            return 0 if not bad else 1
        rows = read_jsonl(args.db)
        bad = lint_db(rows)
        if bad:
            for loc, why in bad:
                print(f"  {loc}: {why}", file=sys.stderr)
            print("sanctions DB fails lint; fix before screening",
                  file=sys.stderr)
            return 2
        index = load_index(rows)
        if args.cmd == "screen":
            res = screen_addr(index, args.chain, args.addr)
            if args.json:
                print(json.dumps(res, indent=2, default=str))
            elif res["verdict"] == "MATCH":
                print(f"MATCH {res['addr']} ({res['chain']})\n"
                      f"  entity {res['entity']} program {res['program']}"
                      f" listed {res['listed']}")
                if res["reroute_chains"]:
                    print("  reroute vector: entity also on "
                          + ", ".join(res["reroute_chains"]))
            else:
                print(f"{res['verdict']} {res['addr']} ({res['chain']})"
                      + (f" — {res['reason']}" if res.get("reason") else ""))
            return {"MATCH": 1, "CLEAR": 0}.get(res["verdict"], 2)
        trows = read_jsonl(args.txs)
        findings = screen_batch(trows, index) + peel_chains(trows)
        findings.sort(key=lambda f: f["severity"] != "block")
        added = dup = None
        if args.cmd == "watch":
            now = (_parse_ts(args.now) if args.now
                   else dt.datetime.now(dt.timezone.utc))
            added, dup = record_alerts(args.alerts, findings, now)
        blocks = sum(1 for f in findings if f["severity"] == "block")
        if args.json:
            summary = {"blocks": blocks,
                       "reviews": len(findings) - blocks,
                       "findings": findings}
            if args.cmd == "watch":
                summary["alerts_added"], summary["alerts_duplicate"] = added, dup
            print(json.dumps(summary, indent=2, default=str))
        else:
            for f in findings:
                mark = "ALERT" if f["severity"] == "block" else "review"
                print(f"{mark:7s} {f['kind']:20s} {f['chain'] or '-'} "
                      f"{f['addr'] or '-'} {f.get('detail', '')}")
            if args.cmd == "watch":
                print(f"alerts: {added} new, {dup} duplicate")
        return 1 if blocks else 0
    except (OSError, ValueError) as exc:
        print(f"sanctions-screen: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        selftest()
    else:
        raise SystemExit(main())
