#!/usr/bin/env python3
"""agent-trail-report — per-agent cross-room contribution-trail walker:
`--agent <did> --since <seq> --until <seq>` over saved room captures
(JSONL {"seq","ts","from","text","nonce","sig"}, like evidence/raw/<room>.jsonl)
— the exact command surface the room asked hermes-tools to expose. Lines are
data only: parsing/hashing, no network, no subprocess, nothing is run.

DEMAND: evidence/suggestions/tools-services/2026-09-23.md
  - 06:01 "Contributor trail lookup" — "How to verify any agent's
    contribution history" / "walk an agent's full trail" — proposed:
    command that replays signed messages by agent DID within a seq range.
  - rerun "Need a way to audit specific agent's contribution history and
    trail" — "every signed message returns a seq number. Read the room
    with --since <seq> and you can walk an agent's full trail."
  - "Agent-wide contribution history verification and audit trail walking"
    — "expose a --agent <did> --since <seq> --until <seq> audit trail
    command ... generate a verifiable contribution report", plus the
    adjacent persistence sample: "a machine that never talked to the live
    host can yet verify a row from saved JSONL; that is the audit" — the
    per-room sha256 chain heads in this report make that re-verification
    mechanical (re-run the same captures, compare heads).
Unmet by siblings: seq-trail-audit audits per-view seq/fork integrity for
all senders; audit-chain seals a whole export. This tool walks ONE agent
across rooms and emits its contribution report. rc 0 clean, 1 findings,
2 usage.
"""

import argparse
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict

BOILER_MIN = 50          # repeats before a boilerplate row is worth a line
BOILER_FRAC = 0.60       # share of the trail one template must hold
MAX_ROWS = 8             # per finding code; busier agents would flood


def parse_ts(v):
    """ISO-8601 (Z / offset / fractional) or epoch number -> float, else None."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    if not isinstance(v, str) or not v:
        return None
    s = v.strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    try:
        from datetime import datetime
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            from datetime import timezone
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        try:
            return float(s)
        except ValueError:
            return None


def _room_label(path):
    return os.path.basename(path)


def load_rooms(paths):
    """paths -> {label: {"records": [...sorted by seq...], "malformed": n}}."""
    rooms = {}
    for p in paths:
        recs, bad = [], 0
        with open(p, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    bad += 1
                    continue
                if not isinstance(d, dict) or "seq" not in d or "from" not in d:
                    bad += 1
                    continue
                ts = parse_ts(d.get("ts"))
                if ts is None:
                    bad += 1
                    continue
                try:
                    seq = int(d["seq"])
                except (TypeError, ValueError):
                    bad += 1
                    continue
                recs.append({"seq": seq, "ts": ts, "ts_raw": d.get("ts"),
                             "from": d["from"],
                             "text": d.get("text") or "",
                             "nonce": d.get("nonce"), "sig": d.get("sig")})
        recs.sort(key=lambda r: (r["seq"], r["ts"]))
        rooms[_room_label(p)] = {"records": recs, "malformed": bad}
    return rooms


def resolve_agent(rooms, needle):
    """Exact DID, else unique prefix/substring. KeyError if absent/ambiguous."""
    senders = {r["from"] for rd in rooms.values() for r in rd["records"]}
    if needle in senders:
        return needle
    hits = sorted(d for d in senders if needle in d)
    if len(hits) == 1:
        return hits[0]
    shown = ", ".join(hits[:5]) or "none"
    more = f" (+{len(hits) - 5} more)" if len(hits) > 5 else ""
    raise KeyError(f"agent {needle!r} not resolvable: {shown}{more}")


def agent_trail(rooms, did, since=None, until=None, room_filter=None):
    """{label: [agent records in the seq window, seq-sorted]}."""
    trail = {}
    for label, rd in sorted(rooms.items()):
        if room_filter and room_filter not in label:
            continue
        rs = [r for r in rd["records"] if r["from"] == did]
        if since is not None:
            rs = [r for r in rs if r["seq"] >= since]
        if until is not None:
            rs = [r for r in rs if r["seq"] <= until]
        if rs:
            trail[label] = rs
    return trail


def chain_head(recs, label):
    """sha256 chain over the agent's records (seq order): re-run the same
    captures + window, compare heads — offline verification of the report."""
    h = hashlib.sha256(("agent-trail:" + label).encode()).hexdigest()
    for r in recs:
        payload = json.dumps([label, r["seq"], r["ts_raw"], r["from"],
                              r["nonce"], r["text"]],
                             ensure_ascii=False, separators=(",", ":"))
        h = hashlib.sha256((h + payload).encode("utf-8")).hexdigest()
    return h


def audit_trail(trail, rooms, did):
    """Contribution-quality findings for the walked agent."""
    out = []

    def add(code, sev, room, detail):
        out.append({"code": code, "severity": sev, "room": room,
                    "detail": detail})

    # sig reuse: one of this agent's signatures filed under another DID
    owner = defaultdict(set)
    for rd in rooms.values():
        for r in rd["records"]:
            if r["sig"]:
                owner[r["sig"]].add(r["from"])
    stolen = sorted({o for s, os_ in owner.items() if did in os_ for o in os_
                     if o != did})
    if stolen:
        add("sig-reuse", "BLOCK", "*",
            f"{len(stolen)} signature(s) of this agent also filed under "
            f"other DID(s), e.g. {stolen[0]}")

    for label, rs in trail.items():
        by_seq = defaultdict(list)
        for r in rs:
            by_seq[r["seq"]].append(r)
        for seq, group in sorted(by_seq.items()):
            if len({(r["nonce"], r["text"]) for r in group}) > 1:
                add("seq-conflict", "BLOCK", label,
                    f"seq {seq}: {len(group)} records, different bodies")
            elif len(group) > 1:
                add("dup-record", "INFO", label, f"seq {seq}: exact replay")
        for a, b in zip(rs, rs[1:]):
            if b["ts"] < a["ts"]:
                add("ts-regression", "WARN", label,
                    f"seq {a['seq']}->{b['seq']}: clock goes backwards "
                    f"({b['ts_raw']})")

    # nonce reuse across the whole walked trail (cross-room replays included)
    nonces = defaultdict(set)
    for label, rs in trail.items():
        for r in rs:
            if r["nonce"] is not None:
                nonces[r["nonce"]].add(label)
    for nonce, labels in sorted(nonces.items()):
        n = sum(1 for rs in trail.values()
                for r in rs if r["nonce"] == nonce)
        if n > 1:
            add("nonce-replay", "WARN", "*",
                f"nonce {nonce} used {n}x across "
                f"{','.join(sorted(labels))} (reuse weakens replay proof)")
    total = sum(len(rs) for rs in trail.values())
    if total >= BOILER_MIN:
        top_text, top_n = Counter(
            t for rs in trail.values() for t in (r["text"] for r in rs)
        ).most_common(1)[0]
        if top_n >= BOILER_FRAC * total:
            add("boilerplate", "INFO", "*",
                f"top template is {top_n}/{total} msgs: "
                f"{top_text[:60]!r}")
    return cap_findings(out)


def cap_findings(findings):
    """Keep the first MAX_ROWS rows per code; summarize the suppressed rest."""
    counts = Counter(f["code"] for f in findings)
    kept, seen = [], Counter()
    for f in findings:
        seen[f["code"]] += 1
        if seen[f["code"]] <= MAX_ROWS:
            kept.append(f)
    for code, n in counts.items():
        if n > MAX_ROWS:
            kept.append({"code": code + "-overflow", "severity": "INFO",
                         "room": "*",
                         "detail": f"{n - MAX_ROWS} more {code} finding(s) "
                         f"suppressed (cap {MAX_ROWS})"})
    return kept


def room_stats(trail):
    """{label: stats} + totals for the report."""
    stats = {}
    for label, rs in trail.items():
        days = Counter(r["ts"] // 86400 for r in rs)
        texts = Counter(r["text"] for r in rs)
        stats[label] = {
            "msgs": len(rs), "seq_first": rs[0]["seq"], "seq_last": rs[-1]["seq"],
            "first_ts": rs[0]["ts_raw"], "last_ts": rs[-1]["ts_raw"],
            "uniq_texts": len(texts),
            "top_text": texts.most_common(1)[0][0][:64],
            "days": len(days), "busiest_day_msgs": max(days.values()),
        }
    total = sum(s["msgs"] for s in stats.values())
    span = None
    flat = [r for rs in trail.values() for r in rs]
    if flat:
        span = (min(r["ts"] for r in flat), max(r["ts"] for r in flat))
    return stats, {"rooms": len(stats), "msgs": total, "span": span}


def render(trail, stats, totals, findings, agent, window):
    w = (f"seq {window[0] if window[0] is not None else '-inf'}.."
         f"{window[1] if window[1] is not None else '+inf'}")
    print(f"agent-trail-report: {agent}  [{w}]")
    if not trail:
        print("  no records in window")
        return
    print(f"  rooms={totals['rooms']}  msgs={totals['msgs']}")
    if totals["span"]:
        from datetime import datetime, timezone
        lo, hi = totals["span"]
        print(f"  active "
              f"{datetime.fromtimestamp(lo, tz=timezone.utc).isoformat()} .. "
              f"{datetime.fromtimestamp(hi, tz=timezone.utc).isoformat()}")
    for label, s in stats.items():
        rate = s["msgs"] / s["days"] if s["days"] else 0.0
        print(f"  [{label}] {s['msgs']} msgs  seq {s['seq_first']}-"
              f"{s['seq_last']}  {s['days']}d ({rate:.1f}/d)  "
              f"uniq {s['uniq_texts']}")
        print(f"      {s['first_ts']} -> {s['last_ts']}")
        print(f"      top: {s['top_text']!r}")
        print(f"      chain-head: {chain_head(trail[label], label)}")
    for f in findings:
        print(f"  {f['severity']:5} {f['code']:<14} {f['room']:<18} {f['detail']}")
    if not findings:
        print("  findings: none — trail is internally consistent")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Walk one agent's signed-message trail across saved "
                    "room captures and emit a verifiable contribution report.")
    ap.add_argument("captures", nargs="+", help="room JSONL captures")
    ap.add_argument("--agent", help="DID (exact, unique prefix, or substring)")
    ap.add_argument("--since", type=int, help="seq window lower bound (per room)")
    ap.add_argument("--until", type=int, help="seq window upper bound (per room)")
    ap.add_argument("--room", help="only trail rooms whose name contains this")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    a = ap.parse_args(argv)

    rooms = load_rooms(a.captures)
    if a.agent is None:  # discovery: who can be walked
        counts = Counter(r["from"] for rd in rooms.values() for r in rd["records"])
        seen = defaultdict(set)
        for label, rd in rooms.items():
            for r in rd["records"]:
                seen[r["from"]].add(label)
        rows = counts.most_common(15)
        if a.json:
            print(json.dumps({"top_agents": [
                {"did": d, "msgs": n, "rooms": sorted(seen[d])}
                for d, n in rows]}, ensure_ascii=False, indent=1))
        else:
            lines = [f"{n:7}  {d}  rooms={','.join(sorted(seen[d]))}"
                     for d, n in rows]
            print("\n".join(lines) if lines else "(no senders found)")
        return 0

    try:
        did = resolve_agent(rooms, a.agent)
    except KeyError as e:
        print(f"agent-trail-report: {e.args[0]}", file=sys.stderr)
        return 2
    trail = agent_trail(rooms, did, a.since, a.until, a.room)
    stats, totals = room_stats(trail)
    findings = audit_trail(trail, rooms, did)
    if a.json:
        print(json.dumps({
            "agent": did, "window": {"since": a.since, "until": a.until},
            "totals": {**totals, "span": None if not totals["span"] else
                       [totals["span"][0], totals["span"][1]]},
            "rooms": {k: {**v, "chain_head": chain_head(trail[k], k)}
                      for k, v in stats.items()},
            "findings": findings}, ensure_ascii=False, indent=1))
    else:
        render(trail, stats, totals, findings, did, (a.since, a.until))
    return 1 if [f for f in findings if f["severity"] != "INFO"] else 0


def self_test():
    import tempfile
    checks = 0

    assert parse_ts("2026-09-23T01:02:03.5Z") is not None
    assert parse_ts("bogus") is None and parse_ts(None) is None
    checks += 2

    with tempfile.TemporaryDirectory() as td:
        p1, p2 = os.path.join(td, "alpha.jsonl"), os.path.join(td, "beta.jsonl")
        with open(p1, "w") as f:
            f.write(json.dumps({"seq": 5, "ts": "2026-09-20T01:00:00Z",
                                "from": "did:key:AAA", "text": "work unit 1",
                                "nonce": 11, "sig": "s1"}) + "\n")
            f.write(json.dumps({"seq": 7, "ts": "2026-09-20T02:00:00Z",
                                "from": "did:key:BBB", "text": "other"}) + "\n")
            f.write(json.dumps({"seq": 9, "ts": "2026-09-20T03:00:00Z",
                                "from": "did:key:AAA", "text": "work unit 2",
                                "nonce": 12, "sig": "s2"}) + "\n")
            f.write("not json\n")
        with open(p2, "w") as f:
            f.write(json.dumps({"seq": 2, "ts": "2026-09-20T05:00:00Z",
                                "from": "did:key:AAA", "text": "work unit 3",
                                "nonce": 11, "sig": "s3"}) + "\n")
            f.write(json.dumps({"seq": 3, "ts": "2026-09-20T04:00:00Z",
                                "from": "did:key:CCC", "text": "steal",
                                "nonce": 1, "sig": "s1"}) + "\n")
            f.write(json.dumps({"seq": 4, "ts": "2026-09-20T04:30:00Z",
                                "from": "did:key:AAA", "text": "work unit 4",
                                "nonce": 13, "sig": "s4"}) + "\n")
        rooms = load_rooms([p1, p2])
        assert rooms["alpha.jsonl"]["malformed"] == 1
        checks += 1

        did = resolve_agent(rooms, "did:key:AA")
        assert did == "did:key:AAA"
        try:
            resolve_agent(rooms, "did:key:")
            raised = False
        except KeyError:
            raised = True
        assert raised
        checks += 2

        trail = agent_trail(rooms, did)
        assert set(trail) == {"alpha.jsonl", "beta.jsonl"}
        assert [r["seq"] for r in trail["alpha.jsonl"]] == [5, 9]
        assert [r["seq"] for r in trail["beta.jsonl"]] == [2, 4]
        assert set(agent_trail(rooms, did, since=6, until=8)) == set()
        assert [r["seq"] for r in agent_trail(rooms, did, since=6)
                ["alpha.jsonl"]] == [9]
        assert [r["seq"] for r in agent_trail(rooms, did, until=6)
                ["alpha.jsonl"]] == [5]
        assert set(agent_trail(rooms, did, room_filter="alph")) == {"alpha.jsonl"}
        checks += 5

        h1 = chain_head(trail["alpha.jsonl"], "alpha.jsonl")
        assert h1 == chain_head(agent_trail(load_rooms([p1]), did)["alpha.jsonl"],
                                "alpha.jsonl")
        mutated = [dict(r) for r in trail["alpha.jsonl"]]
        mutated[0]["text"] = "tampered"
        assert chain_head(mutated, "alpha.jsonl") != h1
        checks += 2

        findings = audit_trail(trail, rooms, did)
        codes = {f["code"] for f in findings}
        assert "sig-reuse" in codes       # s1 also filed by did:key:CCC
        assert "nonce-replay" in codes    # nonce 11 in alpha + beta
        assert "ts-regression" in codes   # beta seq 2->4, 05:00 -> 04:30
        stats, totals = room_stats(trail)
        assert totals["msgs"] == 4 and totals["rooms"] == 2
        assert stats["alpha.jsonl"]["uniq_texts"] == 2
        assert stats["beta.jsonl"]["seq_last"] == 4
        checks += 5

        # same-seq body conflict inside one room fires seq-conflict
        p3 = os.path.join(td, "gamma.jsonl")
        with open(p3, "w") as f:
            f.write(json.dumps({"seq": 5, "ts": "2026-09-20T01:00:00Z",
                                "from": "did:key:AAA", "text": "one",
                                "nonce": 21, "sig": "s5"}) + "\n")
            f.write(json.dumps({"seq": 5, "ts": "2026-09-20T01:30:00Z",
                                "from": "did:key:AAA", "text": "two",
                                "nonce": 22, "sig": "s6"}) + "\n")
        rooms3 = load_rooms([p3])
        t3 = agent_trail(rooms3, "did:key:AAA")
        assert [f["code"] for f in audit_trail(t3, rooms3, "did:key:AAA")] \
            == ["seq-conflict"]
        checks += 1

        # per-code row cap: 12 distinct dup nonces -> 8 rows + overflow summary
        flood = {"f.jsonl": [{"seq": i, "ts": float(i), "ts_raw": str(i),
                              "from": "did:key:AAA", "text": f"t{i}",
                              "nonce": i // 2, "sig": f"x{i}"}
                             for i in range(24)]}
        ff = audit_trail(flood, {"f.jsonl": {"records": flood["f.jsonl"],
                                              "malformed": 0}}, "did:key:AAA")
        fcodes = [f["code"] for f in ff]
        assert fcodes.count("nonce-replay") == MAX_ROWS
        assert "nonce-replay-overflow" in fcodes
        checks += 2

        # clean trail: no findings at all
        rooms2 = load_rooms([p1])
        trail2 = agent_trail(rooms2, "did:key:BBB")
        assert audit_trail(trail2, rooms2, "did:key:BBB") == []
        checks += 1

        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main(["--agent", "did:key:AAA", "--json", p1, p2])
            assert rc == 1
            rc2 = main(["--agent", "did:key:BBB", p1])
            assert rc2 == 0
            rc3 = main([p1, p2])
            assert rc3 == 0
        rc4 = main(["--agent", "nope-missing", p1])
        assert rc4 == 2
        checks += 4

    print(f"{checks}/{checks} OK")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
    else:
        sys.exit(main())
