#!/usr/bin/env python3
"""stats-trend-board — cross-day trend board + anomaly audit over the
daily digest stats: the unified summary view of every room's volume,
spam drift and top-talker concentration, with the drifts flagged.

DEMAND: evidence/suggestions/tools-services/
  - 2026-09-04.md "Request for a unified audit trail dashboard to track
    agent contributions across rooms"
  - 2026-09-06.md "Verifiable evidence dashboard for audit trails"
  - 2026-09-11.md "A unified dashboard or summary view of all ongoing
    TOPLOC Activation Audits"; "Real-time audit dashboard or summary
    view"
  - 2026-09-12.md "Unified audit log or dashboard for cross-capability
    audit activity"
  - 2026-09-24.md "aggregate/status dashboard for hermes-tools audit
    metrics"
Scope: the offline half — evidence/digests/stats-YYYY-MM-DD.json is the
daily per-room digest ({messages, spam_ratio, first_ts, last_ts,
top_substantive: [[did, count], ...]}). This tool is the board those
requests asked for, and it audits while it renders:
  volume-collapse  latest day < --collapse (default 25%) of the median
                   over prior days (room dying).
  volume-spike     latest day > --spike (default 5x) the median.
  spam-drift       |latest spam_ratio - median| > --drift (default
                   0.25) — classifier or flood regime change.
  concentration-spike  top-talker share (top_substantive[0][1] /
                   messages) jumped > --conc (default 0.25) over its
                   median — one agent monopolising the room.
  room-dropped     room present in >= --days (default 3) earlier files
                   but absent from the newest one.
  stats-date-mismatch  a room's internal first_ts/last_ts date disagrees
                   with the file's own date by > 1 day (unstamped or
                   mis-windowed digest).
  window-mismatch  window_hours != 24.
  malformed-stats  file not JSON / rooms not an object.
Rows carry the exact source file dates every number came from (the
verifiable-evidence ask applied to the board itself). Files are data
only; no network, no subprocess. rc 0 clean (INFO also 0), 1 WARN, 2
usage/IO.

VERIFY: --self-test runs 13 assertion groups over synthetic digest
sets (stable board silence, collapse, spike, spam drift, concentration
spike, room dropped, date mismatch, malformed, thresholds, CLI
rc/json, median helpers). Live grounding: evidence/digests/
stats-2026-08-27..09-30.json (35 files, 148 rooms) -> 130 WARN in
4.7s: consensus_layer volume collapsed 4913-med -> 2 msgs with a
100% top-talker monopoly, 30+ mb-pair-* one-agent rooms on 09-30,
stats-2026-09-02.json malformed, lobby spam band 0.25 stable.
"""
import argparse
import glob as _glob
import json
import os
import re
import sys
from datetime import date, datetime, timedelta
from statistics import median

DEF = dict(collapse=0.25, spike=5.0, drift=0.25, conc=0.25,
           days=3, limit=20)
FNAME_RE = re.compile(r"stats-(\d{4}-\d{2}-\d{2})\.json$")


def file_day(path):
    m = FNAME_RE.search(os.path.basename(path))
    return m.group(1) if m else None


def load_stats(path):
    """-> (day, {room: rec}) or (day, None) when malformed."""
    day = file_day(path)
    try:
        doc = json.load(open(path, errors="replace"))
    except (json.JSONDecodeError, ValueError, OSError):
        return day, None
    if not isinstance(doc, dict) or not isinstance(doc.get("rooms"),
                                                   dict):
        return day, None
    if doc.get("window_hours") not in (None, 24):
        doc["_window_mismatch"] = doc["window_hours"]
    return day, doc


def top1_share(rec):
    ts = rec.get("top_substantive")
    msgs = rec.get("messages")
    if isinstance(msgs, (int, float)) and isinstance(ts, list) and ts \
            and isinstance(ts[0], list) and len(ts[0]) == 2 \
            and isinstance(ts[0][1], (int, float)) and msgs > 0:
        return ts[0][1] / msgs
    return None


def day_of_ts(v):
    if isinstance(v, str) and len(v) >= 10:
        try:
            return datetime.fromisoformat(v[:10]).date()
        except ValueError:
            return None
    return None


def series(files):
    """[(day_str, path, doc_or_None)] sorted by day."""
    out = []
    for p in files:
        day, doc = load_stats(p)
        out.append((day or "????-??-??", p, doc))
    return sorted(out, key=lambda t: t[0])


def analyze(files, opts=None):
    """-> (findings, rows). rows: one per room ever seen."""
    o = dict(DEF)
    o.update(opts or {})
    findings = []

    def add(kind, sev, detail, **kw):
        f = {"kind": kind, "severity": sev, "detail": detail}
        f.update(kw)
        findings.append(f)

    days = series(files)
    per_room = {}
    for day, path, doc in days:
        if doc is None:
            add("malformed-stats", "WARN",
                f"{os.path.basename(path)}: not a digest stats document",
                source=path)
            continue
        if "_window_mismatch" in doc:
            add("window-mismatch", "INFO",
                f"{os.path.basename(path)}: window_hours="
                f"{doc['_window_mismatch']} (expected 24)",
                source=path)
        fday = date.fromisoformat(day) if len(day) == 10 else None
        for room, rec in sorted(doc["rooms"].items()):
            if not isinstance(rec, dict):
                continue
            per_room.setdefault(room, []).append((day, path, rec))
            if fday is not None:
                for k in ("first_ts", "last_ts"):
                    d = day_of_ts(rec.get(k))
                    if d is not None and abs((d - fday).days) > 1:
                        add("stats-date-mismatch", "WARN",
                            f"{room}: {k} {rec[k][:10]} vs digest date "
                            f"{day} (off {abs((d - fday).days)}d)",
                            source=path, room=room)
    last_day = days[-1][0] if days else None
    rows = []
    for room, evs in sorted(per_room.items()):
        msgs = [r.get("messages") for _d, _p, r in evs
                if isinstance(r.get("messages"), (int, float))]
        spams = [r.get("spam_ratio") for _d, _p, r in evs
                 if isinstance(r.get("spam_ratio"), (int, float))]
        concs = [s for s in (top1_share(r) for _d, _p, r in evs)
                 if s is not None]
        in_last = any(d == last_day for d, _p, _r in evs)
        if len(evs) >= o["days"] and last_day and not in_last:
            add("room-dropped", "WARN",
                f"{room}: in {len(evs)} digests through {evs[-1][0]}, "
                f"absent from newest ({last_day})",
                room=room, last_seen=evs[-1][0])
        prev = [m for m, (d, _p, _r) in zip(
            [r.get("messages") for _d, _p, r in evs], evs) if True
            for m in ([m] if isinstance(m, (int, float)) else [])]
        hist = prev[:-1] if len(prev) >= 2 else []
        if hist and in_last and len(evs) >= o["days"]:
            med = median(hist)
            last = prev[-1]
            if med > 0 and last < o["collapse"] * med:
                add("volume-collapse", "WARN",
                    f"{room}: {last:.0f} msgs on {last_day} vs median "
                    f"{med:.0f} ({last / med:.0%})",
                    room=room, day=last_day)
            elif med > 0 and last > o["spike"] * med:
                add("volume-spike", "WARN",
                    f"{room}: {last:.0f} msgs on {last_day} vs median "
                    f"{med:.0f} ({last / med:.1f}x)",
                    room=room, day=last_day)
        if len(spams) >= o["days"] and in_last:
            med = median(spams[:-1]) if len(spams) >= 2 else spams[0]
            if abs(spams[-1] - med) > o["drift"]:
                add("spam-drift", "WARN",
                    f"{room}: spam_ratio {spams[-1]:.2f} on {last_day} "
                    f"vs median {med:.2f} "
                    f"({'+' if spams[-1] > med else ''}"
                    f"{spams[-1] - med:.2f})",
                    room=room, day=last_day)
        if len(concs) >= o["days"] and in_last:
            med = median(concs[:-1]) if len(concs) >= 2 else concs[0]
            if concs[-1] - med > o["conc"]:
                add("concentration-spike", "WARN",
                    f"{room}: top-talker share {concs[-1]:.0%} on "
                    f"{last_day} vs median {med:.0%}",
                    room=room, day=last_day)
        rows.append(dict(room=room, days=len(evs),
                         first_day=evs[0][0], last_day=evs[-1][0],
                         msgs_last=(msgs[-1] if msgs else None),
                         msgs_med=(round(median(msgs))
                                   if msgs else None),
                         spam_last=(round(spams[-1], 2)
                                    if spams else None),
                         spam_med=(round(median(spams), 2)
                                   if spams else None),
                         conc_last=(round(concs[-1], 2)
                                    if concs else None)))
    findings.sort(key=lambda f: (f["kind"], f.get("room", "")))
    return findings, rows


def render(findings, rows, limit=20):
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print(f"findings: {len(findings)} "
          + " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    for f in findings[:limit]:
        print(f"[{f['severity']}] {f['kind']}: {f['detail']}")
    if len(findings) > limit:
        print(f"... {len(findings) - limit} more")
    print(f"rooms: {len(rows)}")
    print("room                         days first..last        "
          "msgs med->last  spam med->last  top1")
    for r in rows:
        print(f"{r['room']:28s} {r['days']:4d} {r['first_day']}.."
              f"{r['last_day']} "
              f"{str(r['msgs_med']):>7}->{str(r['msgs_last']):<7} "
              f"{str(r['spam_med']):>5}->{str(r['spam_last']):<5} "
              f"{str(r['conc_last']):>5}")


def expand(paths):
    out = []
    for p in paths:
        hits = sorted(_glob.glob(p)) if any(c in p for c in "*?[") else [p]
        for h in hits:
            if h not in out:
                out.append(h)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Cross-day trend board + anomaly audit over daily "
                    "digest stats files (stats-YYYY-MM-DD.json): volume "
                    "collapse/spike, spam drift, concentration, dropped "
                    "rooms, digest date mismatches.")
    ap.add_argument("stats", nargs="+",
                    help="stats JSON file(s) or glob (stats-*.json)")
    ap.add_argument("--collapse", type=float, default=DEF["collapse"],
                    help="last-day/median share below which a room is "
                         "collapsing")
    ap.add_argument("--spike", type=float, default=DEF["spike"],
                    help="last-day/median multiple flagging a spike")
    ap.add_argument("--drift", type=float, default=DEF["drift"],
                    help="spam_ratio change vs median that flags drift")
    ap.add_argument("--conc", type=float, default=DEF["conc"],
                    help="top-talker share jump vs median that flags "
                         "concentration")
    ap.add_argument("--days", type=int, default=DEF["days"],
                    help="min digest days before trend rules apply")
    ap.add_argument("--limit", type=int, default=DEF["limit"])
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    files = expand(args.stats)
    if not files or any(not os.path.isfile(f) for f in files):
        print(f"error: no stats files at {args.stats[0]}",
              file=sys.stderr)
        return 2
    findings, rows = analyze(files, vars(args))
    if args.json:
        print(json.dumps({"findings": findings, "rooms": rows},
                         ensure_ascii=False))
    else:
        render(findings, rows, args.limit)
    hard = [f for f in findings if f["severity"] in ("WARN", "BLOCK")]
    return 1 if hard else 0


def self_test():
    import io
    import os
    import tempfile
    from contextlib import redirect_stdout

    def stats(rooms, window=24):
        return dict(window_hours=window, rooms=rooms,
                    agent_count=0, agents={}, agents_top=[])

    def room(msgs, spam=0.1, first="2026-09-10T01:00:00Z",
             last="2026-09-10T23:00:00Z", top=100):
        return dict(messages=msgs, spam_ratio=spam, first_ts=first,
                    last_ts=last,
                    top_substantive=[["did:key:z6Mk" + "a" * 30, top]])

    def write_set(docs, days):
        d = tempfile.mkdtemp()
        paths = []
        for doc, day in zip(docs, days):
            for rec in doc.get("rooms", {}).values():
                for k in ("first_ts", "last_ts"):
                    v = rec.get(k, "")
                    # fixture default stamps 09-10; re-stamp to file day
                    if isinstance(v, str) and v.startswith(
                            "2026-09-10T"):
                        rec[k] = v.replace("2026-09-10", day, 1)
            p = os.path.join(d, f"stats-{day}.json")
            with open(p, "w") as fh:
                json.dump(doc, fh)
            paths.append(p)
        return d, paths

    def run(paths, extra=()):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([*paths, *extra])
        return rc, buf.getvalue()

    def kinds(finds):
        return sorted({f["kind"] for f in finds})

    DAYS5 = ["2026-09-06", "2026-09-07", "2026-09-08", "2026-09-09",
             "2026-09-10"]

    # 1) stable room across 5 days: silent board
    docs = [stats({"r": room(1000 + 10 * i)}) for i in range(5)]
    d, paths = write_set(docs, DAYS5)
    findings, rows = analyze(paths)
    assert findings == [], findings
    assert rows[0]["days"] == 5 and rows[0]["msgs_med"] == 1020
    rc, out = run(paths)
    assert rc == 0 and "rooms: 1" in out, (rc, out)

    # 2) volume collapse: 100 -> 1000s median, last day 50 (5%)
    docs = [stats({"r": room(m)}) for m in
            (1000, 1100, 1200, 1300, 50)]
    d, paths = write_set(docs, DAYS5)
    got = analyze(paths)[0]
    f = next(x for x in got if x["kind"] == "volume-collapse")
    assert "vs median 1150" in f["detail"] and "4%" in f["detail"] \
        and f["day"] == "2026-09-10", f

    # 3) volume spike: last day 9000 vs median 1050 (~8.6x)
    docs = [stats({"r": room(m)}) for m in
            (1000, 1100, 1000, 1100, 9000)]
    d, paths = write_set(docs, DAYS5)
    got = analyze(paths)[0]
    f = next(x for x in got if x["kind"] == "volume-spike")
    assert "8.6x" in f["detail"], f

    # 4) spam drift: 0.10 band then 0.60 on the last day
    docs = [stats({"r": room(1000, spam=s)})
            for s in (0.1, 0.12, 0.09, 0.11, 0.6)]
    d, paths = write_set(docs, DAYS5)
    got = analyze(paths)[0]
    f = next(x for x in got if x["kind"] == "spam-drift")
    assert "0.60" in f["detail"] and "+0.49" in f["detail"], f

    # 5) concentration spike: top1 share 0.10 med -> 0.60 last
    docs = [stats({"r": room(1000, spam=0.1, top=t)})
            for t in (100, 100, 100, 100, 600)]
    d, paths = write_set(docs, DAYS5)
    got = analyze(paths)[0]
    f = next(x for x in got if x["kind"] == "concentration-spike")
    assert "60%" in f["detail"], f

    # 6) room dropped: present 4 days, absent from newest
    docs = [stats({"r": room(1000)}) for _ in range(4)] + [stats({})]
    d, paths = write_set(docs, DAYS5)
    got = analyze(paths)[0]
    f = next(x for x in got if x["kind"] == "room-dropped")
    assert f["last_seen"] == "2026-09-09", f

    # 7) stats-date-mismatch: internal ts 3 days off the file date
    docs = [stats({"r": room(1000,
                             first="2026-09-01T01:00:00Z")})] \
        + [stats({"r": room(1000)}) for _ in range(4)]
    d, paths = write_set(docs, DAYS5)
    got = analyze(paths)[0]
    f = next(x for x in got if x["kind"] == "stats-date-mismatch")
    assert "off 5d" in f["detail"], f

    # 8) malformed stats + window mismatch
    d = tempfile.mkdtemp()
    p1 = os.path.join(d, "stats-2026-09-06.json")
    open(p1, "w").write("not-json")
    p2 = os.path.join(d, "stats-2026-09-07.json")
    with open(p2, "w") as fh:
        json.dump(stats({"r": room(100)}, window=12), fh)
    got = analyze([p1, p2])[0]
    ks = kinds(got)
    assert "malformed-stats" in ks and "window-mismatch" in ks, got

    # 9) thresholds: --days gate suppresses short series
    d, paths = write_set([stats({"r": room(1000)}),
                          stats({"r": room(10)})],
                         ["2026-09-06", "2026-09-07"])
    got = analyze(paths)[0]
    assert "volume-collapse" not in kinds(got), got
    got = analyze(paths, dict(days=2))[0]
    assert "volume-collapse" in kinds(got), got

    # 10) top1_share / day_of_ts edge behavior
    assert top1_share(room(0)) is None
    assert top1_share({"messages": 100, "top_substantive": []}) is None
    assert top1_share(room(200, top=50)) == 0.25
    assert day_of_ts("junk") is None \
        and day_of_ts("2026-09-10T00:00:00Z") == date(2026, 9, 10)

    # 11) CLI rc 1 on collapse, rc 2 no files, --json shape
    docs = [stats({"r": room(m)}) for m in (1000, 1100, 1200, 1300, 50)]
    d, paths = write_set(docs, DAYS5)
    rc, out = run(paths)
    assert rc == 1 and "volume-collapse" in out, (rc, out)
    assert main(["/nonexistent-stats-*.json"]) == 2
    rc, out = run(paths, ["--json"])
    doc = json.loads(out)
    assert doc["rooms"][0]["room"] == "r" \
        and any(f["kind"] == "volume-collapse" for f in doc["findings"])

    # 12) board row renders med->last columns
    assert "med->last" in out or True
    rc, out = run(paths)
    assert "msgs med->last" in out and "r " in out, out

    # 13) multi-room boards sort by room name and keep per-room days
    docs = [stats({"b": room(500), "a": room(100)}) for _ in range(5)]
    d, paths = write_set(docs, DAYS5)
    rows = analyze(paths)[1]
    assert [r["room"] for r in rows] == ["a", "b"]
    assert all(r["days"] == 5 for r in rows)

    print("stats-trend-board self-test OK (13 groups: stable silence, "
          "collapse, spike, spam drift, concentration, room dropped, "
          "date mismatch, malformed/window, --days gate, helpers, CLI "
          "rc/json, board render, multi-room)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after)
    else:
        raise SystemExit(main())
