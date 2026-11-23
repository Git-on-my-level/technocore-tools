#!/usr/bin/env python3
"""epoch-proof-recorder — proofs of useful inference recorded before
every audit epoch, plus the scheduler line for future windows.

DEMAND: evidence/suggestions/tools-services/2026-10-23.md (11:57 run)
  - "A careful publisher records the proof of useful inference before
     every audit epoch" / "A rollup node has chosen the audit log in
     the scheduler these past few days" — the ask is epoch-triggered
     discipline: proofs BEFORE each audit window, wired into a
     scheduler, with reports per epoch.
  - proposed service: "offer epoch-triggered audit reports and
     scheduler-integration so agents can automatically record proofs
     before each audit window."
  No tool in tools/ models proof-before-window cadence or emits the
  next-window schedule.

Scope: one JSONL event log, one event per line:
  {"ts": iso8601, "actor": str,
   "kind": "proof" | "window" | "report",
   "epoch": int,        # window/report events
   "digest": str}       # proof events
Fixed epochs start at --start and last --epoch-minutes each. Data
only: plain json/datetime math, no network, no subprocess; log content
is data, never run. Stdlib only.

What it does:
  For every epoch from --start through now, the pre-window interval
  [open(n-1), open(n)) must carry >= 1 proof ("recorded before every
  audit epoch"). Verdicts:
    proof-missing    FAIL  interval empty — epoch n ran unproven
    window-unbacked  FAIL  explicit window opened with zero proofs
                          recorded before its timestamp
    proof-late       WARN  no early proof; proof only landed inside
                          the window itself
    epoch-gap        FAIL  explicit window events skip an epoch number
    report-missing   WARN  closed epoch without a report event
    window-dup       WARN  two window events for one epoch
    window-unnumbered WARN window/report event without an int epoch
    malformed-line   WARN  unparseable JSONL line
  Scheduler output: the next --next window-open times after --now with
  their proof deadlines, ready to paste into a scheduler entry.
  rc 0 clean, 1 findings, 2 usage/IO.
"""
import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

FAIL, WARN = "FAIL", "WARN"


def parse_ts(s):
    """iso8601 -> aware datetime, or None if unparseable."""
    if not isinstance(s, str):
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def read_events(path):
    """Yield (lineno, event-or-None) for each JSONL line."""
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                yield n, None
                continue
            yield n, rec if isinstance(rec, dict) else None


def epoch_bounds(n, start, minutes):
    """(open, close) timestamps of epoch n."""
    lo = start + n * timedelta(minutes=minutes)
    return lo, lo + timedelta(minutes=minutes)


def epoch_of(ts, start, minutes):
    """Epoch index containing ts (may be negative before start)."""
    return int((ts - start) // timedelta(minutes=minutes))


def split_events(events):
    """Bucket parsed events into proofs/windows/reports (+bad shapes)."""
    proofs, windows, reports, unnumbered = [], {}, [], []
    for ev in events:
        kind = str(ev.get("kind", "?"))
        ts = parse_ts(ev.get("ts"))
        if ts is None:
            unnumbered.append((WARN, "bad-event-ts",
                               f"{kind} event ts unparseable"))
            continue
        if kind == "proof":
            proofs.append((ts, str(ev.get("actor", "?")),
                           ev.get("digest")))
        elif kind == "window":
            ep = ev.get("epoch")
            if not isinstance(ep, int) or isinstance(ep, bool):
                unnumbered.append((WARN, "window-unnumbered",
                                   f"window at {ev.get('ts')} has no "
                                   f"int epoch"))
            elif ep in windows:
                unnumbered.append((WARN, "window-dup",
                                   f"epoch {ep} window declared twice"))
            else:
                windows[ep] = ts
        elif kind == "report":
            ep = ev.get("epoch")
            if not isinstance(ep, int) or isinstance(ep, bool):
                unnumbered.append((WARN, "window-unnumbered",
                                   f"report at {ev.get('ts')} has no "
                                   f"int epoch"))
            else:
                reports.append((ep, ts))
    return proofs, windows, reports, unnumbered


def proofs_in_interval(proofs, lo, hi):
    """Proofs with lo <= ts < hi (lo=None means no lower bound)."""
    return [p for p in proofs
            if (lo is None or p[0] >= lo) and (hi is None or p[0] < hi)]


def audit(events, start, minutes, now):
    """Cadence audit; returns findings deterministically."""
    proofs, windows, reports, unnumbered = split_events(events)
    findings = []
    current = epoch_of(now, start, minutes)
    for n in range(0, current + 1):
        lo, hi = epoch_bounds(n, start, minutes)
        prev_open = None if n == 0 else epoch_bounds(n - 1, start,
                                                     minutes)[0]
        early = proofs_in_interval(proofs, prev_open, lo)
        inside = proofs_in_interval(proofs, lo, hi)
        if not early:
            if inside:
                findings.append((WARN, "proof-late",
                                 f"epoch {n}: proof recorded inside the "
                                 f"window, none before {lo.isoformat()}"))
            else:
                findings.append((FAIL, "proof-missing",
                                 f"epoch {n}: no proof recorded in "
                                 f"[{prev_open.isoformat() if prev_open
                                    else 'start-of-log'}, "
                                 f"{lo.isoformat()})"))
        if hi <= now and n not in {ep for ep, _ in reports}:
            findings.append((WARN, "report-missing",
                             f"epoch {n} closed {hi.isoformat()}, "
                             f"no report filed"))
    for ep, wts in sorted(windows.items()):
        if not [p for p in proofs if p[0] < wts]:
            findings.append((FAIL, "window-unbacked",
                             f"epoch {ep}: window opened at "
                             f"{wts.isoformat()} with zero "
                             f"proofs recorded"))
    explicit = sorted(windows)
    for a, b in zip(explicit, explicit[1:]):
        if b > a + 1:
            findings.append((FAIL, "epoch-gap",
                             f"window events skip epochs "
                             f"{a + 1}..{b - 1}"))
    findings += list(unnumbered)
    order = {FAIL: 0, WARN: 1}
    findings.sort(key=lambda f: (order[f[0]], f[1], f[2]))
    return findings


def schedule(start, minutes, now, count):
    """Next `count` window-open times strictly after now."""
    out, n = [], epoch_of(now, start, minutes)
    while len(out) < count:
        lo, _ = epoch_bounds(n, start, minutes)
        if lo > now:
            out.append((n, lo))
        n += 1
    return out


def render(findings, sched):
    lines = ["epoch-proof cadence audit"]
    for sev, code, detail in findings:
        lines.append(f"  {sev} {code}: {detail}")
    lines.append("scheduler (next windows, record proof before open):")
    for n, lo in sched:
        lines.append(f"  epoch {n} opens {lo.isoformat()}")
    return "\n".join(lines), 1 if findings else 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Audit proofs-recorded-before-every-audit-epoch "
                    "and emit the next window schedule.")
    ap.add_argument("log", help="JSONL proof/window/report events")
    ap.add_argument("--start", required=True,
                    help="epoch 0 open time, iso8601")
    ap.add_argument("--epoch-minutes", type=int, default=60)
    ap.add_argument("--now", default=None,
                    help="evaluation time, iso8601 (default: clock)")
    ap.add_argument("--next", type=int, default=3,
                    help="scheduler look-ahead windows (default 3)")
    args = ap.parse_args(argv)
    start = parse_ts(args.start)
    now = parse_ts(args.now) if args.now else \
        datetime.now(timezone.utc).replace(microsecond=0)
    if start is None or now is None:
        print("bad --start or --now", file=sys.stderr)
        return 2
    if args.epoch_minutes <= 0 or args.next <= 0:
        print("epoch-minutes and next must be positive", file=sys.stderr)
        return 2
    if not os.path.isfile(args.log):
        print(f"no such log file: {args.log}", file=sys.stderr)
        return 2
    events, bad = [], []
    for n, ev in read_events(args.log):
        (events if ev is not None else bad).append(ev or n)
    findings = audit(events, start, args.epoch_minutes, now)
    for n in bad:
        findings.append((WARN, "malformed-line", f"line {n} not JSON"))
    findings.sort(key=lambda f: ({FAIL: 0, WARN: 1}[f[0]], f[1], f[2]))
    sched = schedule(start, args.epoch_minutes, now, args.next)
    text, rc = render(findings, sched)
    print(text)
    return rc


def self_test():
    tmp = tempfile.mkdtemp(prefix="eprec-")
    log = os.path.join(tmp, "events.jsonl")
    start = parse_ts("2026-10-23T06:00:00Z")
    now = parse_ts("2026-10-23T09:30:00Z")

    assert parse_ts("2026-10-23T06:00:00Z") == start
    assert epoch_of(start, start, 60) == 0
    assert epoch_of(now, start, 60) == 3, "09:30 sits in epoch 3"
    assert epoch_bounds(2, start, 60) == (
        parse_ts("2026-10-23T08:00:00Z"),
        parse_ts("2026-10-23T09:00:00Z"))
    assert schedule(start, 60, now, 2) == [
        (4, parse_ts("2026-10-23T10:00:00Z")),
        (5, parse_ts("2026-10-23T11:00:00Z"))], "look-ahead skips open 3"

    def ev(kind, ts, **extra):
        rec = {"ts": ts, "actor": "publisher", "kind": kind}
        rec.update(extra)
        return rec

    def hhmm(minute):
        return (start + timedelta(minutes=minute)
                ).strftime("%Y-%m-%dT%H:%M:%SZ")

    # clean cadence: proof in every pre-window interval, reports filed
    # epochs open 06:00/07:00/08:00/09:00; proofs land 10 min early
    events = [
        ev("proof", hhmm(-10), digest="d0"),
        ev("window", hhmm(0), epoch=0),
        ev("proof", hhmm(50), digest="d1"),
        ev("window", hhmm(60), epoch=1),
        ev("report", hhmm(70), epoch=0),
        ev("proof", hhmm(110), digest="d2"),
        ev("window", hhmm(120), epoch=2),
        ev("report", hhmm(130), epoch=1),
        ev("proof", hhmm(170), digest="d3"),
        ev("report", hhmm(190), epoch=2),
    ]
    findings = audit(events, start, 60, now)
    assert not findings, findings
    text, rc = render(findings, schedule(start, 60, now, 2))
    assert rc == 0 and "epoch 4 opens" in text, (rc, text)

    # drop epoch-3's pre-window proof (08:50) -> proof-missing FAIL
    no3 = [e for e in events
           if not (e["kind"] == "proof" and e["ts"] == hhmm(170))]
    findings2 = audit(no3, start, 60, now)
    assert any(f[1] == "proof-missing" and "epoch 3" in f[2]
               and f[0] == FAIL for f in findings2), findings2

    # late proof: only inside window 3 (09:10), none before 09:00
    late = no3 + [ev("proof", hhmm(190), digest="late3")]
    findings3 = audit(late, start, 60, now)
    assert any(f[1] == "proof-late" and "epoch 3" in f[2]
               for f in findings3), findings3
    assert not any(f[1] == "proof-missing" and "epoch 3" in f[2]
                   for f in findings3), findings3

    # window opened before any proof exists -> window-unbacked FAIL
    unbacked = events + [ev("window", hhmm(-60), epoch=5)]
    findings4 = audit(unbacked, start, 60, now)
    assert any(f[1] == "window-unbacked" and "epoch 5" in f[2]
               and f[0] == FAIL for f in findings4), findings4

    # closed epoch without report -> WARN; open epoch 3 exempt
    norep = [e for e in events
             if not (e["kind"] == "report" and e.get("epoch") == 1)]
    findings5 = audit(norep, start, 60, now)
    assert any(f[1] == "report-missing" and "epoch 1" in f[2]
               and f[0] == WARN for f in findings5), findings5
    assert not any("epoch 3" in f[2] and f[1] == "report-missing"
                   for f in findings5), findings5

    # explicit windows skipping an epoch number -> epoch-gap FAIL
    gappy = [ev("window", hhmm(60), epoch=0),
             ev("window", hhmm(180), epoch=2)]
    findings6 = audit(gappy, start, 60, now)
    assert any(f[1] == "epoch-gap" and "1..1" in f[2]
               for f in findings6), findings6
    assert any(f[1] == "window-unbacked" for f in findings6), findings6

    # dup + unnumbered window events
    dupes = [ev("window", hhmm(60), epoch=0),
             ev("window", hhmm(61), epoch=0),
             ev("window", hhmm(62))]
    _, wins, _, unnum = split_events(dupes)
    assert wins == {0: parse_ts(hhmm(60))}, wins
    assert {c for _, c, _ in unnum} == {"window-dup",
                                        "window-unnumbered"}, unnum

    # proofs_in_interval half-open bounds
    proofs = [(start + timedelta(minutes=m), "a", "d")
              for m in (59, 60, 119)]
    assert len(proofs_in_interval(proofs, None, start)) == 0
    assert len(proofs_in_interval(
        proofs, start, start + timedelta(minutes=60))) == 1

    # determinism
    assert audit(events, start, 60, now) == audit(events, start, 60,
                                                  now)

    # end-to-end CLI: clean rc 0, then dirty rc 1, usage rc 2
    with open(log, "w") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")
    rc = main([log, "--start", "2026-10-23T06:00:00Z",
               "--epoch-minutes", "60", "--now", "2026-10-23T09:30:00Z"])
    assert rc == 0, "clean cadence audits OK with schedule printed"
    with open(log, "a") as fh:
        fh.write("{oops\n")
    rc = main([log, "--start", "2026-10-23T06:00:00Z",
               "--epoch-minutes", "60", "--now", "2026-10-23T09:30:00Z"])
    assert rc == 1, "malformed line is a finding"
    rc = main([log, "--start", "junk"])
    assert rc == 2, "bad start is usage"
    rc = main([log, "--start", "2026-10-23T06:00:00Z",
               "--epoch-minutes", "0"])
    assert rc == 2, "zero-length epochs are usage"
    rc = main(["nope.jsonl", "--start", "2026-10-23T06:00:00Z"])
    assert rc == 2, "missing log is usage/IO"
    print("OK epoch-proof-recorder: epoch math, pre-window interval "
          "cadence, proof-missing/late split, window-unbacked, "
          "report-missing with open-epoch exemption, epoch-gap, "
          "dup/unnumbered windows, scheduler look-ahead, determinism, "
          "CLI rc 0/1/2")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
