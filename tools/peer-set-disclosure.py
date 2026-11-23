#!/usr/bin/env python3
"""peer-set-disclosure — pre-vote room roster disclosure audit: for every
vote event in a capture, reconstruct the peer set as it stood at the
disclosure deadline (--lead-secs before the vote opens), report it, and
flag late roster changes after the deadline plus voters who were not in
the disclosed set.

DEMAND: evidence/suggestions/tools-services/2026-11-16.md (05:59 run)
  - request: "Desire for audit tools to reveal peer set inside deal
    room before next vote and similar disclosures" — evidence: "Audit
    tools will reveal the peer set inside the deal room before the
    next vote." — proposed service: "hermes-tools could add a
    scheduled audit disclosure that reports peer sets / internal
    states of rooms ahead of governance events".

Distinct from room-dedup.py (message duplication advice),
room-export-verify.py (export seq/hash integrity) and
quorum-price-audit.py (quorum pricing): this is the membership×vote
correlation — who was entitled per the disclosed roster, who joined
too late to be disclosed, who voted without being in the set.

Input (data only — parsed, never run): JSONL capture, one event per
line, all rooms unless --room filters:
  {"ts":"2026-11-16T10:00:00Z","kind":"join","room":"deal-room",
   "peer":"did:key:z6A..."}
  {"ts":...,"kind":"leave","room":"deal-room","peer":"did:..."}
  {"ts":...,"kind":"vote","room":"deal-room","vote_id":"v9",
   "voter":"did:..."}           # voter optional
ts ISO-8601 (naive = UTC) or epoch seconds. Findings per vote:
  late-roster-change  WARN  join/leave strictly after the disclosure
                           deadline (roster not knowable when the
                           pre-vote disclosure should have been made;
                           needs re-disclosure).
  undisclosed-voter   WARN  vote carries a voter absent from the
                           disclosed set.
  empty-roster        INFO  vote in a room with no members at the
                           deadline (nothing disclosable).
rc 0 = no WARN findings; 1 = findings; 2 = usage / unreadable input.
"""

import argparse
import datetime as dt
import json
import sys

KINDS = ("join", "leave", "vote")


def parse_ts(value):
    """ISO-8601 (naive = UTC) or epoch seconds → aware datetime."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return dt.datetime.fromtimestamp(value, dt.timezone.utc)
    text = str(value).strip().replace("Z", "+00:00")
    try:
        when = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    return when


def parse_events(lines):
    """JSONL events → (membership+votes, errors)."""
    events, errors = [], []
    for n, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            errors.append({"line": n, "error": "unparsable json"})
            continue
        if not isinstance(obj, dict) or obj.get("kind") not in KINDS:
            errors.append({"line": n, "error": "unknown kind"})
            continue
        when = parse_ts(obj.get("ts", ""))
        if when is None:
            errors.append({"line": n, "error": "bad ts"})
            continue
        room = str(obj.get("room", ""))
        peer = str(obj.get("peer") or obj.get("voter") or "")
        if not room or not peer:
            errors.append({"line": n, "error": "missing room/peer"})
            continue
        events.append({"n": n, "ts": when, "kind": obj["kind"],
                       "room": room, "peer": peer,
                       "vote_id": str(obj.get("vote_id", ""))})
    return events, errors


def roster_at(events, room, deadline):
    """Members of `room` at `deadline` (events at the deadline count)."""
    members = set()
    for ev in sorted((e for e in events if e["room"] == room
                      and e["kind"] in ("join", "leave")),
                     key=lambda e: (e["ts"], e["n"])):
        if ev["ts"] > deadline:
            break
        if ev["kind"] == "join":
            members.add(ev["peer"])
        else:
            members.discard(ev["peer"])
    return members


def disclose(events, lead_secs):
    """Per-vote disclosure blocks + findings across all rooms."""
    votes = sorted((e for e in events if e["kind"] == "vote"),
                   key=lambda e: (e["ts"], e["n"]))
    blocks, findings = [], []
    for vote in votes:
        deadline = vote["ts"] - dt.timedelta(seconds=lead_secs)
        roster = roster_at(events, vote["room"], deadline)
        window = [e for e in events
                  if e["room"] == vote["room"]
                  and e["kind"] in ("join", "leave")
                  and deadline < e["ts"] <= vote["ts"]]
        blocks.append({
            "room": vote["room"], "vote_id": vote["vote_id"],
            "vote_ts": vote["ts"].isoformat(),
            "deadline": deadline.isoformat(),
            "disclosed_set": sorted(roster),
            "late_changes": [{"kind": e["kind"], "peer": e["peer"],
                              "ts": e["ts"].isoformat()}
                             for e in window]})
        for change in window:
            findings.append({
                "signal": "late-roster-change", "level": "WARN",
                "room": vote["room"], "vote_id": vote["vote_id"],
                "note": ("%s %s after the disclosure deadline (%s)"
                         % (change["kind"], change["peer"],
                            change["ts"]))})
        if not roster:
            findings.append({
                "signal": "empty-roster", "level": "INFO",
                "room": vote["room"], "vote_id": vote["vote_id"],
                "note": "no members at the disclosure deadline"})
        if vote["peer"] not in roster:
            findings.append({
                "signal": "undisclosed-voter", "level": "WARN",
                "room": vote["room"], "vote_id": vote["vote_id"],
                "note": ("voter %s voted but was not in the disclosed "
                         "set" % vote["peer"])})
    return blocks, findings


def render(blocks, findings, errors, lead_secs):
    lines = ["peer-set-disclosure: %d vote(s), lead %ds"
             % (len(blocks), lead_secs)]
    for b in blocks:
        lines.append("  vote %-8s room=%-12s roster@deadline=%s"
                     % (b["vote_id"] or "?", b["room"],
                        ",".join(p[:12] for p in b["disclosed_set"])
                        or "-"))
    for f in findings:
        lines.append("[%s] %s %s/%s: %s"
                     % (f["level"], f["signal"], f["room"],
                        f["vote_id"] or "?", f["note"]))
    for e in errors:
        lines.append("[WARN] parse-error line %s: %s"
                     % (e["line"], e["error"]))
    return "\n".join(lines)


def run(opt):
    """Load capture, disclose, print, return the exit code."""
    try:
        lines = (sys.stdin.readlines() if opt.capture == "-"
                 else open(opt.capture, errors="replace").readlines())
    except OSError as exc:
        print("peer-set-disclosure: unreadable input: %s" % exc,
              file=sys.stderr)
        return 2
    events, errors = parse_events(lines)
    if opt.room:
        events = [e for e in events if e["room"] == opt.room]
    blocks, findings = disclose(events, opt.lead_secs)
    if opt.json:
        print(json.dumps({"votes": blocks, "findings": findings,
                          "parse_errors": errors},
                         ensure_ascii=False))
    else:
        print(render(blocks, findings, errors, opt.lead_secs))
    bad = any(f["level"] == "WARN" for f in findings) or errors
    return 1 if bad else 0


def build_parser():
    ap = argparse.ArgumentParser(
        prog="peer-set-disclosure",
        description="Reconstruct the pre-vote peer set per vote event "
                    "and flag late roster changes and undisclosed "
                    "voters.")
    ap.add_argument("capture", nargs="?", help="JSONL event capture")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--lead-secs", type=int, default=3600,
                    help="disclosure deadline before each vote "
                         "(default 3600)")
    ap.add_argument("--room", default="",
                    help="restrict to one room")
    return ap


def self_test():
    import json as _json
    import os
    import tempfile

    # ts layer
    assert parse_ts("2026-11-16T10:00:00Z") is not None
    assert (parse_ts("2026-11-16T10:00:00")
            == parse_ts("2026-11-16T10:00:00Z"))
    assert parse_ts(1763283600) is not None
    assert parse_ts("soon") is None

    # roster reconstruction: join/leave order, rejoin, deadline
    # inclusivity (an event AT the deadline is disclosed)
    def ev(ts, kind, room="deal-room", peer="p1", n=0, vote_id=""):
        return {"n": n, "ts": parse_ts(ts), "kind": kind, "room": room,
                "peer": peer, "vote_id": vote_id}
    t0 = "2026-11-16T10:00:00Z"
    hist = [ev(t0, "join", peer="p1"),
            ev("2026-11-16T10:05:00Z", "join", peer="p2"),
            ev("2026-11-16T10:10:00Z", "leave", peer="p1"),
            ev("2026-11-16T10:15:00Z", "join", peer="p1")]
    dl = parse_ts("2026-11-16T10:15:00Z")
    assert roster_at(hist, "deal-room", dl) == {"p1", "p2"}
    assert roster_at(hist, "deal-room",
                     parse_ts("2026-11-16T10:07:00Z")) == {"p1", "p2"}
    assert roster_at(hist, "other-room", dl) == set()

    # clean vote: both voters disclosed, roster stable across the
    # lead window
    cap = hist + [
        ev("2026-11-16T12:00:00Z", "vote", peer="p1", n=10,
           vote_id="v1"),
        ev("2026-11-16T12:00:30Z", "vote", peer="p2", n=11,
           vote_id="v1b"),
    ]
    blocks, findings = disclose(cap, 3600)
    b1 = [b for b in blocks if b["vote_id"] == "v1"][0]
    assert b1["disclosed_set"] == ["p1", "p2"], b1
    assert not [f for f in findings if f["level"] == "WARN"], findings

    # filed risk: a peer joins INSIDE the lead window and votes —
    # late roster change + undisclosed voter
    cap2 = cap + [
        ev("2026-11-16T11:30:00Z", "join", peer="p3"),
        ev("2026-11-16T12:01:00Z", "vote", peer="p3", n=12,
           vote_id="v2"),
    ]
    _, findings2 = disclose(cap2, 3600)
    sig = {(f["signal"], f["vote_id"]) for f in findings2}
    assert ("late-roster-change", "v2") in sig, sig
    assert ("undisclosed-voter", "v2") in sig, sig
    assert not any(f["vote_id"] == "v1"
                   and f["signal"] == "undisclosed-voter"
                   for f in findings2)

    # member who left before the deadline votes → undisclosed voter,
    # no late change for the earlier leave
    cap3 = [ev(t0, "join", peer="p1"),
            ev("2026-11-16T10:05:00Z", "leave", peer="p1"),
            ev("2026-11-16T12:00:00Z", "vote", peer="p1", n=20,
               vote_id="v3")]
    _, findings3 = disclose(cap3, 3600)
    sig3 = {f["signal"] for f in findings3}
    assert "undisclosed-voter" in sig3, findings3
    assert "late-roster-change" not in sig3, findings3

    # vote in an empty room → INFO, not WARN
    _, findings4 = disclose(
        [ev("2026-11-16T12:00:00Z", "vote", room="ghost", peer="px",
            n=30, vote_id="v4")], 3600)
    assert any(f["signal"] == "empty-roster"
               and f["level"] == "INFO" for f in findings4)

    # end-to-end over a file: WARN capture rc 1 + --json agreement,
    # clean capture rc 0, unreadable rc 2, --room filter, parse errors
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                     delete=False) as fh:
        for e in cap2:
            row = {"ts": e["ts"].isoformat().replace("+00:00", "Z"),
                   "kind": e["kind"], "room": e["room"],
                   "peer": e["peer"]}
            if e["vote_id"]:
                row["vote_id"] = e["vote_id"]
            fh.write(_json.dumps(row) + "\n")
        fh.write("{oops\n")
        fh.write('{"ts":"2026-11-16T12:00:00Z","kind":"vote",'
                 '"room":"x"}\n')
        warn_path = fh.name
    opt = build_parser().parse_args([warn_path])
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc1 = run(opt)
    assert rc1 == 1, rc1
    assert "undisclosed-voter" in buf.getvalue()
    buf2 = io.StringIO()
    with contextlib.redirect_stdout(buf2):
        rcj = run(build_parser().parse_args([warn_path, "--json"]))
    payload = _json.loads(buf2.getvalue())
    assert rcj == 1 and len(payload["votes"]) == 3
    assert len(payload["parse_errors"]) == 2, payload["parse_errors"]
    clean = tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                        delete=False)
    clean.write(_json.dumps(
        {"ts": "2026-11-16T08:00:00Z", "kind": "join",
         "room": "deal-room", "peer": "p1"}) + "\n")
    clean.write(_json.dumps(
        {"ts": "2026-11-16T12:00:00Z", "kind": "vote",
         "room": "deal-room", "peer": "p1", "vote_id": "v9"}) + "\n")
    clean.close()
    buf3 = io.StringIO()
    with contextlib.redirect_stdout(buf3):
        rc0 = run(build_parser().parse_args([clean.name]))
    assert rc0 == 0, rc0
    assert run(build_parser().parse_args(
        ["/nonexistent-capture.jsonl"])) == 2
    buf4 = io.StringIO()
    with contextlib.redirect_stdout(buf4):
        rcf = run(build_parser().parse_args(
            [warn_path, "--room", "ghost"]))
    assert rcf == 1  # only the parse errors remain WARNs
    assert "deal-room" not in buf4.getvalue()
    for p in (warn_path, clean.name):
        os.unlink(p)
    print("peer-set-disclosure self-test OK (deadline-inclusive roster "
          "reconstruction, rejoin, clean vote, late join + undisclosed "
          "voter, early-leaver voter, empty roster, --room/--json, "
          "rc 0/1/2, parse errors)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (mutation probe runs after)
    else:
        raise SystemExit(run(build_parser().parse_args()))
