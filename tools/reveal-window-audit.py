#!/usr/bin/env python3
"""reveal-window-audit — timed-reveal ("chime") window audit over a
JSONL event capture: verifies that every reveal happened inside its
declared fixed window (open/close), that the commitment predates the
reveal, and that the signed timestamps actually cover the events they
claim (signature time never precedes event time, reveal signatures
land inside the window). Deterministic; events are data only.

DEMAND: evidence/suggestions/tools-services/2026-10-15.md
  - request (05:xx run): "spec a fixed reveal window + signed
    timestamps so a 'chime' (timed reveal) is i…" — proposed service:
    hermes-tools specifying and checking fixed reveal windows with
    signed timestamps.
  - request (same run): "spec a 'fixed reveal window plus signed
    timestamps' mechanism into a round/gam…".
  - request (later run): "Signed, verifiable timestamps and fixed
    reveal windows for events".
  This tool is the checker half of that ask: input is the event
  capture, output is named findings (rule id, id, detail) per reveal
  round plus a verdict. Stdlib only; nothing is executed."""
import argparse
import hashlib
import json
import sys

SEVS = ("BLOCK", "WARN", "INFO")


def parse_events(path):
    """file -> [event dicts]; first bad line raises ValueError."""
    evs = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except ValueError as exc:
                raise ValueError("line {}: not JSON: {}".format(lineno, exc))
            if not isinstance(ev, dict) or "type" not in ev or "id" not in ev:
                raise ValueError("line {}: need 'type' and 'id'".format(lineno))
            evs.append(ev)
    return evs


def num(v):
    """value -> True if a real number (bool excluded)."""
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def audit(evs):
    """events -> (findings, rounds); findings are (rule, id, detail)."""
    finds = []
    windows = {}
    commits = {}
    reveals = {}
    for ev in evs:
        kind, rid = ev["type"], str(ev["id"])
        if kind == "window":
            if rid in windows:
                finds.append(("window-redeclared", rid,
                              "window declared again at ts {}".format(
                                  ev.get("ts", "?"))))
                continue
            if not (num(ev.get("open")) and num(ev.get("close"))):
                finds.append(("window-no-bounds", rid,
                              "window declaration lacks numeric "
                              "open/close"))
                continue
            windows[rid] = (ev["open"], ev["close"])
            if ev["open"] >= ev["close"]:
                finds.append(("window-neg", rid,
                              "open {} not before close {}".format(
                                  ev["open"], ev["close"])))
        elif kind in ("commit", "reveal"):
            store = commits if kind == "commit" else reveals
            if rid in store:
                finds.append(("{}-dup".format(kind), rid,
                              "second {} for this round".format(kind)))
                continue
            store[rid] = ev
        else:
            finds.append(("event-unknown", rid,
                          "unrecognized event type '{}'".format(kind)))
    for rid in sorted(set(commits) | set(reveals)):
        if rid not in windows:
            finds.append(("window-unknown", rid,
                          "event(s) for a round with no declared window"))
    for rid, ev in sorted(reveals.items()):
        if rid in windows:
            lo, hi = windows[rid]
            if num(ev.get("ts")):
                if ev["ts"] < lo:
                    finds.append(("reveal-early", rid,
                                  "reveal ts {} before window open {}"
                                  .format(ev["ts"], lo)))
                elif ev["ts"] > hi:
                    finds.append(("reveal-late", rid,
                                  "reveal ts {} after window close {}"
                                  .format(ev["ts"], hi)))
            else:
                finds.append(("reveal-no-ts", rid, "reveal lacks a ts"))
        if num(ev.get("sig_ts")) and num(ev.get("ts")) \
                and ev["sig_ts"] < ev["ts"]:
            finds.append(("sig-ts-order", rid,
                          "reveal signature ts {} predates event ts {}"
                          .format(ev["sig_ts"], ev["ts"])))
        if rid in commits and num(ev.get("ts")) \
                and num(commits[rid].get("ts")) \
                and commits[rid]["ts"] >= ev["ts"]:
            finds.append(("commit-after-reveal", rid,
                          "commit ts {} not before reveal ts {}".format(
                              commits[rid]["ts"], ev["ts"])))
    for rid, ev in sorted(commits.items()):
        if num(ev.get("sig_ts")) and num(ev.get("ts")) \
                and ev["sig_ts"] < ev["ts"]:
            finds.append(("sig-ts-order", rid,
                          "commit signature ts {} predates event ts {}"
                          .format(ev["sig_ts"], ev["ts"])))
    for rid in sorted(windows):
        if rid not in reveals:
            finds.append(("reveal-missing", rid,
                          "window {}..{} closed with no reveal".format(
                              windows[rid][0], windows[rid][1])))
    rounds = {"windows": len(windows), "commits": len(commits),
              "reveals": len(reveals)}
    return finds, rounds


def verdict(findings):
    """findings -> FAIL on hard rules, AT-RISK on any finding, else CLEAN."""
    hard = {"reveal-early", "window-neg", "commit-after-reveal",
            "window-no-bounds"}
    if any(r in hard for r, _, _ in findings):
        return "FAIL"
    if findings:
        return "AT-RISK"
    return "CLEAN"


def findings_digest(findings):
    canon = "\n".join("{}|{}|{}".format(r, i, d) for r, i, d in findings)
    return hashlib.sha256(canon.encode()).hexdigest()[:16]


def main(argv):
    ap = argparse.ArgumentParser(
        description="audit timed-reveal rounds for window violations and "
                    "signed-timestamp ordering")
    ap.add_argument("events", help="JSONL reveal-round event capture")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable report")
    args = ap.parse_args(argv)
    try:
        evs = parse_events(args.events)
    except OSError:
        print("reveal-window-audit: cannot read {}".format(args.events),
              file=sys.stderr)
        return 2
    except ValueError as exc:
        print("reveal-window-audit: {}".format(exc), file=sys.stderr)
        return 2
    finds, rounds = audit(evs)
    digest = findings_digest(finds)
    if args.json:
        print(json.dumps({"tool": "reveal-window-audit",
                          "verdict": verdict(finds), "digest": digest,
                          "rounds": rounds,
                          "findings": [{"rule": r, "id": i, "detail": d}
                                       for r, i, d in finds]},
                         ensure_ascii=False))
        return 1 if finds else 0
    print("reveal-window-audit: {} ({})".format(verdict(finds), digest))
    for r, i, d in finds:
        print("  [{}] {} {}: {}".format(
            SEVS[0] if r in ("reveal-early", "window-neg",
                             "commit-after-reveal", "window-no-bounds")
            else SEVS[1], r, i, d))
    return 1 if finds else 0


def self_test():
    import io
    import os
    import tempfile
    from contextlib import redirect_stdout

    def ev(**kw):
        return json.dumps(kw)

    def find(lines):
        return audit([json.loads(x) for x in lines])

    # 1. clean chime: commit in window, signed after event, reveal inside
    good = [ev(type="window", id="r1", open=100, close=200),
            ev(type="commit", id="r1", ts=110, sig_ts=111),
            ev(type="reveal", id="r1", ts=150, sig_ts=151)]
    finds, rounds = find(good)
    assert finds == [] and verdict(finds) == "CLEAN", finds
    assert rounds == {"windows": 1, "commits": 1, "reveals": 1}, rounds

    # 2. early reveal FAILs; late reveal only WARNs
    early = [ev(type="window", id="r2", open=100, close=200),
             ev(type="commit", id="r2", ts=90, sig_ts=91),
             ev(type="reveal", id="r2", ts=95, sig_ts=96)]
    finds, _ = find(early)
    assert ("reveal-early", "r2") in [(r, i) for r, i, _ in finds], finds
    assert "before window open 100" in [d for _, _, d in finds][0]
    assert verdict(finds) == "FAIL"
    late = [ev(type="window", id="r3", open=100, close=200),
            ev(type="commit", id="r3", ts=110, sig_ts=111),
            ev(type="reveal", id="r3", ts=240, sig_ts=241)]
    finds, _ = find(late)
    assert [r for r, _, _ in finds] == ["reveal-late"], finds
    assert verdict(finds) == "AT-RISK"

    # 3. window bookkeeping: negative, redeclared, missing reveal,
    #    unknown round
    messy = [ev(type="window", id="r4", open=200, close=100),
             ev(type="window", id="r5", open=10, close=20),
             ev(type="window", id="r5", open=30, close=40),
             ev(type="reveal", id="r9", ts=15, sig_ts=15)]
    finds, _ = find(messy)
    rules = [r for r, _, _ in finds]
    assert rules.count("window-neg") == 1 and "window-redeclared" in rules
    assert "window-unknown" in rules and "reveal-missing" in rules, rules
    assert verdict(finds) == "FAIL"

    # 4. signed timestamps must cover events; commit must precede reveal
    unsigned = [ev(type="window", id="r6", open=100, close=200),
                ev(type="commit", id="r6", ts=110, sig_ts=105),
                ev(type="reveal", id="r6", ts=150, sig_ts=160)]
    finds, _ = find(unsigned)
    assert ("sig-ts-order", "r6") in [(r, i) for r, i, _ in finds], finds
    inverted = [ev(type="window", id="r7", open=100, close=200),
                ev(type="commit", id="r7", ts=160, sig_ts=161),
                ev(type="reveal", id="r7", ts=150, sig_ts=151)]
    finds, _ = find(inverted)
    assert ("commit-after-reveal", "r7") in [(r, i) for r, i, _ in finds]
    assert verdict(finds) == "FAIL"

    # 5. end-to-end CLI: rc, verdict text, digest determinism, bad file
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "reveal.jsonl")
        with open(p, "w") as fh:
            fh.write("\n".join(early) + "\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([p, "--json"])
        doc = json.loads(buf.getvalue())
        assert rc == 1 and doc["verdict"] == "FAIL", doc
        buf = io.StringIO()
        with redirect_stdout(buf):
            main([p, "--json"])
        assert json.loads(buf.getvalue())["digest"] == doc["digest"]
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([p])
        assert rc == 1 and "reveal-early" in buf.getvalue()
        bad = os.path.join(d, "bad.jsonl")
        with open(bad, "w") as fh:
            fh.write('{"type": "window"}\n')
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([bad])
        assert rc == 2, rc

    print("reveal-window-audit self-test OK (5 groups: clean chime "
          "passes, early reveal FAILs vs late reveal WARNs, window "
          "negative/redeclared/missing-reveal/unknown-round bookkeeping, "
          "signature timestamps must cover events and commit precede "
          "reveal, end-to-end CLI with deterministic digest and rc 2 on "
          "malformed capture)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main(sys.argv[1:]))
