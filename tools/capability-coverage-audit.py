#!/usr/bin/env python3
"""capability-coverage-audit — capability-to-audit-workflow coverage matrix.

DEMAND: evidence/suggestions/tools-services/ (file citations below)
  - "Unified view of cross-chain or multi-model agent sessions and capabilities"
  - "Support for additional audit capabilities beyond TOPLOC Activation Audit"
  - "Room audit service for non-TOPLOC capabilities (e.g., liquidity provision, governance, general security)"
  - "Room-audit service agents (like hermes-tools) should be available to audit TOPLOC activation workflows"
  - "View and manage TOPLOC Activation Audit tasks and bounties (e.g., filter by status, reward, agent)"
  - "Multi-capability audit workflows"
  Scope: one JSONL capture, one session event per line: {"ts","capability",
    "session","event","agent","board"}; event in workflow_registered|
    agent_available|task_posted|task_claimed|audited|service_requested. The
    matrix cross-checks every capability that is requested, tasked or
    audited against the workflows registered to cover it. Data only:
    JSON/regex parsing, nothing executed. rc 0/1/2. Stdlib only.
"""
import argparse
import json
import re
import sys

SEVS = ("BLOCK", "WARN", "INFO")
TASK_EVENTS = ("task_posted", "task_claimed")
BOARD_EVENTS = ("task_posted", "task_claimed", "service_requested")
BIND_EVENTS = ("workflow_registered", "agent_available")

def _f(kind, severity, origin, detail):
    """Uniform finding dict."""
    return {"kind": kind, "severity": severity, "origin": origin,
            "detail": detail}

def load_jsonl(path):
    """Read JSONL -> (records, bad_lines); unparsable/non-dict lines counted."""
    records, bad = [], 0
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if not isinstance(rec, dict):
                    raise ValueError("not a record")
                records.append(rec)
            except ValueError:
                bad += 1
    return records, bad

def _slug(name):
    """Normalized capability/board token: lowercase alphanumerics only."""
    return re.sub(r"[^a-z0-9]+", "", str(name).lower())

def _cap(rec):
    cap = rec.get("capability")
    return cap if isinstance(cap, str) and cap.strip() else None

def _sess(rec):
    s = rec.get("session")
    return s if isinstance(s, str) and s.strip() else "?"

def _known(records):
    """Pass-1 registry state from registration/availability events.

    -> {"reg_pairs": {(cap, session): [(agent, board), ...]},
        "reg_caps", "agent_caps", "bound_boards", "seen_caps"}.
    """
    reg_pairs, reg_caps = {}, set()
    agent_caps, bound_boards, seen_caps = set(), set(), set()
    for rec in records:
        cap = _cap(rec)
        if cap is None:
            continue
        seen_caps.add(cap)
        ev = rec.get("event")
        if ev == "workflow_registered":
            reg_caps.add(cap)
            reg_pairs.setdefault((cap, _sess(rec)), []).append(
                (rec.get("agent"), rec.get("board")))
        elif ev == "agent_available":
            agent_caps.add(cap)
        if ev in BIND_EVENTS:
            board = rec.get("board")
            if isinstance(board, str) and board:
                bound_boards.add(board)
    return {"reg_pairs": reg_pairs, "reg_caps": reg_caps,
            "agent_caps": agent_caps, "bound_boards": bound_boards,
            "seen_caps": seen_caps}

def registry_findings(records):
    """Registry integrity: audit-without-workflow (BLOCK), tasks on unknown
    capabilities and conflicting re-registrations (WARN), dormant
    workflows (INFO)."""
    known = _known(records)
    audited, task_unknown, audited_caps = {}, {}, set()
    for rec in records:
        cap, ev = _cap(rec), rec.get("event")
        if cap is None:
            continue
        if ev == "audited":
            audited[(cap, _sess(rec))] = audited.get((cap, _sess(rec)), 0) + 1
            audited_caps.add(cap)
        elif ev in TASK_EVENTS and cap not in known["reg_caps"]:
            task_unknown[cap] = task_unknown.get(cap, 0) + 1
    finds = []
    for (cap, sess), n in sorted(audited.items()):
        if (cap, sess) not in known["reg_pairs"]:
            finds.append(_f("audit-without-workflow", "BLOCK",
                            f"{cap}/{sess}",
                            f"{n} audited event(s) for a session with no "
                            f"workflow_registered"))
    for cap, n in sorted(task_unknown.items()):
        finds.append(_f("task-unknown-capability", "WARN", cap,
                        f"{n} task event(s) on a capability never "
                        f"registered"))
    for (cap, sess), fields in sorted(known["reg_pairs"].items()):
        distinct = sorted(set(fields), key=repr)
        if len(fields) > 1 and len(distinct) > 1:
            finds.append(_f("registration-conflict", "WARN",
                            f"{cap}/{sess}",
                            "re-registered with conflicting fields: "
                            + " vs ".join(repr(d) for d in distinct[:2])))
    for cap in sorted(known["reg_caps"] - audited_caps):
        finds.append(_f("dormant-workflow", "INFO", cap,
                        "workflow registered but zero audited events in "
                        "capture"))
    return finds

def agent_gap_findings(records):
    """workflow_registered with no agent_available ever (WARN agent-gap)."""
    known = _known(records)
    return [_f("agent-gap", "WARN", cap,
               "workflow registered but no agent_available serves it")
            for cap in sorted(known["reg_caps"] - known["agent_caps"])]

def board_findings(records):
    """Board values pointing at capabilities never seen (WARN)."""
    known = _known(records)
    seen_slug = {_slug(c) for c in known["seen_caps"]}
    flagged = {}
    for rec in records:
        board = rec.get("board")
        if rec.get("event") not in BOARD_EVENTS:
            continue
        if not (isinstance(board, str) and board):
            continue
        if board not in known["bound_boards"] and _slug(board) not in seen_slug:
            flagged.setdefault(board, _cap(rec) or "?")
    return [_f("board-unknown-capability", "WARN", board,
               f"board references a capability never seen (used for "
               f"{cap})")
            for board, cap in sorted(flagged.items())]

def request_findings(records):
    """service_requested for a capability with no workflow_registered."""
    known = _known(records)
    counts = {}
    for rec in records:
        cap = _cap(rec)
        if (rec.get("event") == "service_requested" and cap is not None
                and cap not in known["reg_caps"]):
            counts[cap] = counts.get(cap, 0) + 1
    return [_f("coverage-hole", "BLOCK", cap,
               f"{n} service_requested for a capability with no "
               f"workflow_registered (unauditable)")
            for cap, n in sorted(counts.items())]

def capability_rows(records):
    """Per-capability counts for the coverage matrix render."""
    rows = {}
    for rec in records:
        cap = _cap(rec)
        if cap is None:
            continue
        r = rows.setdefault(cap, {"capability": cap, "sessions": set(),
                                  "registered": 0, "agents": set(),
                                  "posted": 0, "claimed": 0, "audited": 0,
                                  "requested": 0})
        r["sessions"].add(_sess(rec))
        ev = rec.get("event")
        if ev == "workflow_registered":
            r["registered"] += 1
        elif ev == "agent_available" and rec.get("agent"):
            r["agents"].add(str(rec.get("agent")))
        elif ev == "task_posted":
            r["posted"] += 1
        elif ev == "task_claimed":
            r["claimed"] += 1
        elif ev == "audited":
            r["audited"] += 1
        elif ev == "service_requested":
            r["requested"] += 1
    return [{"capability": cap, "sessions": len(rows[cap]["sessions"]),
             "registered": rows[cap]["registered"],
             "agents": len(rows[cap]["agents"]),
             "posted": rows[cap]["posted"], "claimed": rows[cap]["claimed"],
             "audited": rows[cap]["audited"],
             "requested": rows[cap]["requested"]} for cap in sorted(rows)]

def audit(path):
    """Run every detector over the capture -> (findings, rows, stats)."""
    records, bad = load_jsonl(path)
    finds = (request_findings(records) + registry_findings(records)
             + agent_gap_findings(records) + board_findings(records))
    if bad:
        finds.append(_f("malformed-line", "INFO", path,
                        f"{bad} unparsable line(s) skipped"))
    rank = {"BLOCK": 0, "WARN": 1, "INFO": 2}
    finds.sort(key=lambda f: (rank[f["severity"]], f["kind"], f["origin"]))
    rows = capability_rows(records)
    return finds, rows, {"records": len(records), "bad_lines": bad,
                         "capabilities": len(rows)}

def render(findings, rows=None):
    """Print finding lines then the per-capability matrix; return counts."""
    counts = {s: 0 for s in SEVS}
    for f in findings:
        counts[f["severity"]] += 1
        print(f"{f['severity']} {f['kind']} {f['origin']}: {f['detail']}")
    print("no findings" if not findings else
          f"{len(findings)} finding(s): "
          + ", ".join(f"{s} {counts[s]}" for s in SEVS))
    if rows:
        print("capability                       reg agents posted claimed"
              " audited requested")
        for r in rows:
            print(f"{r['capability'][:31]:31} {r['registered']:4}"
                  f" {r['agents']:6} {r['posted']:6} {r['claimed']:7}"
                  f" {r['audited']:7} {r['requested']:9}")
    return counts

def main(argv=None):
    """CLI: path positional, --json optional; rc 0/1/2."""
    ap = argparse.ArgumentParser(
        description="capability-to-audit-workflow coverage matrix")
    ap.add_argument("path", help="JSONL capture of capability session events")
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args(argv)
    try:
        finds, rows, stats = audit(args.path)
    except OSError as exc:
        print(f"cannot read {args.path}: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"tool": "capability-coverage-audit", **stats,
                          "findings": finds, "matrix": rows}, indent=1))
    else:
        render(finds, rows)
    return 1 if finds else 0

def self_test():
    import io
    import os
    import tempfile
    from contextlib import redirect_stdout

    toploc, board = "TOPLOC Activation Audit", "toploc-activation-audit"

    def _ev(ts, cap=toploc, sess="s1", event="audited", **kw):
        rec = {"ts": ts, "capability": cap, "session": sess, "event": event}
        rec.update(kw)
        return rec

    def run(caps, extra=()):
        """caps: list of captures (records or raw strings) -> (rc, output)."""
        paths = []
        try:
            for cap in caps:
                with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                                 delete=False) as tf:
                    tf.write("\n".join(r if isinstance(r, str)
                                       else json.dumps(r)
                                       for r in cap) + "\n")
                    paths.append(tf.name)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main([*paths, *extra])
            return rc, buf.getvalue()
        finally:
            for p in paths:
                os.unlink(p)

    def kinds(finds):
        return [f["kind"] for f in finds]

    # 1. clean capture: two capabilities, each registered, served, tasked
    #    and audited -> silent, rc 0
    clean = [_ev(0, event="workflow_registered", agent="hermes-tools",
                 board=board),
             _ev(1, event="agent_available", agent="hermes-tools"),
             _ev(2, event="task_posted", board=board),
             _ev(3, event="task_claimed", board=board),
             _ev(4, event="audited"),
             _ev(5, "liquidity provision", "s2", "workflow_registered",
                 agent="vault-watch", board="liquidity-provision"),
             _ev(6, "liquidity provision", "s2", "agent_available",
                 agent="vault-watch"),
             _ev(7, "liquidity provision", "s2", "audited")]
    rc, out = run([clean])
    assert rc == 0 and "no findings" in out, (rc, out)
    for fn in (registry_findings, agent_gap_findings, board_findings,
               request_findings):
        assert fn(clean) == [], fn.__name__
    # 2. coverage hole: service_requested with no workflow_registered
    hole = [_ev(9, "governance", "s5", "service_requested", board="governance")]
    f = request_findings(hole)
    assert kinds(f) == ["coverage-hole"] and f[0]["severity"] == "BLOCK", f
    # 3. agent gap + dormant workflow: registered but never served/audited
    gap = [_ev(0, "general security", "s3", "workflow_registered",
               board="general-security")]
    f = agent_gap_findings(gap)
    assert kinds(f) == ["agent-gap"] and f[0]["severity"] == "WARN", f
    f = registry_findings(gap)
    assert kinds(f) == ["dormant-workflow"], f
    assert f[0]["severity"] == "INFO" and f[0]["origin"] == "general security"
    # 4. audit without workflow: audited session never registered
    ghost = [_ev(4, "governance", "s9", "audited")]
    f = registry_findings(ghost)
    assert kinds(f) == ["audit-without-workflow"], f
    assert f[0]["severity"] == "BLOCK" and "governance/s9" in f[0]["origin"]
    # 5. tasks on unknown capability WARN (board slug still known)
    tk = [_ev(2, "bounty-triage", "s4", "task_posted", board="bounty-triage"),
          _ev(3, "bounty-triage", "s4", "task_claimed")]
    f = registry_findings(tk)
    assert kinds(f) == ["task-unknown-capability"], f
    assert board_findings(tk) == []
    # 6. conflicting re-registration for one capability+session
    conf = [_ev(0, event="workflow_registered", agent="hermes-tools"),
            _ev(1, event="workflow_registered", agent="hermes-two"),
            _ev(2, event="agent_available", agent="hermes-tools"),
            _ev(3, event="audited")]
    f = registry_findings(conf)
    assert kinds(f) == ["registration-conflict"] and "vs" in f[0]["detail"], f
    # 7. board referencing a capability never seen
    bd = clean[:1] + [_ev(2, event="task_posted", board="ghost-board")]
    f = board_findings(bd)
    assert kinds(f) == ["board-unknown-capability"], f
    assert f[0]["origin"] == "ghost-board"
    # 8. matrix rows and render table
    rows = capability_rows(clean)
    assert [r["capability"] for r in rows] == ["TOPLOC Activation Audit",
                                               "liquidity provision"], rows
    assert rows[0]["audited"] == 1 and rows[0]["posted"] == 1, rows[0]
    assert rows[1]["agents"] == 1 and rows[1]["registered"] == 1, rows[1]
    _, out = run([clean])
    assert "capability" in out and "TOPLOC Activation Audit" in out, out
    # 9. CLI: findings rc 1; --json shape; malformed INFO; unreadable rc 2
    rc, out = run([hole])
    assert rc == 1 and "BLOCK coverage-hole" in out, (rc, out)
    doc = json.loads(run([clean], ["--json"])[1])
    assert doc["findings"] == [] and doc["records"] == 8, doc
    assert len(doc["matrix"]) == 2, doc
    rc, out = run([['{"broken', _ev(0, event="audited")]])
    assert rc == 1 and "malformed-line" in out, (rc, out)
    assert main(["/nonexistent-capture.jsonl"]) == 2
    print("capability-coverage-audit self-test OK (9 groups: clean, hole, "
          "agent-gap/dormant, audit-without-workflow, unknown-capability "
          "tasks, registration conflict, unknown board, matrix rows, CLI "
          "rc/json)")

if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
