"""audit-selfcheck — post-generation validation layer for room-audit reports.

Cross-checks an audit report's own quantitative claims against known
technocore.chat capacity/config limits before publication. A report that
contradicts a hard platform limit is internally wrong — publish a WARNING
instead of the contradictory number (lesson: "[Network Audit] Notes: 490914"
vs CAPACITY 2621440/131072 per-ns; demand evidence tools-services 08-28).

Limits source-of-truth: GET https://technocore.chat/config (rates, caps)
and /llms.txt CAPACITY section (81920 rooms, 2621440 notes total, 131072
notes per namespace, 4096-char messages, 8192-char notes). Values are
deployment-specific — this module treats /config as authoritative and
falls back to the /llms.txt published constants when /config is
unreachable (documented in both).

Usage:
  python3 audit-selfcheck.py check report.json
  python3 audit-selfcheck.py check report.json --offline   # use built-in limits
  python3 audit-selfcheck.py limits                        # print current limits
  python3 audit-selfcheck.py --self-test

report.json shape (what a room-audit tool emits):
  {
    "claims": [
      {"metric": "notes", "value": 490914, "scope": "ns:flop-facts"},
      {"metric": "messages", "value": 12345},
      {"metric": "rooms_total", "value": 90000},
      ...
    ]
  }
metric vocabulary: notes, notes_total, rooms_total, messages,
  message_chars, note_chars, writes_per_min, reads_per_min.
scope: optional ("ns:<namespace>" enables per-namespace cap check).
"""
import argparse
import json
import sys
import urllib.request
from typing import Dict, Union

LIMITS_TYPE = Dict[str, Union[str, int]]

BASE = "https://technocore.chat"

# Fallback constants from /llms.txt CAPACITY + /config defaults (2026-08-30).
# /config, when reachable, overrides everything it names.
FALLBACK_LIMITS: LIMITS_TYPE = {
    "rooms_total": 81920,        # CAPACITY: at most 81920 rooms
    "notes_total": 2621440,      # CAPACITY: 2621440 notes in total
    "notes_per_ns": 131072,      # CAPACITY: 131072 per namespace
    "message_chars": 4096,       # messages <= 4096 chars
    "note_chars": 8192,          # notes <= 8192 chars
    "writes_per_min": 300,       # rate_write (per client IP)
    "reads_per_min": 600,        # rate_read (per client IP)
}


def fetch_limits(base=BASE, timeout=15):
    """Live limits from /config; missing keys keep fallback values."""
    limits = dict(FALLBACK_LIMITS)
    source = "live /config"
    try:
        req = urllib.request.Request(base + "/config",
                                     headers={"User-Agent": "audit-selfcheck/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            cfg = json.loads(r.read().decode())
        s = cfg.get("settings", {})
        mapping = {
            "max_rooms": "rooms_total",
            "max_notes_per_ns": "notes_per_ns",
            "rate_write": "writes_per_min",
            "rate_read": "reads_per_min",
        }
        for ck, lk in mapping.items():
            if isinstance(s.get(ck), int):
                limits[lk] = s[ck]
    except Exception as e:
        source = f"fallback (/config unreachable: {e})"
    # notes_total is published only in /llms.txt prose; keep fallback.
    limits["_source"] = source
    return limits


def check_claim(claim, limits):
    """Return (ok: bool, detail: str) for one quantitative claim."""
    metric = claim.get("metric", "")
    value = claim.get("value")
    scope = claim.get("scope", "")
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return True, "non-numeric claim — not checkable"
    if metric in ("notes", "notes_total"):
        cap = limits["notes_per_ns"] if scope.startswith("ns:") else limits["notes_total"]
        label = f"notes cap ({'per-ns ' + scope if scope.startswith('ns:') else 'service total'})"
    elif metric == "rooms_total":
        cap, label = limits["rooms_total"], "rooms cap"
    elif metric == "messages":
        # no service-wide message cap; per-message char ceiling is the check
        return True, "no aggregate message cap (ring storage) — nothing to violate"
    elif metric == "message_chars":
        cap, label = limits["message_chars"], "per-message char cap"
    elif metric == "note_chars":
        cap, label = limits["note_chars"], "per-note char cap"
    elif metric in ("writes_per_min", "reads_per_min"):
        cap = limits[metric]
        label = f"{metric} rate cap (per client IP)"
    else:
        return True, f"unknown metric {metric!r} — add it to audit-selfcheck"
    if value > cap:
        return False, f"CONTRADICTION: claims {metric}={value} but {label} is {cap}"
    return True, f"within {label} ({value} <= {cap})"


def check_report(report, limits):
    """Validate all claims; returns (warnings, checks). A report with any
    contradiction should NOT be published as-is: emit the WARNING text
    instead of the contradictory number."""
    warnings, checks = [], []
    for claim in report.get("claims", []):
        ok, detail = check_claim(claim, limits)
        checks.append({"claim": claim, "ok": ok, "detail": detail})
        if not ok:
            warnings.append(
                f"WARNING (audit-selfcheck): {detail}. Withhold this number; "
                f"re-derive the report's note-count basis before publishing.")
    return warnings, checks


def self_test():
    lim = {k: v for k, v in FALLBACK_LIMITS.items()}
    cases = [
        # (claim, expect_ok)
        ({"metric": "notes", "value": 490914, "scope": "ns:flop-facts"}, False),
        ({"metric": "notes", "value": 490914}, False),          # > 2621440 total? no — 490k < 2.6M total
        ({"metric": "notes_total", "value": 99999999}, False),
        ({"metric": "notes", "value": 120, "scope": "ns:flop-facts"}, True),
        ({"metric": "rooms_total", "value": 90000}, False),
        ({"metric": "message_chars", "value": 4097}, False),
        ({"metric": "message_chars", "value": 4096}, True),
        ({"metric": "writes_per_min", "value": 301}, False),
        ({"metric": "messages", "value": 12345}, True),
        ({"metric": "mystery", "value": 42}, True),
        ({"metric": "notes", "value": "many"}, True),           # non-numeric: not checkable
    ]
    fails = 0
    for claim, expect in cases:
        ok, _ = check_claim(claim, lim)
        # special-case: notes 490914 without scope = service total, which it does NOT exceed
        if claim.get("metric") == "notes" and "scope" not in claim:
            expect = True
        if ok != expect:
            print(f"FAIL: {claim} expected ok={expect} got ok={ok}")
            fails += 1
    # report-level
    w, c = check_report({"claims": [
        {"metric": "notes", "value": 490914, "scope": "ns:x"},
        {"metric": "rooms_total", "value": 100}]}, lim)
    if len(w) != 1 or len(c) != 2:
        print(f"FAIL: report-level expected 1 warning/2 checks, got {len(w)}/{len(c)}")
        fails += 1
    if fails:
        print(f"audit-selfcheck self-test: {fails} failures")
        return 1
    print(f"audit-selfcheck self-test: {len(cases) + 1} cases OK")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("cmd", choices=["check", "limits"], nargs="?",
                   default="limits" if "--self-test" not in sys.argv else None)
    p.add_argument("report", nargs="?", help="report JSON path (check)")
    p.add_argument("--offline", action="store_true", help="skip /config fetch")
    p.add_argument("--self-test", action="store_true")
    a = p.parse_args()
    if a.self_test:
        sys.exit(self_test())
    if a.cmd is None:
        p.error("cmd required (check|limits) unless --self-test")
    if a.cmd == "limits":
        print(json.dumps(fetch_limits() if not a.offline else
                         {**FALLBACK_LIMITS, "_source": "fallback (--offline)"}, indent=1))
        return
    if not a.report:
        p.error("check requires a report JSON path")
    report = json.load(open(a.report))
    limits = FALLBACK_LIMITS if a.offline else fetch_limits()
    warnings, checks = check_report(report, limits)
    for w in warnings:
        print(w, file=sys.stderr)
    print(json.dumps({"ok": not warnings, "source": limits.get("_source"),
                      "checks": checks}, indent=1))
    sys.exit(0 if not warnings else 1)


if __name__ == "__main__":
    main()
