#!/usr/bin/env python3
"""retention-seal-audit — retention + tamper-evidence audit for the
sealed capture archive: span continuity, hash/byte verification, line
shortfalls, retention-day coverage, and seals that stopped landing.

DEMAND: evidence/suggestions/tools-services/
  - 2026-09-23.md (run family) — quote: "Specify the audit log retention
    and tamper-evidence guarantees needed for ..." — asked for an
    average latency figure, an outbound request with no timeout, a
    counter that resets on restart, a rollback that only reverts code,
    a feature flag that outlived its rollout, and more; the shared ask
    is what retention + tamper evidence backs a derived figure.
  - 2026-09-25.md "Compliance and forensic audit log design for systems
    with no deduplication, weak indexes, or schema-less state"
Scope: the offline answer for THIS archive — evidence/raw/sealed/
manifest.jsonl is the seal ledger (one JSON object per sealed span:
room, start_seq, end_seq, lines, sha256, bytes, ts, path). This tool
audits it end to end:
  sha256-mismatch   recomputed digest differs from the manifest (BLOCK).
  bytes-mismatch    sealed file size differs from the manifest (BLOCK).
  missing-file      manifest entry points at no file on disk (BLOCK).
  seq-gap           adjacent spans for a room leave seqs unsealed
                    (next start != prev end + 1) — retention hole.
  span-overlap      next span starts at/before prev end — double-sealed
                    or mis-labeled span.
  line-shortfall    lines != end_seq - start_seq + 1 — messages lost
                    INSIDE a sealed span (weak tamper evidence: the
                    seal covers fewer lines than the seq range claims).
  retention-hole    calendar day(s) between a room's first and last
                    seal with no seal at all.
  retention-stopped room's newest seal is > --stopped-days (default 3)
                    older than the newest seal across the archive.
  duplicate-span    two entries seal the same room seq range.
  malformed-entry   manifest line that is not a JSON object.
Files are read as bytes for hashing; nothing is executed, no network,
no subprocess, no extraction. rc 0 clean (INFO-only also rc 0), 1 on
WARN/BLOCK, 2 usage/IO.

VERIFY: --self-test runs 14 assertion groups over a synthetic sealed
archive (clean continuity silence, gap, overlap, duplicate, line
shortfall, hash/byte tamper, missing file, retention holes and stops,
malformed entry, --no-files, CLI rc/json/table, helpers). Live
grounding: evidence/raw/sealed/manifest.jsonl (2026-09-07..10-01, 95
spans) -> 95/95 sha256+bytes verified, 12 WARN: kibble 14-seq unsealed
gap, lobby 2 gaps + 5 span overlaps (up to 7572 seqs), meta 11
retention-day holes + stopped 09-27, faucet retention stopped 09-10,
technocore 1 day hole; 83 intra-span line shortfalls (INFO). rc 1 in
~8s incl. hashing.
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timedelta

DEF = dict(stopped_days=3.0, limit=20)


def load_manifest(path):
    """manifest -> (entries, malformed_idx). Malformed lines skipped."""
    entries, bad = [], []
    with open(path, errors="replace") as fh:
        for i, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                bad.append(i)
                continue
            if isinstance(rec, dict):
                entries.append((i, rec))
            else:
                bad.append(i)
    return entries, bad


def day_of(v):
    """entry ts -> date, else None."""
    if not isinstance(v, str) or len(v) < 10:
        return None
    try:
        return datetime.fromisoformat(v[:10]).date()
    except ValueError:
        return None


def check_file(entry, root):
    """(ok, kind) byte+hash verification for one manifest entry."""
    rel = entry.get("path")
    if not isinstance(rel, str) or not rel:
        return False, "missing-file"
    p = os.path.join(root, rel)
    if not os.path.isfile(p):
        return False, "missing-file"
    h = hashlib.sha256()
    n = 0
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            n += len(chunk)
    want_b = entry.get("bytes")
    if isinstance(want_b, int) and want_b != n:
        return False, "bytes-mismatch"
    want_h = entry.get("sha256")
    if isinstance(want_h, str) and want_h.lower() != h.hexdigest():
        return False, "sha256-mismatch"
    return True, None


def analyze(entries, root, opts=None, verify_files=True):
    """(line_idx, entry) list -> (findings, per-room table rows)."""
    o = dict(DEF)
    o.update(opts or {})
    findings = []

    def add(kind, sev, detail, **kw):
        f = {"kind": kind, "severity": sev, "detail": detail}
        f.update(kw)
        findings.append(f)

    rooms = {}
    for i, e in entries:
        room = e.get("room")
        if not isinstance(room, str):
            room = "?"
        rooms.setdefault(room, []).append((i, e))

    ref_day = None
    for _i, e in entries:
        d = day_of(e.get("ts"))
        if d and (ref_day is None or d > ref_day):
            ref_day = d

    rows = []
    for room in sorted(rooms):
        es = sorted(rooms[room], key=lambda ie: (
            _seq(ie[1].get("start_seq")) is None,
            _seq(ie[1].get("start_seq")) or 0))
        gaps = overlaps = dups = shortfalls = 0
        seen_ranges = set()
        for (i1, a), (i2, b) in zip(es, es[1:]):
            ae, bs = _seq(a.get("end_seq")), _seq(b.get("start_seq"))
            if ae is None or bs is None:
                continue
            if bs == ae + 1:
                pass
            elif bs > ae + 1:
                gaps += 1
                add("seq-gap", "WARN",
                    f"{room}: {bs - ae - 1} seqs unsealed between spans "
                    f"(end {ae} -> start {bs})",
                    room=room, line=i2 + 1)
            else:
                overlaps += 1
                add("span-overlap", "WARN",
                    f"{room}: next span starts {ae + 1 - bs} seqs before "
                    f"prev end (end {ae} -> start {bs})",
                    room=room, line=i2 + 1)
        for i, e in es:
            s, x = _seq(e.get("start_seq")), _seq(e.get("end_seq"))
            ln = e.get("lines")
            if s is not None and x is not None and isinstance(ln, int):
                if ln != x - s + 1:
                    shortfalls += 1
                    add("line-shortfall", "INFO",
                        f"{room}: span {s}..{x} sealed {ln} lines "
                        f"({x - s + 1 - ln} short of the seq range)",
                        room=room, line=i + 1)
            rng = (s, x)
            if rng in seen_ranges:
                dups += 1
                add("duplicate-span", "WARN",
                    f"{room}: seq range {s}..{x} sealed more than once",
                    room=room, line=i + 1)
            seen_ranges.add(rng)
            if verify_files:
                ok, kind = check_file(e, root)
                if not ok:
                    add(kind, "BLOCK",
                        f"{room}: sealed file fails {kind} "
                        f"({e.get('path')})",
                        room=room, line=i + 1)
        days = sorted({d for d in (day_of(e.get("ts"))
                                   for _i, e in es) if d})
        holes = 0
        if days:
            span = (days[-1] - days[0]).days + 1
            holes = span - len(days)
            if holes > 0:
                missing = _missing_days(days)
                add("retention-hole", "WARN",
                    f"{room}: {holes} calendar day(s) with no seal "
                    f"between {days[0]} and {days[-1]} "
                    f"(first missing {missing[0]})",
                    room=room)
            if ref_day is not None and days[-1] < ref_day - timedelta(
                    days=o["stopped_days"]):
                add("retention-stopped", "WARN",
                    f"{room}: newest seal {days[-1]} vs archive newest "
                    f"{ref_day} — retention stopped "
                    f"{(ref_day - days[-1]).days}d ago",
                    room=room)
        rows.append(dict(room=room, spans=len(es),
                         first_day=str(days[0]) if days else "-",
                         last_day=str(days[-1]) if days else "-",
                         days=len(days), holes=holes, gaps=gaps,
                         overlaps=overlaps, dups=dups,
                         shortfalls=shortfalls))
    findings.sort(key=lambda f: ({"BLOCK": 0, "WARN": 1, "INFO": 2}[
        f["severity"]], f["kind"], f.get("room", "")))
    return findings, rows


def _seq(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _missing_days(days):
    have = set(days)
    out = []
    d = days[0]
    while d <= days[-1]:
        if d not in have:
            out.append(d)
        d += timedelta(days=1)
    return out or [days[0]]


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
    print("room         spans first..last        days holes gaps ovl "
          "dup shortfall")
    for r in rows:
        print(f"{r['room']:12s} {r['spans']:5d} {r['first_day']}.."
              f"{r['last_day']} {r['days']:4d} {r['holes']:5d} "
              f"{r['gaps']:4d} {r['overlaps']:3d} {r['dups']:3d} "
              f"{r['shortfalls']:9d}")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Audit the sealed-capture manifest: span continuity, "
                    "sha256/bytes tamper evidence, line shortfalls, "
                    "retention-day coverage.")
    ap.add_argument("manifest", help="sealed manifest.jsonl")
    ap.add_argument("--root", default=None,
                    help="root that manifest paths are relative to "
                         "(default: manifest's grandparent)")
    ap.add_argument("--no-files", action="store_true",
                    help="skip sha256/bytes file verification")
    ap.add_argument("--stopped-days", dest="stopped_days", type=float,
                    default=DEF["stopped_days"],
                    help="room silent this many days vs archive newest "
                         "=> retention-stopped")
    ap.add_argument("--limit", type=int, default=DEF["limit"])
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        entries, bad = load_manifest(args.manifest)
    except OSError as e:
        print(f"error: cannot read {args.manifest}: {e}", file=sys.stderr)
        return 2
    root = args.root
    if root is None:
        m = os.path.abspath(args.manifest)
        root = m
        for _ in range(3):      # <root>/raw/sealed/manifest.jsonl
            root = os.path.dirname(root)
    findings, rows = analyze(entries, root, vars(args),
                             verify_files=not args.no_files)
    for i in bad:
        findings.insert(0, {"kind": "malformed-entry", "severity": "WARN",
                            "detail": f"manifest line {i + 1} is not a "
                            "JSON object", "line": i + 1})
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

    def build(entries, files=None):
        """Synthetic sealed archive: manifest + real member files."""
        d = tempfile.mkdtemp()
        sealed = os.path.join(d, "raw", "sealed")
        day = os.path.join(sealed, "2026", "09", "07")
        os.makedirs(day)
        files = files if files is not None else {}
        lines = []
        for n, e in enumerate(entries):
            name = f"{e.get('room', 'r')}-{e['start_seq']}-" \
                   f"{e['end_seq']}.bin"
            rel = f"raw/sealed/2026/09/07/{name}"
            blob = files.get(e.get("path", rel), b"x" * 100)
            with open(os.path.join(d, rel), "wb") as fh:
                fh.write(blob)
            rec = dict(room=e.get("room", "r"), start_seq=e["start_seq"],
                       end_seq=e["end_seq"], lines=e.get("lines",
                                                         e["end_seq"]
                                                         - e["start_seq"]
                                                         + 1),
                       sha256=hashlib.sha256(blob).hexdigest(),
                       bytes=len(blob), ts=e.get("ts", "2026-09-07T00:00:00Z"),
                       path=rel)
            for k in ("sha256", "bytes", "lines", "ts"):
                if k in e:
                    rec[k] = e[k]
            lines.append(json.dumps(rec))
        mp = os.path.join(sealed, "manifest.jsonl")
        with open(mp, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        return d, mp

    def run(mp, extra=(), root=None):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([mp, *extra] + (["--root", root] if root else []))
        return rc, buf.getvalue()

    def kinds(finds):
        return sorted({f["kind"] for f in finds})

    # 1) clean contiguous two-span archive: silent
    d, mp = build([dict(room="r", start_seq=1, end_seq=10),
                   dict(room="r", start_seq=11, end_seq=20,
                        ts="2026-09-08T00:00:00Z")])
    findings, rows = analyze(load_manifest(mp)[0], d)
    assert findings == [], findings
    assert rows[0]["spans"] == 2 and rows[0]["holes"] == 0
    rc, out = run(mp)
    assert rc == 0 and "findings: 0" in out, (rc, out)

    # 2) seq gap between spans
    d, mp = build([dict(room="r", start_seq=1, end_seq=10),
                   dict(room="r", start_seq=25, end_seq=30)])
    got = analyze(load_manifest(mp)[0], d)[0]
    f = next(x for x in got if x["kind"] == "seq-gap")
    assert "14 seqs unsealed" in f["detail"], f

    # 3) span overlap (next starts before prev end)
    d, mp = build([dict(room="r", start_seq=1, end_seq=10),
                   dict(room="r", start_seq=7, end_seq=15)])
    got = analyze(load_manifest(mp)[0], d)[0]
    f = next(x for x in got if x["kind"] == "span-overlap")
    assert "4 seqs before" in f["detail"], f

    # 4) duplicate span
    d, mp = build([dict(room="r", start_seq=1, end_seq=10),
                   dict(room="r", start_seq=1, end_seq=10)])
    assert "duplicate-span" in kinds(analyze(load_manifest(mp)[0],
                                             d)[0])

    # 5) line shortfall inside a span
    d, mp = build([dict(room="r", start_seq=1, end_seq=10, lines=8)])
    got = analyze(load_manifest(mp)[0], d)[0]
    f = next(x for x in got if x["kind"] == "line-shortfall")
    assert "2 short" in f["detail"] and f["severity"] == "INFO", f

    # 6) sha256 tamper (BLOCK) and bytes mismatch
    d, mp = build([dict(room="r", start_seq=1, end_seq=10,
                        sha256="0" * 64)])
    got = analyze(load_manifest(mp)[0], d)[0]
    f = next(x for x in got if x["kind"] == "sha256-mismatch")
    assert f["severity"] == "BLOCK", f
    d, mp = build([dict(room="r", start_seq=1, end_seq=10, bytes=99999)])
    assert "bytes-mismatch" in kinds(analyze(load_manifest(mp)[0],
                                             d)[0])

    # 7) missing member file
    d, mp = build([dict(room="r", start_seq=1, end_seq=10)])
    os.unlink(os.path.join(d, "raw", "sealed", "2026", "09", "07",
                           "r-1-10.bin"))
    got = analyze(load_manifest(mp)[0], d)[0]
    f = next(x for x in got if x["kind"] == "missing-file")
    assert f["severity"] == "BLOCK", f

    # 8) retention hole: sealed 09-07 and 09-10, none between
    d, mp = build([dict(room="r", start_seq=1, end_seq=10,
                        ts="2026-09-07T00:00:00Z"),
                   dict(room="r", start_seq=11, end_seq=20,
                        ts="2026-09-10T00:00:00Z")])
    got = analyze(load_manifest(mp)[0], d)[0]
    f = next(x for x in got if x["kind"] == "retention-hole")
    assert "2 calendar day(s)" in f["detail"], f

    # 9) retention stopped: room silent while archive moves on
    d, mp = build([dict(room="r", start_seq=1, end_seq=10,
                        ts="2026-09-07T00:00:00Z"),
                   dict(room="q", start_seq=1, end_seq=5,
                        ts="2026-09-12T00:00:00Z")])
    got = analyze(load_manifest(mp)[0], d)[0]
    f = next(x for x in got if x["kind"] == "retention-stopped"
             and x.get("room") == "r")
    assert "stopped 5d ago" in f["detail"], f

    # 10) malformed manifest entries surface as WARN with line number
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                     delete=False) as tf:
        tf.write('{"room": "r", "start_seq": 1, "end_seq": 2, '
                 '"lines": 2, "sha256": "' + "0" * 64 + '", '
                 '"bytes": 0, "path": "nowhere.bin"}\n')
        tf.write("not-json\n")
        mp2 = tf.name
    try:
        rc, out = run(mp2)
        assert rc == 1 and "malformed-entry" in out \
            and "line 2" in out, (rc, out)
    finally:
        os.unlink(mp2)

    # 11) --no-files skips hash verification (stale-manifest arithmetic)
    d, mp = build([dict(room="r", start_seq=1, end_seq=10,
                        sha256="0" * 64)])
    got = analyze(load_manifest(mp)[0], d, verify_files=False)[0]
    assert "sha256-mismatch" not in kinds(got), got

    # 12) CLI rc 1 on gap, rc 2 unreadable, --json shape
    d, mp = build([dict(room="r", start_seq=1, end_seq=10),
                   dict(room="r", start_seq=25, end_seq=30)])
    rc, out = run(mp)
    assert rc == 1 and "seq-gap" in out, (rc, out)
    assert main(["/nonexistent-manifest.jsonl"]) == 2
    rc, out = run(mp, ["--json"])
    doc = json.loads(out)
    assert doc["rooms"][0]["room"] == "r" \
        and any(f["kind"] == "seq-gap" for f in doc["findings"])

    # 13) table renders room row with all counters
    d, mp = build([dict(room="r", start_seq=1, end_seq=10),
                   dict(room="r", start_seq=25, end_seq=30, lines=2)])
    rc, out = run(mp)
    assert "r " in out and "shortfall" in out, out

    # 14) _seq/_missing_days/_day edge behavior
    assert _seq(True) is None and _seq(7) == 7
    assert _missing_days([datetime(2026, 9, 7).date(),
                          datetime(2026, 9, 10).date()]) == [
        datetime(2026, 9, 8).date(), datetime(2026, 9, 9).date()]
    assert day_of("short") is None and day_of("2026-09-07T00:00:00Z") \
        == datetime(2026, 9, 7).date()

    print("retention-seal-audit self-test OK (14 groups: clean "
          "continuity, seq gap, overlap, duplicate, line shortfall, "
          "sha256/bytes tamper, missing file, retention hole/stopped, "
          "malformed entry, --no-files, CLI rc/json, table, helpers)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after)
    else:
        raise SystemExit(main())
