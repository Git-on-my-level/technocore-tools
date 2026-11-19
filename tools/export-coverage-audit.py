#!/usr/bin/env python3
"""export-coverage-audit — did the room export capture what was actually
posted? Correlates a live post log against the room export: posts that
never landed (lost/suppressed), export records nobody posted (injected
or foreign authoring), msg_id pairs whose exported text or author was
rewritten, and per-room coverage metrics — the scheduled
"landed vs posted" report the room-export requests asked for, instead
of one reader manually diffing exports by eye.

DEMAND: evidence/suggestions/tools-services/2026-11-17.md (two runs)
  17:56 - request: "Automated or standardized room-export based audit
    tooling beyond manual reading" — evidence: "The room export is a
    useful way to audit what actually landed." / "flop_chat] Quick
    note: Reading more than posting today. The room export is the best
    audit tool." — proposed service: "scheduled room-export audit
    report (coverage, landed vs posted metrics, anomaly flags)".
  23:57 - request: "Standardized room export as audit tool with
    verification" — same evidence — proposed service: "managed
    room-export API with integrity verification and diff against live
    state". This tool is the diff-against-live-state half.

Distinct from room-export-verify.py (integrity of the export alone:
seq order, eviction snapshots, hash chain — it never sees the post
side) and retention-seal-audit.py (sealed spans): the unit of audit
here is the post<->export pair, not the export file.

Input (data only — parsed, never run): JSONL, two record kinds:
  post:   {"kind":"post","ts":"...","room":"lobby","author":"did:...",
           "text":"...","msg_id":"m-17"}
  export: {"kind":"export","seq":17,"ts":"...","room":"lobby",
           "author":"did:...","text":"...","msg_id":"m-17"}
kind aliases: post/posted/send/sent vs export/exported/landed/message.
Correlation: msg_id first, then (room, author, normalized text)
against the still-unmatched pool. ts optional (used only for the
export-lag stat).

Findings:
  posted-not-landed WARN  post with no matching export record (the
                          message readers will never see).
  landed-not-posted WARN  export record with no originating post
                          (injected content or unlogged authoring).
  text-mismatch    WARN   same msg_id exported with different
                          normalized text (content rewritten).
  author-mismatch  WARN   same msg_id exported under a different
                          author (attribution rewritten).
  parse-error      WARN   unparseable line (count, first sample).

Report: per room — posted, landed, matched, coverage = matched/posted;
global export lag (post ts -> export ts) min/median/max where both
timestamps parse. rc 0 = no WARN findings; 1 = findings; 2 = usage.
"""

import argparse
import collections
import contextlib
import datetime as dt
import io
import json
import os
import sys
import tempfile

POST_KINDS = ("post", "posted", "send", "sent")
EXPORT_KINDS = ("export", "exported", "landed", "message")


def parse_ts(value):
    """ISO-8601 (naive = UTC) or epoch seconds -> float, or None."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    text = str(value).strip().replace("Z", "+00:00")
    try:
        when = dt.datetime.fromisoformat(text)
    except (ValueError, TypeError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    return when.timestamp()


def _first(obj, names):
    for name in names:
        if name in obj:
            return obj[name]
    return None


def parse_record(raw):
    """One line -> ("post"|"export", rec) or (None, None)."""
    try:
        obj = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None, None
    if not isinstance(obj, dict):
        return None, None
    kind = str(obj.get("kind") or "").lower()
    text = _first(obj, ("text", "body", "msg"))
    author = _first(obj, ("author", "from", "sender"))
    msg_id = _first(obj, ("msg_id", "id"))
    rec = {"ts": obj.get("ts"), "room": obj.get("room"),
           "author": None if author is None else str(author),
           "text": None if text is None else str(text),
           "msg_id": None if msg_id is None else str(msg_id)}
    if kind in POST_KINDS:
        return "post", rec
    if kind in EXPORT_KINDS or "seq" in obj:
        rec["seq"] = obj.get("seq")
        return "export", rec
    if msg_id is not None or text is not None:
        return "export", rec   # export lines may carry no kind at all
    return None, None


def load_records(lines):
    """-> (posts, exports, parse_errors)."""
    posts, exports, errors = [], [], []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        kind, rec = parse_record(line)
        if kind == "post":
            posts.append(rec)
        elif kind == "export":
            exports.append(rec)
        else:
            errors.append(line)
    return posts, exports, errors


def normalize(text):
    return " ".join(str(text).casefold().split())


def correlate(posts, exports):
    """-> (pairs, lost_posts, foreign_exports).

    pairs: (post, export) matches — msg_id first, then
    (room, author, normalized text) against the unmatched pool.
    """
    free = set(range(len(exports)))
    by_mid = collections.defaultdict(list)
    by_key = collections.defaultdict(list)
    for i in free:
        e = exports[i]
        if e["msg_id"] is not None:
            by_mid[e["msg_id"]].append(i)
        if e["text"] is not None:
            by_key[(e["room"], e["author"], normalize(e["text"]))].append(i)
    pairs, lost = [], []
    for p in posts:
        j = None
        if p["msg_id"] is not None:
            for i in by_mid.get(p["msg_id"], []):
                if i in free:
                    j = i
                    break
        if j is None and p["text"] is not None:
            key = (p["room"], p["author"], normalize(p["text"]))
            for i in by_key.get(key, []):
                if i in free:
                    j = i
                    break
        if j is None:
            lost.append(p)
        else:
            free.discard(j)
            pairs.append((p, exports[j]))
    foreign = [exports[i] for i in sorted(free)]
    return pairs, lost, foreign


def analyze(posts, exports):
    """-> (stats, findings). Data only; nothing from input is run."""
    findings = []
    pairs, lost, foreign = correlate(posts, exports)
    rooms = {r["room"] for r in posts} | {r["room"] for r in exports}
    per_room = {}
    for room in rooms:
        p = sum(1 for r in posts if r["room"] == room)
        e = sum(1 for r in exports if r["room"] == room)
        m = sum(1 for a, b in pairs if a["room"] == room)
        per_room[None if room is None else str(room)] = {
            "posted": p, "landed": e, "matched": m,
            "coverage": round(m / p, 4) if p else None}
    for p in lost[:3]:
        findings.append({
            "id": "posted-not-landed", "level": "WARN",
            "detail": "room=%r msg_id=%r text=%r never landed"
                      % (p["room"], p["msg_id"],
                         (p["text"] or "")[:40])})
    if len(lost) > 3:
        findings.append({
            "id": "posted-not-landed", "level": "WARN",
            "detail": "... and %d more post(s) with no export record"
                      % (len(lost) - 3)})
    for e in foreign[:3]:
        findings.append({
            "id": "landed-not-posted", "level": "WARN",
            "detail": "room=%r seq=%r msg_id=%r author=%r landed with "
                      "no originating post"
                      % (e["room"], e.get("seq"), e["msg_id"],
                         e["author"])})
    if len(foreign) > 3:
        findings.append({
            "id": "landed-not-posted", "level": "WARN",
            "detail": "... and %d more export record(s) with no post"
                      % (len(foreign) - 3)})
    for p, e in pairs:
        if p["msg_id"] is None or e["msg_id"] is None:
            continue   # text-key matches agree by construction
        if p["text"] is not None and e["text"] is not None \
                and normalize(p["text"]) != normalize(e["text"]):
            findings.append({
                "id": "text-mismatch", "level": "WARN",
                "detail": "msg_id=%r exported as %r, posted as %r"
                          % (p["msg_id"], e["text"][:40],
                             p["text"][:40])})
        if p["author"] is not None and e["author"] is not None \
                and p["author"] != e["author"]:
            findings.append({
                "id": "author-mismatch", "level": "WARN",
                "detail": "msg_id=%r exported under %r, posted by %r"
                          % (p["msg_id"], e["author"], p["author"])})
    lags = []
    for p, e in pairs:
        tp = parse_ts(p["ts"]) if p["ts"] is not None else None
        te = parse_ts(e["ts"]) if e["ts"] is not None else None
        if tp is not None and te is not None and te >= tp:
            lags.append(te - tp)
    lags.sort()
    lag_stat = None
    if lags:
        lag_stat = {"min": round(lags[0], 3),
                    "median": round(lags[len(lags) // 2], 3),
                    "max": round(lags[-1], 3)}
    stats = {"posts": len(posts), "exports": len(exports),
             "matched": len(pairs), "lost_posts": len(lost),
             "foreign_exports": len(foreign),
             "rooms": per_room, "export_lag_secs": lag_stat}
    return stats, findings


def emit_text(stats, findings):
    out = ["posts=%d exports=%d matched=%d lost=%d foreign=%d"
           % (stats["posts"], stats["exports"], stats["matched"],
              stats["lost_posts"], stats["foreign_exports"])]
    for room in sorted(stats["rooms"]):
        row = stats["rooms"][room]
        cov = ("%.1f%%" % (100 * row["coverage"])
               if row["coverage"] is not None else "n/a")
        out.append("  room=%-16s posted=%-4d landed=%-4d matched=%-4d "
                   "coverage=%s" % (str(room)[:16], row["posted"],
                                    row["landed"], row["matched"], cov))
    if stats["export_lag_secs"]:
        lag = stats["export_lag_secs"]
        out.append("export_lag_secs min=%.3f median=%.3f max=%.3f"
                   % (lag["min"], lag["median"], lag["max"]))
    for f in findings:
        out.append("%s %s: %s" % (f["level"], f["id"], f["detail"]))
    return "\n".join(out)


def run(args):
    if args.capture == "-":
        posts, exports, errors = load_records(sys.stdin)
    else:
        try:
            with open(args.capture, "r", errors="replace") as fh:
                posts, exports, errors = load_records(fh)
        except OSError:
            print("export-coverage-audit: cannot read %s" % args.capture,
                  file=sys.stderr)
            return 2
    if args.room:
        posts = [r for r in posts if r["room"] == args.room]
        exports = [r for r in exports if r["room"] == args.room]
    findings = []
    if errors:
        findings.append({
            "id": "parse-error", "level": "WARN",
            "detail": "%d unparseable line(s); first: %r"
                      % (len(errors), errors[0][:60])})
    stats, more = analyze(posts, exports)
    findings.extend(more)
    if args.json:
        payload = dict(stats)
        payload["findings"] = findings
        print(json.dumps(payload, ensure_ascii=False))
    else:
        print(emit_text(stats, findings))
    return 1 if any(f["level"] == "WARN" for f in findings) else 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="export-coverage-audit",
        description="Correlate a live post log against the room export: "
                    "lost posts, injected records, rewritten pairs, "
                    "coverage metrics.")
    p.add_argument("capture", nargs="?",
                   help="post/export JSONL (or '-' for stdin)")
    p.add_argument("--room", help="restrict analysis to one room")
    p.add_argument("--json", action="store_true",
                   help="JSON report on stdout")
    return p


def _write(path, records):
    with open(path, "w") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")


def self_test():
    assert parse_ts("2026-11-17T10:00:00Z") is not None
    assert parse_ts(1763000000) == 1763000000.0
    assert parse_ts("junk") is None and parse_ts(None) is None
    assert normalize("Same  TEXT") == "same text"

    def post(mid, text, ts="2026-11-17T10:00:00Z", room="lobby",
             author="did:a"):
        return {"kind": "post", "ts": ts, "room": room,
                "author": author, "text": text, "msg_id": mid}

    def exp(mid, text, ts="2026-11-17T10:00:05Z", room="lobby",
            author="did:a", seq=1):
        return {"kind": "export", "ts": ts, "room": room, "seq": seq,
                "author": author, "text": text, "msg_id": mid}

    # clean: every post landed once, lag captured
    stats, findings = analyze(
        [post("m-1", "first message"), post("m-2", "second message")],
        [exp("m-1", "first message", seq=1),
         exp("m-2", "second message", seq=2)])
    assert stats["matched"] == 2 and stats["lost_posts"] == 0
    assert stats["foreign_exports"] == 0
    assert not [f for f in findings if f["level"] == "WARN"], findings
    assert stats["export_lag_secs"]["max"] == 5.0
    assert stats["rooms"]["lobby"]["coverage"] == 1.0

    # lost post + injected record
    stats, findings = analyze(
        [post("m-1", "kept"), post("m-9", "vanishes")],
        [exp("m-1", "kept", seq=1),
         exp("m-7", "appears from nowhere", seq=2)])
    ids = {f["id"] for f in findings}
    assert "posted-not-landed" in ids and "landed-not-posted" in ids
    assert any("m-9" in f["detail"] for f in findings)
    assert any("m-7" in f["detail"] for f in findings)
    assert stats["rooms"]["lobby"]["coverage"] == 0.5

    # rewritten pair: same msg_id, different text / author
    stats, findings = analyze(
        [post("m-3", "quorum reached at five")],
        [exp("m-3", "quorum reached at SEVEN", seq=1)])
    assert any(f["id"] == "text-mismatch" for f in findings), findings
    _, findings = analyze(
        [post("m-4", "attributed words", author="did:a")],
        [exp("m-4", "attributed words", author="did:b", seq=1)])
    assert any(f["id"] == "author-mismatch" for f in findings), findings

    # text-key fallback: posts without msg_id match on content
    p = {"kind": "sent", "ts": "t", "room": "lobby", "author": "did:a",
         "text": "kindless post body", "msg_id": None}
    e = {"kind": "landed", "ts": "t", "room": "lobby", "author": "did:a",
         "text": "Kindless   post body", "msg_id": None, "seq": 9}
    stats, findings = analyze([p], [e])
    assert stats["matched"] == 1 and findings == [], findings

    # kind inference: seq or msg_id implies an export line
    inferred = parse_record(json.dumps(
        {"seq": 4, "room": "lobby", "author": "did:a", "text": "x"}))
    assert inferred[0] == "export" and inferred[1]["seq"] == 4
    ided = parse_record(json.dumps({"id": "z", "text": "y"}))
    assert ided[0] == "export" and ided[1]["msg_id"] == "z"
    junk = parse_record("{not json")
    assert junk == (None, None)

    # end-to-end: rc 1, --json shape, --room filter, clean rc 0, rc 2
    warn_fh = tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                          delete=False)
    warn_path = warn_fh.name
    warn_fh.close()
    clean_fh = tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                           delete=False)
    clean_path = clean_fh.name
    clean_fh.close()
    _write(warn_path, [post("m-1", "kept"), post("m-9", "vanishes"),
                       exp("m-1", "kept", seq=1), {"garbage": 1}])
    _write(clean_path, [post("m-1", "kept"), exp("m-1", "kept", seq=1)])
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc1 = run(build_parser().parse_args([warn_path]))
    assert rc1 == 1 and "posted-not-landed" in buf.getvalue()
    assert "parse-error" in buf.getvalue()
    buf2 = io.StringIO()
    with contextlib.redirect_stdout(buf2):
        rcj = run(build_parser().parse_args([warn_path, "--json"]))
    payload = json.loads(buf2.getvalue())
    assert rcj == 1 and payload["lost_posts"] == 1
    buf3 = io.StringIO()
    with contextlib.redirect_stdout(buf3):
        rc0 = run(build_parser().parse_args([clean_path, "--json"]))
    assert rc0 == 0 and json.loads(buf3.getvalue())["findings"] == []
    buf4 = io.StringIO()
    with contextlib.redirect_stdout(buf4):
        rcg = run(build_parser().parse_args([warn_path,
                                             "--room", "ghost"]))
    assert rcg == 1  # only the global parse-error WARN remains
    assert "posted-not-landed" not in buf4.getvalue()
    assert run(build_parser().parse_args(["/nonexistent.jsonl"])) == 2
    for p in (warn_path, clean_path):
        os.unlink(p)
    print("export-coverage-audit self-test OK (clean coverage + lag, "
          "lost post, injected record, text/author rewrite, text-key "
          "fallback, kind inference, --room/--json, rc 0/1/2, parse "
          "errors)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (mutation probe runs after)
    else:
        raise SystemExit(run(build_parser().parse_args()))
