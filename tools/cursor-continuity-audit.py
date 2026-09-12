#!/usr/bin/env python3
"""cursor-continuity-audit — continuity/stability audit for keyset-paginated
API walks (JSONL capture, one record per page fetch: {"ts","collection",
"fetch","request_cursor","has_more","limit","items":[...],"next_cursor"}).

DEMAND: evidence/suggestions/tools-services/2026-09-08.md (09:35 run)
  - "Continuous background data-integrity verification for pagination
    cursors without locking" — evidence: "Auditing data integrity across
    pagination by cursor without locking production tables" (10:52) —
    proposed service: "Cursor-continuity audit for stable pagination
    across concurrent writes".
Scope: the continuity half (cursor chain never gaps or branches) and the
stability half (sort order never inverts, keys never repeat across pages,
re-fetching a cursor never drifts — exactly what concurrent writes break).
Captures are data only: plain parsing, no network, no subprocess. rc 0
clean, 1 BLOCK/WARN, 2 usage/IO. Stdlib only.
"""
import argparse
import base64
import io
import json
import sys

MISSING = object()  # sentinel: item lacks the sort field


def sval(item, field):
    return item.get(field, MISSING)


def cmp_mixed(a, b):
    """Compare sort values; None = uncomparable (mixed types)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return None
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return (a > b) - (a < b)
    if isinstance(a, str) and isinstance(b, str):
        return (a > b) - (a < b)
    return None


def sort_key(item, sortspec):
    """Composite sort value tuple; MISSING member if field absent."""
    out = []
    for field, _asc in sortspec:
        v = sval(item, field)
        out.append(v if v is not None else MISSING)
    return tuple(out)


def key_le(a, b, sortspec):
    """Is composite a <= b under spec (asc/desc per field)? None=unknown."""
    for va, vb, (_f, asc) in zip(a, b, sortspec):
        if va is MISSING or vb is MISSING:
            return None
        c = cmp_mixed(va, vb)
        if c is None:
            return None
        if not asc:
            c = -c
        if c != 0:
            return c < 0
    return True  # equal everywhere


def decode_cursor(tok, codec):
    """opaque -> None (opaque tokens are compared by equality only);
    base64url-json -> decoded object, or 'BAD' if undecodable."""
    if codec != "base64json" or not isinstance(tok, str) or not tok:
        return None
    pad = "=" * (-len(tok) % 4)
    try:
        raw = base64.urlsafe_b64decode(tok + pad)
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else {"v": obj}
    except Exception:
        return "BAD"


def load_records(path):
    """Yield (index, record-or-None) per line; None = malformed."""
    with open(path, "r", errors="replace") as fh:
        for i, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                rec = None
            if rec is not None and not isinstance(rec, dict):
                rec = None
            yield i, rec


def audit(records, sortspec, key_field, codec):
    """records: [(index, dict|None)] -> findings list of dicts."""
    f = []

    def add(sev, kind, coll, fetch, page, detail):
        f.append(dict(severity=sev, kind=kind, collection=coll,
                      fetch=fetch, page=page, detail=detail))

    pages, malformed = [], 0
    for idx, rec in records:
        if rec is None:
            malformed += 1
            continue
        pages.append((idx, rec))
    if malformed:
        add("WARN", "malformed-line", "-", "-", "-",
            f"{malformed} unparsable input line(s)")

    # group page fetches: (collection, fetch id), ordered by ts then file order
    groups = {}
    for idx, rec in pages:
        gid = (str(rec.get("collection", "default")),
               str(rec.get("fetch", "walk")))
        groups.setdefault(gid, []).append((idx, rec))

    # seen cursors per collection, for re-fetch drift detection
    seen_req = {}   # (coll, request_cursor) -> frozenset(item keys)
    cursor_src = {}  # cursor token -> collection that emitted it

    for (coll, walk), plist in groups.items():
        plist.sort(key=lambda p: p[0])  # capture order = wire order
        prev = None
        walk_seen = {}  # item key -> page number it first appeared on
        for n, (idx, rec) in enumerate(plist):
            req = rec.get("request_cursor")
            nxt = rec.get("next_cursor")
            more = rec.get("has_more")
            items = rec.get("items")
            items = items if isinstance(items, list) else []
            tag = f"page {n + 1}"

            # items must be dicts with the key field
            keys = []
            for it in items:
                k = it.get(key_field) if isinstance(it, dict) else None
                keys.append(k)

            # --- cursor chain continuity ---
            if prev is None:
                if req not in (None, ""):
                    add("INFO", "resumed-walk", coll, walk, tag,
                        f"walk starts at non-empty cursor {req!r}")
            else:
                pmore, pnxt = prev[1].get("has_more"), prev[1].get("next_cursor")
                if pmore and pnxt in (None, ""):
                    add("BLOCK", "chain-truncated", coll, walk,
                        f"page {n}", "has_more=true but no next_cursor")
                if req != pnxt:
                    add("BLOCK", "chain-break", coll, walk, tag,
                        f"request_cursor {req!r} != previous "
                        f"next_cursor {pnxt!r}")
            if more and nxt in (None, ""):
                add("BLOCK", "chain-truncated", coll, walk, tag,
                    "has_more=true but no next_cursor")
            if more is False and nxt not in (None, ""):
                add("WARN", "dangling-terminator", coll, walk, tag,
                    f"has_more=false yet next_cursor={nxt!r}")

            # --- page sizing ---
            limit = rec.get("limit")
            if isinstance(limit, (int, float)) and not isinstance(limit, bool):
                if more and 0 <= len(items) < limit:
                    add("WARN", "under-filled-page", coll, walk, tag,
                        f"{len(items)} items < limit {limit} but "
                        f"has_more=true")
                if len(items) > limit:
                    add("WARN", "over-limit", coll, walk, tag,
                        f"{len(items)} items > limit {limit}")
            if more and not items:
                add("WARN", "empty-page", coll, walk, tag,
                    "has_more=true but page is empty")

            # --- sort stability + duplicate keys within the walk ---
            if prev is not None:
                p_raw = prev[1].get("items")
                pitems = [it for it in (p_raw if isinstance(p_raw, list) else [])
                          if isinstance(it, dict)]
                last = sort_key(pitems[-1], sortspec) if pitems else None
                first = (sort_key(items[0], sortspec)
                         if items and isinstance(items[0], dict) else None)
                if last is not None and first is not None:
                    ok = key_le(last, first, sortspec)
                    if ok is None:
                        add("WARN", "mixed-sort-types", coll, walk, tag,
                            "page-boundary sort values not comparable")
                    elif not ok:
                        add("BLOCK", "sort-inversion", coll, walk, tag,
                            "first key of this page < last key of previous "
                            "page (unstable ordering across concurrent "
                            "writes)")
            for pos, (it, k) in enumerate(zip(items, keys)):
                if not isinstance(it, dict) or k is None:
                    add("WARN", "missing-key", coll, walk, tag,
                        f"item {pos} lacks key field {key_field!r}")
                    continue
                if k in walk_seen:
                    where = ("inside one page"
                             if walk_seen[k] == n + 1
                             else f"across pages {walk_seen[k]} and {n + 1}")
                    add("BLOCK", "duplicate-key", coll, walk, tag,
                        f"key {k!r} repeats {where} (unstable pagination)")
                else:
                    walk_seen[k] = n + 1
                sk = sort_key(it, sortspec)
                if any(v is MISSING for v in sk):
                    add("WARN", "missing-sort-field", coll, walk, tag,
                        f"item {k!r} lacks a --sort field")
            for pos in range(1, len(items)):
                ia, ib = items[pos - 1], items[pos]
                if not isinstance(ia, dict) or not isinstance(ib, dict):
                    continue
                a = sort_key(ia, sortspec)
                b = sort_key(ib, sortspec)
                if any(v is MISSING for v in a + b):
                    continue
                ok = key_le(a, b, sortspec)
                if ok is None:
                    add("WARN", "mixed-sort-types", coll, walk, tag,
                        f"items {pos - 1}/{pos} sort values not comparable")
                elif not ok:
                    add("BLOCK", "sort-inversion", coll, walk, tag,
                        f"page-internal inversion at item {pos}")

            # --- cursor binding (base64json codec only) ---
            if codec == "base64json" and items and isinstance(nxt, str) \
                    and nxt and isinstance(items[-1], dict):
                dec = decode_cursor(nxt, codec)
                if dec == "BAD":
                    add("WARN", "cursor-undecodable", coll, walk, tag,
                        "next_cursor is not base64url JSON")
                elif isinstance(dec, dict):
                    for field, _asc in sortspec:
                        if field in dec:
                            want = sval(items[-1], field)
                            if want is not MISSING and dec[field] != want:
                                add("BLOCK", "cursor-bind", coll, walk, tag,
                                    f"next_cursor[{field}]={dec[field]!r} "
                                    f"!= last item {want!r}")
            if isinstance(req, str) and req:
                src = cursor_src.get(req)
                if src is not None and src != coll:
                    add("WARN", "cursor-leak", coll, walk, tag,
                        f"request_cursor emitted by collection {src!r} "
                        f"is being replayed against {coll!r}")
            if isinstance(nxt, str) and nxt:
                cursor_src.setdefault(nxt, coll)

            # --- re-fetch drift ---
            if req not in (None, ""):
                kset = frozenset(k for k in keys if k is not None)
                prior = seen_req.get((coll, req))
                if prior is None:
                    seen_req[(coll, req)] = kset
                elif prior != kset:
                    add("WARN", "refetch-drift", coll, walk, tag,
                        f"cursor {req!r} re-fetched with a different "
                        f"key set (pagination unstable under concurrency)")
                else:
                    add("INFO", "refetch-stable", coll, walk, tag,
                        f"cursor {req!r} re-fetched identically")

            # --- ts regressions within a walk ---
            if prev is not None:
                pt, t = prev[1].get("ts"), rec.get("ts")
                if isinstance(pt, str) and isinstance(t, str) and t < pt:
                    add("WARN", "late-page", coll, walk, tag,
                        f"ts {t!r} precedes previous page ts {pt!r}")
            prev = (idx, rec)

        if prev is not None and prev[1].get("has_more") is None:
            add("INFO", "ambiguous-terminator", coll, walk, "last page",
                "final page lacks has_more; walk may be incomplete")
    return f


def render(findings):
    counts = {s: sum(1 for x in findings if x["severity"] == s)
              for s in ("BLOCK", "WARN", "INFO")}
    print(f"summary: {counts['BLOCK']} block, {counts['WARN']} warn, "
          f"{counts['INFO']} info")
    for x in findings:
        print(f"[{x['severity']}] {x['kind']} ({x['collection']}/"
              f"{x['fetch']}, {x['page']}): {x['detail']}")
    return counts


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Audit cursor continuity and pagination stability of a "
                    "JSONL capture of keyset-paginated API walks.")
    ap.add_argument("capture", help="JSONL file, one page-fetch per line")
    ap.add_argument("--sort", action="append", default=None,
                    metavar="FIELD[:asc|desc]",
                    help="composite sort spec (repeatable; default id:asc)")
    ap.add_argument("--key", default="id",
                    help="item primary-key field (default: id)")
    ap.add_argument("--cursor-codec", choices=("opaque", "base64json"),
                    default="opaque",
                    help="treat cursors as opaque tokens or decode "
                         "base64url-JSON and bind them to page content")
    ap.add_argument("--json", action="store_true",
                    help="emit findings as JSON")
    args = ap.parse_args(argv)

    sortspec = []
    for spec in (args.sort or ["id:asc"]):
        field, _, direction = spec.partition(":")
        sortspec.append((field, direction.lower() != "desc"))

    try:
        recs = list(load_records(args.capture))
    except OSError as e:
        print(f"error: cannot read {args.capture}: {e}", file=sys.stderr)
        return 2

    findings = audit(recs, sortspec, args.key, args.cursor_codec)
    if args.json:
        print(json.dumps({"findings": findings}, ensure_ascii=False))
    else:
        render(findings)
    return 1 if any(x["severity"] != "INFO" for x in findings) else 0


def _mk(coll, walk, n, items, req=None, nxt=None, more=None,
        limit=None, ts=None):
    rec = {"collection": coll, "fetch": walk, "items": items,
           "request_cursor": req, "next_cursor": nxt, "has_more": more}
    if ts:
        rec["ts"] = ts
    if limit is not None:
        rec["limit"] = limit
    return rec


def _kinds(finds):
    return sorted({x["kind"] for x in finds})


def self_test():
    import os
    import tempfile

    # chain continuity: clean walk is silent; gap and branch are BLOCKs
    clean = [(_i, _mk("c", "w", _i, [{"id": _i}], more=_i < 2,
                      nxt="cur1" if _i == 0 else ("cur2" if _i == 1 else None),
                      req=None if _i == 0 else ("cur1" if _i == 1 else "cur2")))
             for _i in range(3)]
    assert audit(clean, [("id", True)], "id", "opaque") == []
    gap = clean[:2] + [(9, _mk("c", "w", 3, [{"id": 9}], req="curX",
                               more=False))]
    assert _kinds(audit(gap, [("id", True)], "id", "opaque")) == ["chain-break"]
    trunc = clean[:2] + [(9, _mk("c", "w", 3, [{"id": 9}], more=True))]
    assert _kinds(audit(trunc, [("id", True)], "id", "opaque")) == \
        ["chain-break", "chain-truncated"]

    # sort stability: boundary inversion (the concurrent-write symptom),
    # page-internal inversion, mixed types, missing sort field
    inv = [(_i, _mk("c", "w", _i, [{"id": 5}], more=_i < 1,
                    nxt="n1", req=None if _i == 0 else "n1"))
           for _i in range(2)]
    inv[1] = (1, _mk("c", "w", 1, [{"id": 2}], more=False, req="n1"))
    assert "sort-inversion" in _kinds(audit(inv, [("id", True)], "id", "opaque"))
    mixed = [(0, _mk("c", "w", 0, [{"id": "a"}, {"id": 3}], more=False))]
    assert _kinds(audit(mixed, [("id", True)], "id", "opaque")) == \
        ["mixed-sort-types"]
    miss = [(0, _mk("c", "w", 0, [{"id": 1, "t": 1}, {"id": 2}], more=False))]
    assert _kinds(audit(miss, [("t", True)], "id", "opaque")) == \
        ["missing-sort-field"]

    # duplicate keys: inside a page and across the page boundary
    dup = [(0, _mk("c", "w", 0, [{"id": 1}, {"id": 1}], more=False))]
    got = audit(dup, [("id", True)], "id", "opaque")
    assert "duplicate-key" in _kinds(got)
    assert "inside one page" in got[0]["detail"]
    dup2 = [(0, _mk("c", "w", 0, [{"id": 1}], more=True, nxt="n1")),
            (1, _mk("c", "w", 1, [{"id": 1}], more=False, req="n1"))]
    got = audit(dup2, [("id", True)], "id", "opaque")
    assert "duplicate-key" in _kinds(got)
    assert "across pages 1 and 2" in got[0]["detail"]
    dup3 = [(0, _mk("c", "w", 0, [{"id": 1}], more=True, nxt="n1")),
            (1, _mk("c", "w", 1, [{"id": 1}, {"id": 2}], more=False,
                    req="n1"))]
    got = audit(dup3, [("id", True)], "id", "opaque")
    assert _kinds(got) == ["duplicate-key"]  # tie at boundary: only the dup

    # page sizing: under-filled / over-limit / empty-page / missing key
    under = [(0, _mk("c", "w", 0, [{"id": 1}], more=True, nxt="n1",
                     limit=10))]
    assert "under-filled-page" in _kinds(
        audit(under, [("id", True)], "id", "opaque"))
    over = [(0, _mk("c", "w", 0, [{"id": 1}, {"id": 2}], more=False,
                    limit=1))]
    assert "over-limit" in _kinds(audit(over, [("id", True)], "id", "opaque"))
    empty = [(0, _mk("c", "w", 0, [], more=True, nxt="n1", limit=10))]
    assert _kinds(audit(empty, [("id", True)], "id", "opaque")) == \
        ["empty-page", "under-filled-page"]
    nokey = [(0, _mk("c", "w", 0, [{"x": 1}], more=False))]
    assert "missing-key" in _kinds(audit(nokey, [("id", True)], "id", "opaque"))
    # items: null and mixed-type arrays are findings, not crashes
    null_items = [(0, _mk("c", "w", 0, None, more=True, nxt="n1")),
                  (1, _mk("c", "w", 1, ["not-a-dict", 3], more=False,
                          req="n1"))]
    assert "missing-key" in _kinds(
        audit(null_items, [("id", True)], "id", "opaque"))
    mixed_items = [(0, _mk("c", "w", 0, ["x", {"id": 1}, 2], more=False))]
    assert "missing-key" in _kinds(
        audit(mixed_items, [("id", True)], "id", "opaque"))

    # desc ordering respected: strictly descending ids stay silent
    desc = [(0, _mk("c", "w", 0, [{"id": 9}, {"id": 5}], more=True,
                    nxt="n1")),
            (1, _mk("c", "w", 1, [{"id": 2}], more=False, req="n1"))]
    assert audit(desc, [("id", False)], "id", "opaque") == []
    assert "sort-inversion" in _kinds(
        audit(desc, [("id", True)], "id", "opaque"))

    # re-fetch drift: same cursor, different key set -> WARN; same -> INFO
    drift = [(0, _mk("c", "w", 0, [{"id": 1}], more=True, nxt="n1")),
             (1, _mk("c", "w", 1, [{"id": 2}, {"id": 3}], more=False,
                     req="n1")),
             (2, _mk("c", "w2", 0, [{"id": 1}, {"id": 2}], more=False,
                     req="n1")),
             (3, _mk("c", "w3", 0, [{"id": 2}, {"id": 3}], more=False,
                     req="n1"))]
    got = audit(drift, [("id", True)], "id", "opaque")
    assert "refetch-drift" in _kinds(got) and "refetch-stable" in _kinds(got)

    # cursor binding via base64json: bound cursor silent, mismatch BLOCK
    def cur(v):
        return base64.urlsafe_b64encode(
            json.dumps({"id": v}).encode()).decode().rstrip("=")
    bound = [(0, _mk("c", "w", 0, [{"id": 1}, {"id": 2}], more=True,
                     nxt=cur(2))),
             (1, _mk("c", "w", 1, [{"id": 3}], more=False, req=cur(2)))]
    assert audit(bound, [("id", True)], "id", "base64json") == []
    badbind = [(0, _mk("c", "w", 0, [{"id": 1}, {"id": 2}], more=True,
                       nxt=cur(9)))]
    assert _kinds(audit(badbind, [("id", True)], "id", "base64json")) == \
        ["cursor-bind"]
    assert "cursor-undecodable" in _kinds(
        audit([(0, _mk("c", "w", 0, [{"id": 1}], more=True, nxt="!!!"))],
              [("id", True)], "id", "base64json"))
    # last item lacking a --sort field must not false-BLOCK cursor-bind
    def cur_t(v):
        return base64.urlsafe_b64encode(
            json.dumps({"t": v}).encode()).decode().rstrip("=")
    miss_bind = [(0, _mk("c", "w", 0, [{"id": 1}], more=True, nxt=cur_t(9)))]
    assert _kinds(audit(miss_bind, [("t", True)], "id", "base64json")) == \
        ["missing-sort-field"]

    # cursor leak across collections; late page; ambiguous terminator;
    # resumed walk; dangling terminator
    leak = [(0, _mk("a", "w", 0, [{"id": 1}], more=True, nxt="tok")),
            (1, _mk("b", "w", 0, [{"id": 5}], more=False, req="tok"))]
    assert "cursor-leak" in _kinds(audit(leak, [("id", True)], "id", "opaque"))
    late = [(0, _mk("c", "w", 0, [{"id": 1}], more=True, nxt="n1",
                    ts="2026-09-12T10:00:00Z")),
            (1, _mk("c", "w", 1, [{"id": 2}], more=False, req="n1",
                    ts="2026-09-12T09:59:00Z"))]
    assert "late-page" in _kinds(audit(late, [("id", True)], "id", "opaque"))
    amb = [(0, _mk("c", "w", 0, [{"id": 1}], nxt="n1"))]
    assert _kinds(audit(amb, [("id", True)], "id", "opaque")) == \
        ["ambiguous-terminator"]
    resumed = [(0, _mk("c", "w", 0, [{"id": 7}], more=False, req="saved"))]
    assert _kinds(audit(resumed, [("id", True)], "id", "opaque")) == \
        ["resumed-walk"]
    dang = [(0, _mk("c", "w", 0, [{"id": 1}], more=False, nxt="n1"))]
    assert _kinds(audit(dang, [("id", True)], "id", "opaque")) == \
        ["dangling-terminator"]

    # end-to-end: file IO, rc contract, --json shape, malformed counting
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                     delete=False) as tf:
        for rec in [r[1] for r in clean]:
            tf.write(json.dumps(rec) + "\n")
        path = tf.name
    try:
        buf = io.StringIO()
        from contextlib import redirect_stdout
        with redirect_stdout(buf):
            assert main([path]) == 0
            assert main([path, "--json"]) == 0
        doc = json.loads(buf.getvalue().splitlines()[-1])
        assert doc["findings"] == []
        assert main(["/nonexistent.jsonl"]) == 2
    finally:
        os.unlink(path)
    # INFO-only (resumed walk) is rc 0; WARN/BLOCK still fail
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                     delete=False) as tf:
        tf.write(json.dumps(_mk("c", "w", 0, [{"id": 7}], more=False,
                                req="saved")) + "\n")
        path = tf.name
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            assert main([path]) == 0
        assert "resumed-walk" in buf.getvalue()
    finally:
        os.unlink(path)
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                     delete=False) as tf:
        tf.write('{"broken\n[]\n{"collection": "c", "fetch": "w", '
                 '"items": [{"id": 1}], "has_more": false}\n')
        path = tf.name
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            assert main([path]) == 1
        assert "2 unparsable" in buf.getvalue(), buf.getvalue()
    finally:
        os.unlink(path)

    print("cursor-continuity-audit self-test OK (29 assertion groups: "
          "chain continuity, sort stability incl. desc, duplicates, page "
          "sizing, re-fetch drift, base64json cursor binding, cursor leak, "
          "late pages, terminators, CLI rc contract, json export)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this line)
    else:
        raise SystemExit(main())
