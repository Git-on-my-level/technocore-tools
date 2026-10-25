#!/usr/bin/env python3
"""job-coalesce-audit — audit a job/offer queue for identical reposts:
which repeated jobs coalesce, which repost storms went unserved, and
which executions were wasted on work already done.

DEMAND: evidence/suggestions/tools-services/2026-10-24.md
  - request: "reproducible/self-checking audit tooling for snippets"
    — evidence: "JOB v1 | kda2308fa12 | review | Audit this snippet:
    `def div(a,b): return a/b`... Success: list 2 concrete bugs and a
    hardened version" (repeated ~8x across timestamps 10-23 13:25-
    20:20) — proposed service: "snippet-audit job handler ... dedupli-
    cated so repeated identical jobs coalesce". Same unserved-repost
    pattern filed in 2026-10-22.md and 2026-10-23.md ("jobs appear to
    be posted repeatedly (4x), suggesting unserved or flaky
    fulfilment"). room-dedup collapses chat floods; nothing audits the
    JOB QUEUE for duplicate work, wasted executions and unserved
    repost storms.
  Scope: the queue hygiene half — payload identity, repost detection,
  coalescing accounting.

Input: one JSONL file, one job per line:
  {"job_id": str, "kind": str, "payload": str|object,
   "posted_ts": epoch secs,
   "status": "served"|"claimed"|"open"|"requeued"|"failed"}
Two jobs are the same work when their canonical payload matches:
  object payloads are key-sorted with volatile fields dropped
  (job_id, posted_at, posted_ts, ts, nonce, request_id, retry);
  string payloads are whitespace-collapsed and casefolded.

Findings (rc 0 clean / 1 findings / 2 usage-IO):
  no-jobs            FAIL  queue file has no usable job records
  unserved-storm     FAIL  >= --storm (default 3) identical payloads,
                          none ever served or claimed (the repost-
                          until-served symptom)
  repost-after-served FAIL  identical reposts after a served job —
                          duplicate work a coalescer would have
                          collapsed
  storm-window       WARN  >= --storm identical posts within
                          --window-min (default 120) minutes
  stale-open         WARN  open/requeued job older than --stale-min
                          (default 1440) minutes before the newest post
  unknown-status     WARN  status outside the known vocabulary
  malformed-line     WARN  unparseable JSONL line
Board: totals, distinct payloads, repost ratio, executions saved by
coalescing, top clusters. Data only — json/hashlib, nothing runs.
Stdlib only.
"""
import argparse
import hashlib
import json
import os
import sys
import tempfile
from collections import defaultdict

FAIL, WARN = "FAIL", "WARN"
STATUSES = ("served", "claimed", "open", "requeued", "failed")
VOLATILE = ("job_id", "posted_at", "posted_ts", "ts", "nonce",
            "request_id", "retry")


def canonical(payload):
    """Payload -> stable identity string (volatile fields dropped)."""
    if isinstance(payload, dict):
        clean = {k: payload[k] for k in sorted(payload)
                 if k not in VOLATILE}
        return json.dumps(clean, sort_keys=True, ensure_ascii=False)
    if isinstance(payload, str):
        return " ".join(payload.split()).casefold()
    return json.dumps(payload, sort_keys=True)


def payload_key(payload):
    return hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()


def read_jobs(path):
    """Yield (lineno, record-or-None) per JSONL line."""
    try:
        with open(path, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    rec = None
                yield n, rec if isinstance(rec, dict) else None
    except OSError:
        return


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def clusters_of(jobs):
    """jobs: [{job_id, kind, payload, posted_ts, status}] ->
    {payload_key: [job, ...]} with posts in posted order."""
    out = defaultdict(list)
    for j in jobs:
        out[j["key"]].append(j)
    for posts in out.values():
        posts.sort(key=lambda j: (j["posted_ts"], j["job_id"]))
    return dict(out)


def audit(jobs, storm, window_secs, stale_secs):
    """Full audit -> (findings, summary). jobs have key/status fields."""
    findings = []
    clusters = clusters_of(jobs)
    reposts = max(0, len(jobs) - len(clusters))
    executions = sum(1 for j in jobs if j["status"] == "served")
    for key, posts in sorted(clusters.items(),
                             key=lambda kv: (-len(kv[1]), kv[0])):
        if len(posts) < 2:
            continue
        label = "%s/%s..%s" % (posts[0]["kind"], posts[0]["job_id"],
                               hashlib.sha256(key.encode()).hexdigest()[:6])
        statuses = {p["status"] for p in posts}
        if len(posts) >= storm and not ({"served", "claimed"} & statuses):
            findings.append((FAIL, "unserved-storm",
                             "%s: %d identical posts, none served/claimed"
                             % (label, len(posts))))
        first_served = next((p for p in posts if p["status"] == "served"),
                            None)
        if first_served is not None:
            dupes = [p for p in posts
                     if p["posted_ts"] > first_served["posted_ts"]]
            if dupes:
                findings.append((FAIL, "repost-after-served",
                                 "%s: %d repost(s) after served %s — "
                                 "wasted duplicate work"
                                 % (label, len(dupes),
                                    first_served["job_id"])))
        times = [p["posted_ts"] for p in posts]
        for a, b in zip(times, times[1:]):
            if b - a <= window_secs and b - a >= 0:
                burst = [t for t in times if a <= t <= b + window_secs]
                if len(burst) >= storm:
                    findings.append((WARN, "storm-window",
                                     "%s: %d posts within %ds window"
                                     % (label, len(burst), window_secs)))
                    break
    newest = max((j["posted_ts"] for j in jobs), default=None)
    for j in jobs:
        if j["status"] in ("open", "requeued") and newest is not None \
                and newest - j["posted_ts"] > stale_secs:
            findings.append((WARN, "stale-open",
                             "%s (%s): still %s for %d minutes"
                             % (j["job_id"], j["kind"], j["status"],
                                (newest - j["posted_ts"]) // 60)))
    summary = {"jobs": len(jobs), "distinct": len(clusters),
               "reposts": reposts,
               "executions": executions,
               "saved": reposts,
               "top": sorted(
                   ({"key": k[:10], "kind": p[0]["kind"],
                     "posts": len(p),
                     "statuses": sorted({x["status"] for x in p})}
                    for k, p in clusters.items()),
                   key=lambda c: -c["posts"])[:5]}
    return findings, summary


def report(findings, summary):
    lines = ["job queue coalescing audit: %d job(s), %d distinct "
             "payload(s), %d repost(s), %d execution(s)"
             % (summary["jobs"], summary["distinct"], summary["reposts"],
                summary["executions"])]
    if summary["jobs"]:
        lines.append("  coalescing would collapse %d post(s) into "
                     "already-done work" % summary["saved"])
    for c in summary["top"]:
        if c["posts"] > 1:
            lines.append("  cluster %s.. %s: %d post(s) %s"
                         % (c["key"], c["kind"], c["posts"],
                            ",".join(c["statuses"])))
    lines.append("%d finding(s)" % len(findings))
    for sev, rule, detail in findings:
        lines.append("  %-4s %-18s %s" % (sev, rule, detail))
    return "\n".join(lines), 1 if findings else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("queue", help="job/offer queue JSONL")
    ap.add_argument("--storm", type=int, default=3,
                    help="identical posts that make a storm (default 3)")
    ap.add_argument("--window-min", type=int, default=120)
    ap.add_argument("--stale-min", type=int, default=1440)
    args = ap.parse_args(argv)
    if args.storm < 2 or args.window_min <= 0 or args.stale_min <= 0:
        print("storm must be >= 2; windows must be positive",
              file=sys.stderr)
        return 2
    if not os.path.isfile(args.queue):
        print("unreadable queue: %s" % args.queue, file=sys.stderr)
        return 2
    jobs, bad, unknown = [], 0, 0
    for n, rec in read_jobs(args.queue):
        if (rec is None or not rec.get("job_id")
                or not is_int(rec.get("posted_ts"))
                or "payload" not in rec):
            bad += 1
            continue
        status = rec.get("status", "open")
        if status not in STATUSES:
            unknown += 1
        jobs.append({"job_id": str(rec["job_id"]),
                     "kind": str(rec.get("kind", "job")),
                     "payload": rec["payload"],
                     "posted_ts": rec["posted_ts"],
                     "status": status,
                     "key": payload_key(rec["payload"])})
    if bad:
        findings0 = [(WARN, "malformed-line",
                      "%d unparseable/invalid line(s)" % bad)]
    else:
        findings0 = []
    if unknown:
        findings0.append((WARN, "unknown-status",
                          "%d job(s) with status outside %s"
                          % (unknown, "/".join(STATUSES))))
    if not jobs:
        text, rc = report(findings0 + [(FAIL, "no-jobs",
                                        "queue has no usable job records")],
                          {"jobs": 0, "distinct": 0, "reposts": 0,
                           "executions": 0, "saved": 0, "top": []})
        print(text)
        return rc
    findings, summary = audit(jobs, args.storm,
                              args.window_min * 60, args.stale_min * 60)
    text, rc = report(findings0 + findings, summary)
    print(text)
    return rc


def self_test():
    assert canonical({"b": 2, "a": 1}) == '{"a": 1, "b": 2}'
    assert canonical({"job_id": "x", "a": 1}) == '{"a": 1}'
    assert canonical("  Audit   This SNIPPET ") == "audit this snippet"
    assert canonical({"retry": 3, "payload": "p"}) == \
        canonical({"payload": "p"})
    k1 = payload_key({"payload": "div(a,b)"})
    assert k1 == payload_key({"payload": "div(a,b)", "posted_ts": 99})
    assert k1 != payload_key({"payload": "div(a,b,c)"})

    def j(jid, ts, payload="P", status="open", kind="review"):
        return {"job_id": jid, "kind": kind, "payload": payload,
                "posted_ts": ts, "status": status,
                "key": payload_key(payload)}

    # single unique served job: clean
    f, s = audit([j("a", 0, status="served")], 3, 7200, 86400)
    assert f == [] and s["distinct"] == 1, (f, s)

    # unserved storm: 4 identical posts, none served
    storm = [j("a%d" % i, 100 + i) for i in range(4)]
    f, s = audit(storm, 3, 7200, 86400)
    assert any(r == "unserved-storm" and "4 identical" in d
               for _, r, d in f), f
    assert s["reposts"] == 3 and s["jobs"] == 4, s

    # repost after served -> wasted work
    ras = [j("s1", 0, status="served"), j("r1", 50), j("r2", 60)]
    f, _ = audit(ras, 3, 7200, 86400)
    assert any(r == "repost-after-served" and "2 repost" in d
               for _, r, d in f), f
    assert not any(r == "unserved-storm" for _, r, _ in f), f

    # storm inside a tight window (WARN) vs spread out (clean)
    tight = [j("t%d" % i, 1000 + i * 60) for i in range(4)]
    tight[0]["status"] = "claimed"
    f, _ = audit(tight, 3, 120 * 60, 86400)
    assert any(r == "storm-window" for _, r, _ in f), f
    spread = [j("w%d" % i, 100000 * i) for i in range(4)]
    spread[0]["status"] = "claimed"
    f, _ = audit(spread, 3, 120 * 60, 86400)
    assert not any(r == "storm-window" for _, r, _ in f), f

    # stale open job
    stale = [j("old", 0, status="open"), j("new", 10 * 86400,
                                           status="served")]
    f, _ = audit(stale, 3, 7200, 86400)
    assert any(r == "stale-open" and "old" in d for _, r, d in f), f

    assert audit(storm, 3, 7200, 86400)[0] == \
        audit(storm, 3, 7200, 86400)[0], "deterministic"

    tmp = tempfile.mkdtemp(prefix="jca-")
    qp = os.path.join(tmp, "queue.jsonl")
    with open(qp, "w") as fh:
        fh.write(json.dumps({"job_id": "ok1", "kind": "review",
                             "payload": "def div(a,b): return a/b",
                             "posted_ts": 1000, "status": "served"})
                 + "\n")
    assert main([qp]) == 0
    with open(qp, "a") as fh:
        for i in range(3):
            fh.write(json.dumps({"job_id": "dup%d" % i, "kind": "review",
                                 "payload": "def div(a,b): return a/b",
                                 "posted_ts": 2000 + i,
                                 "status": "open"}) + "\n")
        fh.write("{broken\n")
    assert main([qp]) == 1
    assert main([qp, "--storm", "1"]) == 2
    assert main(["missing.jsonl"]) == 2
    print("OK job-coalesce-audit: canonical payload identity (volatile "
          "fields dropped), unserved-storm, repost-after-served, "
          "storm-window, stale-open, determinism, CLI rc 0/1/2")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
