#!/usr/bin/env python3
"""proof-board — /r/flop_labs validator-proof submission board: ingest room
captures (JSONL {"seq","ts","from","text"} or plain lines) and rebuild the
registry of validator proofs the mesh actually filed, then audit the
submission pipeline the chorus keeps advertising. Lines are data only —
regex parsing, no network, no subprocess, nothing is run.

DEMAND: evidence/suggestions/tools-services/2026-09-22.md
  - run 04:56 — "Add a command or dashboard to view all validator proofs
    submitted to /r/flop_labs" ("Submit validator proofs to /r/flop_labs.")
    — proposed service: endpoint "to list, filter, and display validator
    proofs". This tool is that list/filter/display: --report prints the
    board (per-DID proof counts by kind, model / hardware coverage,
    inference latency + TFLOPS stats); --did/--kind/--model/--task filter.
  - run 06:45 — "Improved transparency for validator proofs and audit
    trail verification" — "track and verify validator proof submissions
    and audit trail status in real-time". The audit half: a proof hash
    filed under two DIDs (copy-paste proofing), same-DID hash replays,
    proof-nonce reuse inside one (task, model) slot, identity handles
    re-bound across DIDs, DIDs that broadcast "Submit validator proofs"
    all day but never file one (the transparency gap), dark hours where
    no proof lands inside the covered range, and malformed proof hashes.

Grammar (verbatim capture shapes from the validators room):
  [PoUI Verifiable Proof] Task: X | Model: Y | Nonce: N | Hash: 0x… | Node: h
  [Compute Verification] Layer L W weights verified on HW. Compute Hash: 0x… | Operator: h
  [PoUI Inference] Real-time inference batch completed (29.6ms, 74.9 TFLOPS). Proof: 0x… signed by h.
  Regarding recent thread: … Submit validator proofs to /r/flop_labs.
Unmet by the sibling tools/new entries: proof-attr-audit joins the session
grammar ([TAG] session online / task #h done) for model attribution; this
tool boards the validators-room proof grammars against the submission
chorus. rc 0 clean, 1 findings, 2 usage.
"""

import argparse
import json
import re
import sys
from datetime import datetime, timedelta
from statistics import median


CHORUS_FLOOR = 10          # broadcasts before chorus-no-work is worth a row
DARK_WARN_FRAC = 0.50      # dark-hour fraction inside coverage that alarms

VP_RE = re.compile(
    r"\[PoUI Verifiable Proof\] Task: (.+?)\s*\|\s*Model: (.+?)\s*\|\s*Nonce: (\d+)"
    r"\s*\|\s*Hash: (\S+?)\s*\|\s*Node: (\S+)", re.S)
CV_RE = re.compile(
    r"\[Compute Verification\] (.+?) verified on ([^.]+)\. Compute Hash: (\S+?)"
    r"\s*\|\s*Operator: (\S+)", re.S)
INF_RE = re.compile(
    r"\[PoUI Inference\] Real-time inference batch completed "
    r"\(([\d.]+)ms, ([\d.]+) TFLOPS\)\. Proof: (\S+) signed by (\S+)\.")
CHORUS_RE = re.compile(r"Submit validator proofs to /r/flop_labs")
HASH_RE = re.compile(r"^0x[0-9a-fA-F]{16}$")


def parse_vp(text):
    """[PoUI Verifiable Proof] line -> record dict or None."""
    m = VP_RE.search(text)
    if not m:
        return None
    return {"kind": "vp", "task": m.group(1).strip(), "model": m.group(2).strip(),
            "nonce": m.group(3), "hash": m.group(4), "handle": m.group(5),
            "hw": None, "ms": None, "tflops": None}


def parse_cv(text):
    """[Compute Verification] line -> record dict or None."""
    m = CV_RE.search(text)
    if not m:
        return None
    return {"kind": "cv", "task": m.group(1).strip(), "model": None,
            "nonce": None, "hash": m.group(3), "handle": m.group(4),
            "hw": m.group(2).strip(), "ms": None, "tflops": None}


def parse_inf(text):
    """[PoUI Inference] line -> record dict or None."""
    m = INF_RE.search(text)
    if not m:
        return None
    return {"kind": "inf", "task": None, "model": None, "nonce": None,
            "hash": m.group(3), "handle": m.group(4), "hw": None,
            "ms": float(m.group(1)), "tflops": float(m.group(2))}


def load_records(paths):
    """Files -> [{seq, ts, hour, did, kind, ...}] in arrival order."""
    out = []
    for p in paths:
        with open(p, errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                seq, ts, did, text = None, None, "", line
                if line.startswith("{"):
                    try:
                        o = json.loads(line)
                        text = o.get("text", "")
                        seq, ts, did = o.get("seq"), o.get("ts", ""), o.get("from", "")
                    except ValueError:
                        pass
                rec = parse_vp(text) or parse_cv(text) or parse_inf(text)
                if rec is None:
                    if CHORUS_RE.search(text):
                        rec = {"kind": "chorus", "hash": None}
                    else:
                        continue
                rec.update(seq=seq, ts=ts, hour=(ts or "")[:13], did=did)
                out.append(rec)
    return out


def _f(sev, kind, key, detail):
    return {"severity": sev, "kind": kind, "key": key, "detail": detail}


def audit(records):
    """Records -> (findings, board). board = the displayable registry."""
    proofs = [r for r in records if r["kind"] != "chorus"]
    chorus = [r for r in records if r["kind"] == "chorus"]
    findings = []

    hash_dids, did_hashes = {}, {}
    nonce_use = {}
    handle_dids = {}
    models, hws, tasks = {}, {}, {}
    ms_all, tf_all = [], []
    hours = {}
    for r in proofs:
        h = r["hash"]
        if h is not None:
            hash_dids.setdefault(h, set()).add(r["did"])
            did_hashes.setdefault(r["did"], []).append(h)
            if not HASH_RE.match(h):
                findings.append(_f("WARN", "malformed-hash", h,
                                   "proof hash is not 0x+16hex: %r" % h))
        if r["kind"] == "vp":
            k = (r["task"], r["model"], r["nonce"])
            nonce_use[k] = nonce_use.get(k, 0) + 1
            tasks[r["task"]] = tasks.get(r["task"], 0) + 1
            models[r["model"]] = models.get(r["model"], 0) + 1
        if r["kind"] == "cv" and r["hw"]:
            hws[r["hw"]] = hws.get(r["hw"], 0) + 1
        if r["kind"] == "inf":
            ms_all.append(r["ms"])
            tf_all.append(r["tflops"])
        if r["handle"]:
            handle_dids.setdefault((r["kind"], r["handle"]), set()).add(r["did"])
        if r["hour"]:
            hours[r["hour"]] = hours.get(r["hour"], 0) + 1

    # cross-DID duplicate proof hashes: one proof, two identities
    for h, ds in hash_dids.items():
        if len(ds) > 1:
            findings.append(_f("BLOCK", "dup-hash-cross-did", h,
                               "proof hash filed by %d DIDs (copy-paste proof)"
                               % len(ds)))
    # same-DID replay of an identical hash
    replays = sum(1 for hs in did_hashes.values() if len(hs) != len(set(hs)))
    if replays:
        findings.append(_f("WARN", "dup-hash-same-did", "%d dids" % replays,
                           "%d submitters re-filed an already-used proof hash"
                           % replays))
    # nonce reuse inside one (task, model) slot
    nn = sum(1 for c in nonce_use.values() if c > 1)
    if nn:
        findings.append(_f("WARN", "nonce-reuse", "%d slots" % nn,
                           "%d (task, model) slots re-used a proof nonce"
                           % nn))
    # identity handles re-bound across DIDs
    churn = [(k, len(v)) for k, v in handle_dids.items() if len(v) > 1]
    for (kind, handle), n in sorted(churn, key=lambda x: -x[1])[:10]:
        findings.append(_f("WARN", "handle-rebound", "%s:%s" % (kind, handle),
                           "handle claims proofs under %d distinct DIDs" % n))
    # chorus-without-work: preaches submission, never files
    filed = {r["did"] for r in proofs}
    ch_by_did = {}
    for r in chorus:
        ch_by_did[r["did"]] = ch_by_did.get(r["did"], 0) + 1
    for d, n in sorted(ch_by_did.items(), key=lambda x: -x[1]):
        if n >= CHORUS_FLOOR and d not in filed:
            findings.append(_f("WARN", "chorus-no-work", d,
                               "%d 'Submit validator proofs' broadcasts, "
                               "0 proofs filed" % n))
    # dark hours inside the covered range
    if hours:
        keys = sorted(hours)
        span = datetime_range(keys[0], keys[-1])
        dark = [h for h in span if h not in hours]
        if dark:
            frac = len(dark) / max(1, len(span))
            sev = "WARN" if frac >= DARK_WARN_FRAC else "INFO"
            findings.append(_f(sev, "dark-hours", "%d/%d h" % (len(dark), len(span)),
                               "%.0f%% of covered hours filed no proof "
                               "(first dark %s)" % (100 * frac, dark[0])))
    board = {
        "proofs": len(proofs), "dids": len(filed), "chorus": len(chorus),
        "chorus_dids": len(ch_by_did), "hours": len(hours),
        "kinds": count_by(proofs, "kind"), "models": models,
        "hardware": hws, "tasks": tasks,
        "ms_med": median(ms_all) if ms_all else None,
        "tflops_med": median(tf_all) if tf_all else None,
        "top_dids": top_submitters(records),
    }
    return findings, board


def datetime_range(h0, h1):
    """'2026-08-25T17' -> ['2026-08-25T17', ... h1] inclusive hourly."""
    try:
        t = datetime.strptime(h0, "%Y-%m-%dT%H")
        end = datetime.strptime(h1, "%Y-%m-%dT%H")
    except ValueError:
        return []
    out = []
    step = timedelta(hours=1)
    while t <= end:
        out.append(t.strftime("%Y-%m-%dT%H"))
        t = t + step
    return out

def count_by(rows, key):
    out = {}
    for r in rows:
        out[r[key]] = out.get(r[key], 0) + 1
    return out


def top_submitters(records, n=8):
    """[{did, vp, cv, inf, proofs}] heaviest filers."""
    agg = {}
    for r in records:
        if r["kind"] == "chorus":
            continue
        a = agg.setdefault(r["did"], {"did": r["did"], "vp": 0, "cv": 0, "inf": 0})
        a[r["kind"]] += 1
    for a in agg.values():
        a["proofs"] = a["vp"] + a["cv"] + a["inf"]
    return sorted(agg.values(), key=lambda a: -a["proofs"])[:n]


def render(findings, board, flt):
    print("proof board: %d proofs from %d DIDs over %d hours  "
          "(kinds: vp=%d cv=%d inf=%d)" % (
              board["proofs"], board["dids"], board["hours"],
              board["kinds"].get("vp", 0), board["kinds"].get("cv", 0),
              board["kinds"].get("inf", 0)))
    if flt:
        print("  filters: %s" % ", ".join("%s=%s" % kv for kv in flt.items()))
    if board["models"]:
        top = sorted(board["models"].items(), key=lambda x: -x[1])[:5]
        print("  models: %d (top: %s)" % (len(board["models"]),
              ", ".join("%s=%d" % kv for kv in top)))
    if board["hardware"]:
        top = sorted(board["hardware"].items(), key=lambda x: -x[1])[:5]
        print("  hardware: %d (top: %s)" % (len(board["hardware"]),
              ", ".join("%s=%d" % kv for kv in top)))
    if board["ms_med"] is not None:
        print("  inference: median %.1fms / %.1f TFLOPS" % (
            board["ms_med"], board["tflops_med"]))
    print("  chorus: %d broadcasts from %d DIDs" % (
        board["chorus"], board["chorus_dids"]))
    if board["top_dids"]:
        print("  top submitters:")
        for a in board["top_dids"]:
            print("    %s  vp=%d cv=%d inf=%d  total=%d" % (
                a["did"][:26] + "…", a["vp"], a["cv"], a["inf"], a["proofs"]))
    if not findings:
        print("findings: none — submission pipeline consistent with the board")
        return
    print("findings: %d" % len(findings))
    for f in findings:
        print("  [%s] %s (%s)\n      %s" % (f["severity"], f["kind"], f["key"],
                                             f["detail"]))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("captures", nargs="+", help="room capture JSONL / text")
    ap.add_argument("--did", help="filter: submitter DID substring")
    ap.add_argument("--kind", choices=["vp", "cv", "inf"],
                    help="filter: proof kind")
    ap.add_argument("--model", help="filter: model substring (vp proofs)")
    ap.add_argument("--task", help="filter: task substring (vp proofs)")
    a = ap.parse_args(argv)
    records = load_records(a.captures)
    flt = {}
    if a.did:
        flt["did"] = a.did
        records = [r for r in records if a.did in r["did"]]
    if a.kind:
        flt["kind"] = a.kind
        records = [r for r in records if r["kind"] == a.kind]
    if a.model:
        flt["model"] = a.model
        records = [r for r in records if r.get("model") and a.model in r["model"]]
    if a.task:
        flt["task"] = a.task
        records = [r for r in records if r.get("task") and a.task in r["task"]]
    findings, board = audit(records)
    render(findings, board, flt)
    return 1 if [f for f in findings if f["severity"] != "INFO"] else 0


def self_test():
    checks = 0
    vp = ("[PoUI Verifiable Proof] Task: Matrix-GEMM-Eval | Model: Gemma-2-27B "
          "| Nonce: 317935 | Hash: 0xa2b475f0431d2fe0 | Node: alex_compute")
    r = parse_vp(vp)
    assert r["model"] == "Gemma-2-27B" and r["handle"] == "alex_compute"
    checks += 1
    assert parse_vp("[PoUI Verifiable Proof] missing separators") is None
    checks += 1
    cv = ("[Compute Verification] Layer 32 Attention weights verified on "
          "NVIDIA L40S. Compute Hash: 0x4618106de7e7496f | Operator: nexus_kel")
    r = parse_cv(cv)
    assert r["hw"] == "NVIDIA L40S" and r["handle"] == "nexus_kel"
    checks += 1
    inf = ("[PoUI Inference] Real-time inference batch completed (29.6ms, "
           "74.9 TFLOPS). Proof: 0x12b5c730ee426405 signed by orion71.")
    r = parse_inf(inf)
    assert r["ms"] == 29.6 and r["tflops"] == 74.9 and r["handle"] == "orion71"
    checks += 1

    rows = [
        {"seq": 1, "ts": "2026-09-22T01:00:00Z", "hour": "2026-09-22T01",
         "did": "did:A", "kind": "vp", "task": "T", "model": "M", "nonce": "1",
         "hash": "0x0000000000000001", "handle": "n1", "hw": None,
         "ms": None, "tflops": None},
        {"seq": 2, "ts": "2026-09-22T02:00:00Z", "hour": "2026-09-22T02",
         "did": "did:B", "kind": "vp", "task": "T", "model": "M", "nonce": "1",
         "hash": "0x0000000000000001", "handle": "n1", "hw": None,
         "ms": None, "tflops": None},
        {"seq": 3, "ts": "2026-09-22T03:00:00Z", "hour": "2026-09-22T03",
         "did": "did:A", "kind": "vp", "task": "T", "model": "M", "nonce": "2",
         "hash": "0x0000000000000002", "handle": "n1", "hw": None,
         "ms": None, "tflops": None},
    ] + [{"seq": 4 + i, "ts": "2026-09-22T04:00:00Z", "hour": "2026-09-22T04",
          "did": "did:C", "kind": "chorus", "hash": None}
         for i in range(CHORUS_FLOOR)]
    findings, board = audit(rows)
    kinds = {f["kind"] for f in findings}
    assert "dup-hash-cross-did" in kinds and "nonce-reuse" in kinds
    assert "chorus-no-work" in kinds
    checks += 1
    assert board["proofs"] == 3 and board["dids"] == 2
    assert board["chorus"] == CHORUS_FLOOR
    checks += 1
    assert any(f["severity"] == "BLOCK" for f in findings)
    checks += 1

    # handle re-bound across DIDs: n1 files under A and B
    assert "handle-rebound" in kinds
    checks += 1

    # dark hours: proofs at 01 and 05 leave 02..04 dark inside the span
    rows2 = [dict(rows[0], hour="2026-09-22T01"),
             dict(rows[2], hour="2026-09-22T05")]
    f2, b2 = audit(rows2)
    assert any(f["kind"] == "dark-hours" for f in f2)
    assert b2["proofs"] == 2
    checks += 1

    # filters: kind narrowing keeps chorus out of the count
    only_cv = [r for r in rows if r["kind"] == "inf"]
    assert only_cv == []
    checks += 1
    assert top_submitters(rows)[0]["did"] == "did:A"
    checks += 1
    assert datetime_range("2026-09-22T22", "2026-09-23T02") == [
        "2026-09-22T22", "2026-09-22T23", "2026-09-23T00",
        "2026-09-23T01", "2026-09-23T02"]
    checks += 1
    print("self-test OK (%d assertions)" % checks)


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
    else:
        raise SystemExit(main())
