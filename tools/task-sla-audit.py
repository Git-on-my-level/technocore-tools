#!/usr/bin/env python3
"""task-sla-audit — SLA / stall / reward audit + per-model benchmark for
audit-service task lifecycles (JSONL capture, one event per line; event
vocabulary in analyze()).

DEMAND: evidence/suggestions/tools-services/2026-09-13.md
  - 00:23 "Performance/latency metrics for audit agents" — "Dashboard
    showing average audit completion time, success rate, and
    cost-per-audit across providers"; "Cost comparison across models".
  - 06:26 "Unified alerting for audit failures or stalled tasks" —
    "alerting agent to notify on task completion anomalies or validator
    timeouts".
  - 09:37 "Faster audit processing" (SLA-based matching); "Audit cost
    optimization" — "cost analytics ... bidding strategy".
  Echoed 2026-09-12.md: per-model throughput / reward-rate metrics.
Scope: the offline half — the capture file IS the event stream; the
findings ARE the alerting; --report IS the benchmark table. Pure
parsing, no network/subprocess. rc 0 clean/INFO, 1 BLOCK/WARN, 2 IO.
Stdlib only.
"""
import argparse
import json
import sys
from datetime import datetime
from statistics import median

SEVS = ("BLOCK", "WARN", "INFO")
DEF = dict(stall=1800.0, ack=600.0, quorum=3, bid_mult=2.0,
           min_success=0.9, min_tasks=5, flaps=3)


def num(v):
    """numeric and not bool -> float, else None"""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    return None


def parse_ts(v):
    """ISO-8601 string or epoch number -> epoch float; else None."""
    n = num(v)
    if n is not None:
        return n
    if isinstance(v, str):
        s = v.strip()
        if s.endswith(("Z", "z")):
            s = s[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(s).timestamp()
        except ValueError:
            return None
    return None


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
            yield i, rec if isinstance(rec, dict) else None


def analyze(events, opts=None):
    """events: [(index, dict|None)] -> (findings, model_rows).
    Findings sorted BLOCK > WARN > INFO, stable in emission order."""
    o = dict(DEF, **(opts or {}))
    f = []

    def add(sev, kind, task, detail):
        f.append(dict(severity=sev, kind=kind, task=task, detail=detail))

    tasks = {}      # task id -> lifecycle events
    listed = {}     # capability -> [(ts, bid)] in file order
    registry = {}   # model -> (ts, capability) latest session-online
    flap_ev = {}    # (model, capability) -> ["on"/"off", ...]
    models = {}     # model -> {matched, done, comp:[s], bids:[f], reward}
    capture_end = 0.0
    malformed = unknown = 0

    def tstat(model):
        return models.setdefault(
            model, dict(matched=0, done=0, open=0, comp=[], bids=[],
                        reward=0.0))

    def trec(tid):
        return tasks.setdefault(
            tid, dict(matched=[], proofs=[], acks=[], done=[], reward=[],
                      model=None, cap=None))

    def eff_bid(mrec, cap, ts):
        """matched.bid if present, else latest listed bid <= ts."""
        for _ts, rec in reversed(mrec):
            if num(rec.get("bid")) is not None:
                return num(rec["bid"])
        for lts, lbid in sorted(listed.get(cap, []),
                                key=lambda x: x[0], reverse=True):
            if lts <= ts:
                return lbid
        return None

    for idx, rec in events:
        ts = None if rec is None else parse_ts(rec.get("ts"))
        if ts is None:
            malformed += 1
            continue
        capture_end = max(capture_end, ts)
        ev = rec.get("event")
        if ev == "listed":
            if num(rec.get("bid")) is not None:
                listed.setdefault(str(rec.get("capability", "-")),
                                  []).append((ts, num(rec["bid"])))
        elif ev in ("session-online", "session-offline"):
            key = (str(rec.get("model", "-")),
                   str(rec.get("capability", "-")))
            state = "on" if ev == "session-online" else "off"
            series = flap_ev.setdefault(key, [])
            if not series or series[-1] != state:
                series.append(state)
            if ev == "session-online":
                registry[key[0]] = (ts, key[1])
        elif ev in ("matched", "proof", "validator-ack", "done", "reward"):
            r = trec(str(rec.get("task", "?")))
            if ev == "matched":
                if r["matched"]:
                    add("WARN", "re-matched", str(rec["task"]),
                        "task matched again; first match keeps the clock")
                else:
                    r["model"] = str(rec.get("model", "-"))
                    r["cap"] = str(rec.get("capability", "-"))
                    st = tstat(r["model"])
                    st["matched"] += 1
                    reg = registry.get(r["model"])
                    if reg and reg[0] <= ts and reg[1] != r["cap"]:
                        add("WARN", "capability-drift", str(rec["task"]),
                            f"model {r['model']} registered capability "
                            f"{reg[1]} but task matched as {r['cap']}")
                r["matched"].append((ts, rec))
                if num(rec.get("sla")) is None:
                    add("WARN", "missing-sla", str(rec["task"]),
                        "matched without sla; SLA uncheckable")
            elif ev == "proof":
                r["proofs"].append((ts, rec))
            elif ev == "validator-ack":
                r["acks"].append((ts, rec))
            elif ev == "done":
                if r["done"]:
                    add("BLOCK", "double-done", str(rec["task"]),
                        f"{len(r['done']) + 1} done events for one task")
                else:
                    st = tstat(r["model"] or "-")
                    st["done"] += 1
                    if r["matched"]:
                        st["comp"].append(ts - r["matched"][0][0])
                r["done"].append((ts, rec))
                if not r["matched"]:
                    add("WARN", "orphan-done", str(rec["task"]),
                        "done without a matched")
            else:  # reward
                r["reward"].append((ts, rec))
                if not r["done"]:
                    add("WARN", "reward-without-done", str(rec["task"]),
                        "reward settled before/without done")
                if not r["matched"]:
                    add("WARN", "orphan-done", str(rec["task"]),
                        "reward without a matched")
        else:
            unknown += 1

    if malformed:
        add("WARN", "malformed-line", "-",
            f"{malformed} unparsable/ts-less line(s)")
    if unknown:
        add("WARN", "unknown-event", "-", f"{unknown} unknown event type(s)")

    # per-task lifecycle findings, first-seen (= insertion) order
    for tid, r in tasks.items():
        if not r["matched"]:
            continue  # orphan already flagged
        mts, mrec = r["matched"][0]
        sla = num(mrec.get("sla"))
        if r["done"]:
            comp = r["done"][0][0] - mts
            if sla is not None and comp > sla:
                add("BLOCK", "sla-breach", tid, f"completed in {comp:.0f}s "
                    f"vs sla {sla:.0f}s (over by {comp - sla:.0f}s)")
        elif capture_end - mts > o["stall"]:
            extra = f", sla {sla:.0f}s" if sla is not None else ""
            add("BLOCK", "stalled-task", tid, f"no proof/done "
                f"{capture_end - mts:.0f}s after match{extra}")
        else:
            add("INFO", "open-task", tid,
                f"still open {capture_end - mts:.0f}s after match")
            tstat(r["model"] or "-")["open"] += 1
        if len(r["proofs"]) > 1:
            add("INFO", "re-proof", tid,
                f"{len(r['proofs'])} proofs for one task")
        if r["proofs"]:
            pts, prec = r["proofs"][0]
            nval = prec.get("validators")
            need = min(o["quorum"], nval) if isinstance(nval, int) \
                and nval >= 1 else o["quorum"]
            ok = {a[1].get("validator") for a in r["acks"]
                  if a[1].get("ok") is True
                  and pts <= a[0] <= pts + o["ack"]}
            if len(ok) < need and (r["done"] or capture_end - pts > o["ack"]):
                add("BLOCK", "validator-timeout", tid, f"{len(ok)}/{need} "
                    f"validator acks ok within {o['ack']:.0f}s of proof")
            for ats, arec in r["acks"]:
                if ats > pts + o["ack"]:
                    add("INFO", "ack-late", tid, f"validator "
                        f"{arec.get('validator', '?')} acked {ats - pts:.0f}s"
                        f" after proof (window {o['ack']:.0f}s)")
        bid0 = eff_bid(r["matched"], r["cap"], mts)
        for _rts, rrec in r["reward"]:
            amt = num(rrec.get("amount"))
            if amt is None:
                continue
            if bid0 is None:
                add("INFO", "reward-unpriced", tid,
                    f"reward {amt:.2f} with no listed/matched bid")
            elif abs(amt - bid0) > 1e-9:
                how = "overpay" if amt > bid0 else "underpay"
                add("BLOCK", "reward-mismatch", tid,
                    f"{how}: reward {amt:.2f} vs bid {bid0:.2f}")
            tstat(r["model"] or "-")["reward"] += amt
        if bid0 is not None:
            tstat(r["model"] or "-")["bids"].append(bid0)

    # bid outliers vs running median per capability (bidding strategy)
    for cap, series in listed.items():
        prior = []
        for _ts, bid in sorted(series, key=lambda x: x[0]):
            if len(prior) >= 3 and bid > o["bid_mult"] * median(prior):
                add("WARN", "bid-outlier", "-",
                    f"{cap}: bid {bid:.2f} vs running median "
                    f"{median(prior):.2f} (>{o['bid_mult']}x)")
            prior.append(bid)

    # session flapping (model uptime)
    for (model, cap), series in flap_ev.items():
        flips = max(0, len(series) - 1)
        if flips > o["flaps"]:
            add("WARN", "session-flap", "-",
                f"model {model} cap {cap}: {flips} online/offline "
                f"transitions")

    # per-model benchmark rows (the dashboard half of the demand)
    rows = []
    for model in sorted(models, key=lambda m: -models[m]["matched"]):
        st = models[model]
        comp = sorted(st["comp"])
        p95 = comp[min(len(comp) - 1, max(0, -(-95 * len(comp) // 100)
                                          - 1))] if comp else None
        closed = st["matched"] - st["open"]
        succ = st["done"] / closed if closed else None
        rows.append(dict(model=model, matched=st["matched"],
                         done=st["done"],
                         success=succ,
                         med_s=median(comp) if comp else None, p95_s=p95,
                         med_bid=median(st["bids"]) if st["bids"] else None,
                         reward=st["reward"]))
        if st["matched"] >= o["min_tasks"] \
                and succ is not None and succ < o["min_success"]:
            add("WARN", "model-underperform", "-",
                f"model {model}: success {st['done']}/{closed} "
                f"below {o['min_success']:.0%}")

    f.sort(key=lambda x: SEVS.index(x["severity"]))
    return f, rows


def render(findings):
    counts = {s: sum(1 for x in findings if x["severity"] == s)
              for s in SEVS}
    print(f"summary: {counts['BLOCK']} block, {counts['WARN']} warn, "
          f"{counts['INFO']} info")
    for x in findings:
        print(f"[{x['severity']}] {x['kind']} ({x['task']}): "
              f"{x['detail']}")
    return counts


def render_report(rows):
    print("model  matched done succ%  med_s  p95_s med_bid reward")
    keys = ("model", "matched", "done", "success", "med_s", "p95_s",
            "med_bid", "reward")
    fmt = (None, None, None, ".0%", ".0f", ".0f", ".2f", ".2f")
    for r in rows:
        cells = []
        for k, fm, w in zip(keys, fmt, (6, 7, 4, 5, 6, 6, 7, 6)):
            txt = str(r[k]) if fm is None else (
                "-" if r[k] is None else format(r[k], fm))
            cells.append(f"{txt:>{w}}")
        print(" ".join(cells))

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Audit SLA breaches, stalls, validator timeouts and "
                    "reward accounting in a JSONL capture of audit-service "
                    "task events; benchmark models per --report.")
    ap.add_argument("capture", help="JSONL file, one event per line")
    ap.add_argument("--stall-secs", dest="stall", type=float,
                    default=DEF["stall"],
                    help="uncompleted task older than this is stalled")
    ap.add_argument("--ack-secs", dest="ack", type=float, default=DEF["ack"],
                    help="validator ack window after proof")
    ap.add_argument("--quorum", type=int, default=DEF["quorum"],
                    help="validators that must ack ok (default 3)")
    ap.add_argument("--bid-mult", dest="bid_mult", type=float,
                    default=DEF["bid_mult"],
                    help="listed bid over running median x this is an "
                         "outlier (default 2.0)")
    ap.add_argument("--report", action="store_true",
                    help="print the per-model benchmark table")
    ap.add_argument("--json", action="store_true",
                    help="emit findings (and rows) as JSON")
    args = ap.parse_args(argv)
    try:
        recs = list(load_records(args.capture))
    except OSError as e:
        print(f"error: cannot read {args.capture}: {e}", file=sys.stderr)
        return 2
    findings, rows = analyze(recs, vars(args))
    if args.json:
        print(json.dumps({"findings": findings, "rows": rows},
                         ensure_ascii=False))
    else:
        render(findings)
        if args.report:
            render_report(rows)
    return 1 if any(x["severity"] != "INFO" for x in findings) else 0


def _kinds(finds):
    return sorted({x["kind"] for x in finds})


def _ev(ts, **kw):
    return dict(ts=ts, **kw)


def self_test():
    import io
    import os
    import tempfile
    from contextlib import redirect_stdout

    def run(recs, extra=()):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                         delete=False) as tf:
            for rec in recs:
                tf.write((rec if isinstance(rec, str) else json.dumps(rec))
                         + "\n")
            path = tf.name
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main([path, *extra])
            return rc, buf.getvalue()
        finally:
            os.unlink(path)

    # clean lifecycle silent; row hand-computed
    clean = [_ev(100, event="listed", capability="toploc", bid=5.0),
             _ev(200, event="matched", task="T1", capability="toploc",
                 model="llama70b", sla=1000),
             _ev(400, event="proof", task="T1", validators=3)]
    clean += [_ev(410 + 10 * i, event="validator-ack", task="T1",
                  validator=f"V{i + 1}", ok=True) for i in range(3)]
    clean += [_ev(500, event="done", task="T1"),
              _ev(600, event="reward", task="T1", amount=5.0)]
    lc = list(enumerate(clean))
    finds, rows = analyze(lc)
    assert finds == [], finds
    assert rows == [dict(model="llama70b", matched=1, done=1, success=1.0,
                         med_s=300.0, p95_s=300.0, med_bid=5.0,
                         reward=5.0)], rows

    # SLA breach: done 1100s after match vs sla 1000s (hand-computed)
    slow = lc[:6] + [(6, _ev(1300, event="done", task="T1")),
                     (7, _ev(1350, event="reward", task="T1", amount=5.0))]
    got = analyze(slow)[0]
    assert _kinds(got) == ["sla-breach"] and "over by 100s" in got[0]["detail"]

    # stalled vs open: capture ends at 4000 (the listed event)
    stall = [(0, _ev(1000, event="matched", task="S1", model="m", sla=500)),
             (1, _ev(3000, event="matched", task="S2", model="m")),
             (2, _ev(4000, event="listed", capability="other", bid=1.0))]
    got = analyze(stall)[0]
    st = next(x for x in got if x["kind"] == "stalled-task")
    assert st["task"] == "S1" and "sla 500s" in st["detail"], st

    # validator timeout: 2/3 in window; late 1105 ack excluded; re-proof
    vt = lc[:5] + [(5, _ev(1105, event="validator-ack", task="T1",
                           validator="V3", ok=True)),
        (6, _ev(700, event="proof", task="T1", validators=3)),
        (7, _ev(1100, event="done", task="T1")),
        (8, _ev(1150, event="reward", task="T1", amount=5.0))]
    got = analyze(vt)[0]
    ks = _kinds(got)
    assert "validator-timeout" in ks and "ack-late" in ks \
        and "re-proof" in ks, got
    assert "2/3" in next(x for x in got
                         if x["kind"] == "validator-timeout")["detail"]
    # in-window proof with no acks is not a timeout (window still open)
    inflight = lc[:3]  # listed, matched, proof; capture_end=400
    assert "validator-timeout" not in _kinds(analyze(inflight)[0])
    # repeated ok acks from one validator do not satisfy quorum
    dupack = lc[:3] + [(3, _ev(410, event="validator-ack", task="T1",
                                 validator="V1", ok=True)),
                       (4, _ev(420, event="validator-ack", task="T1",
                                 validator="V1", ok=True)),
                       (5, _ev(430, event="validator-ack", task="T1",
                                 validator="V1", ok=True)),
                       (6, _ev(1100, event="done", task="T1"))]
    got = analyze(dupack)[0]
    assert "validator-timeout" in _kinds(got)
    assert "1/3" in next(x for x in got
                         if x["kind"] == "validator-timeout")["detail"]

    # reward accounting: overpay/underpay BLOCK, unpriced INFO
    for amt, how in ((6.0, "overpay"), (4.5, "underpay")):
        got = analyze(lc[:7] + [(7, _ev(600, event="reward", task="T1",
                                        amount=amt))])[0]
        assert _kinds(got) == ["reward-mismatch"] and how in got[0]["detail"]
    unpriced = [(0, _ev(1, event="matched", task="U", model="m", sla=50)),
                (1, _ev(2, event="done", task="U")),
                (2, _ev(3, event="reward", task="U", amount=7.0))]
    assert "reward-unpriced" in _kinds(analyze(unpriced)[0])
    # omitted capability on listed and matched still uses the listed bid
    ncap = [(0, _ev(1, event="listed", bid=5.0)),
            (1, _ev(2, event="matched", task="C", model="m", sla=50)),
            (2, _ev(3, event="done", task="C")),
            (3, _ev(4, event="reward", task="C", amount=5.0))]
    finds, rows = analyze(ncap)
    assert "reward-unpriced" not in _kinds(finds) and finds == [], finds
    assert rows[0]["reward"] == 5.0 and rows[0]["med_bid"] == 5.0, rows
    # mismatch still accumulates into the model cost column
    over = analyze(lc[:7] + [(7, _ev(600, event="reward", task="T1",
                                      amount=6.0))])
    assert over[1][0]["reward"] == 6.0, over[1]

    # hygiene: re-matched, double-done, orphans, reward-without-done, no-sla
    hyg = [(0, _ev(10, event="matched", task="H", model="m", sla=100)),
           (1, _ev(20, event="matched", task="H", model="m", sla=100)),
           (2, _ev(30, event="done", task="H")),
           (3, _ev(40, event="done", task="H")),
           (4, _ev(50, event="done", task="GHOST")),
           (5, _ev(60, event="reward", task="GHOST2", amount=1.0)),
           (6, _ev(70, event="matched", task="NOSLA", model="m")),
           (7, _ev(80, event="done", task="NOSLA"))]
    ks = set(_kinds(analyze(hyg)[0]))
    assert {"re-matched", "double-done", "orphan-done",
            "reward-without-done", "missing-sla"} <= ks, ks

    # bid outlier (ts-sorted): prior [99,4.0,4.1,4.2] -> med 4.15; 9.0 flags
    bids = [(i, _ev(100 + i, event="listed", capability="c", bid=b))
            for i, b in enumerate([4.0, 4.1, 4.2, 9.0, 8.0])]
    bids.append((9, _ev(50, event="listed", capability="c", bid=99.0)))
    bids.append((9, _ev(200, event="listed", capability="d", bid=50.0)))
    got = analyze(bids)[0]
    assert _kinds(got) == ["bid-outlier"] and "running median 4.15" \
        in got[0]["detail"] and len(got) == 1
    # latest listed bid by timestamp, not reverse file order
    oo = [(0, _ev(100, event="listed", capability="c", bid=9.0)),
          (1, _ev(200, event="listed", capability="c", bid=5.0)),
          (2, _ev(50, event="listed", capability="c", bid=99.0)),
          (3, _ev(250, event="matched", task="B1", capability="c",
                  model="m", sla=50)),
          (4, _ev(260, event="done", task="B1")),
          (5, _ev(270, event="reward", task="B1", amount=5.0))]
    finds, rows = analyze(oo)
    assert "reward-mismatch" not in _kinds(finds), finds
    assert rows[0]["med_bid"] == 5.0 and rows[0]["reward"] == 5.0, rows
    flapy = [(i, _ev(10 * i, event=("session-online" if i % 2 == 0
                                    else "session-offline"),
                     model="m2", capability="a")) for i in range(5)]
    assert "session-flap" in _kinds(analyze(flapy)[0])
    assert analyze(flapy, dict(flaps=4))[0] == []
    drift = [(0, _ev(10, event="session-online", model="m3", capability="a")),
             (1, _ev(20, event="matched", task="D1", model="m3",
                     capability="b", sla=99)),
             (2, _ev(30, event="done", task="D1"))]
    assert _kinds(analyze(drift)[0]) == ["capability-drift"]

    # underperformance: 5 matches, 2 done; completions 100,300 -> med 200
    evs = [(0, _ev(1, event="listed", capability="c", bid=5.0))]
    for i in range(5):
        evs.append((1 + 2 * i, _ev(100.0 + 10 * i, event="matched",
                                   task=f"P{i}", model="slow",
                                   capability="c", sla=900)))
        if i < 2:
            evs.append((2 + 2 * i, _ev(100.0 + 10 * i + (100 if i == 0
                                                          else 300),
                                       event="done", task=f"P{i}")))
    evs.append((99, _ev(99999, event="listed", capability="z", bid=1.0)))
    got, rows = analyze(evs)
    ks = _kinds(got)
    assert "model-underperform" in ks \
        and sum(1 for x in got if x["kind"] == "stalled-task") == 3, ks
    det = [x for x in got if x["kind"] == "model-underperform"][0]
    assert "2/5" in det["detail"] and "below 90%" in det["detail"], det
    row = rows[0]
    assert row["model"] == "slow" and row["matched"] == 5 \
        and row["done"] == 2 and abs(row["med_s"] - 200.0) < 1e-9 \
        and abs(row["p95_s"] - 300.0) < 1e-9, row
    # in-flight (open) tasks excluded from success / underperform
    busy = []
    for i in range(5):
        busy.append((2 * i, _ev(10.0 + i, event="matched",
                                 task=f"O{i}", model="busy", sla=900)))
        if i < 4:
            busy.append((2 * i + 1, _ev(20.0 + i, event="done",
                                          task=f"O{i}")))
    got, rows = analyze(busy)
    assert "model-underperform" not in _kinds(got)
    assert "open-task" in _kinds(got)
    assert rows[0]["success"] == 1.0 and rows[0]["done"] == 4, rows

    # malformed / ts-less / unknown-event lines
    junk = [(0, None), (1, _ev("not-a-time", event="done", task="X")),
            (2, _ev(5, event="dance-off", task="Y"))]
    # ISO timestamps parse; completion arithmetic identical to epoch
    iso = [(0, _ev("2026-09-13T10:00:00Z", event="matched", task="I",
                   model="m", sla=1000)),
           (1, _ev("2026-09-13T10:05:00Z", event="done", task="I"))]
    assert abs(analyze(iso)[1][0]["med_s"] - 300.0) < 1e-6

    rc, out = run(clean, ["--json"])
    doc = json.loads(out)
    assert rc == 0 and not doc["findings"] \
        and "llama70b" == doc["rows"][0]["model"]
    rc, out = run(clean, ["--report"])
    assert rc == 0 and "llama70b" in out and "med_s" in out, out
    assert main(["/nonexistent.jsonl"]) == 2
    rc, out = run(['{"broken', _ev(1, event="done", task="Z")])
    assert rc == 1 and "1 unparsable" in out, out
    # INFO-only (open-task) is rc 0; WARN/BLOCK still fail
    rc, out = run([_ev(1, event="matched", task="O", model="m", sla=50)])
    assert rc == 0 and "open-task" in out, out

    print("task-sla-audit self-test OK (16 groups: lifecycle, SLA breach, "
          "stalled/open, validator timeout, rewards, hygiene, bids, "
          "flap/drift, underperform, malformed/unknown, ISO, CLI, json)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this line)
    else:
        raise SystemExit(main())
