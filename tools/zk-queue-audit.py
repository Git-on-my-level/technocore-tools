#!/usr/bin/env python3
"""zk-queue-audit — capacity / queue-depth / per-prover throughput audit
for the zk_audit proving pipeline (JSONL capture, one event per line;
event vocabulary in analyze()).

DEMAND: evidence/suggestions/tools-services/2026-09-14.md
  - "Real-time zk_audit capacity monitoring and queue visibility" —
    "the queue times were all over the place" / "confirm what our
    current zk_audit proof capacity looks like per epoch" — per-epoch
    capacity, queue depth, per-prover throughput metrics.
  - "Capacity reservation / slot-locking for zk_audit runs" — "lock
    capacity now... queuing behind larger batches".
  - "Scaling / auto-provisioning of zk_audit verifiers" — "spin up
    [more nodes]" when "queue times double" / thresholds breached.
  Echoed: "status endpoint with queue depth, proofs/cycle, wait times".
Scope: the offline half — the capture IS the event stream; --report IS
the dashboard; findings ARE the alerts. Pure parsing. rc 0 clean/INFO,
1 BLOCK/WARN, 2 IO. Stdlib only.
"""

import argparse
import json
import sys
from datetime import datetime
from statistics import median

SEVS = ("BLOCK", "WARN", "INFO")
DEF = dict(wait=900.0, depth=10, flaps=3, idle=1800.0, late=600.0)


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
    """events: [(index, dict|None)] -> (findings, epoch_rows, prover_rows).
    Findings sorted BLOCK > WARN > INFO, stable in emission order."""
    o = dict(DEF, **(opts or {}))
    f = []

    def add(sev, kind, key, detail):
        f.append(dict(severity=sev, kind=kind, proof=key, detail=detail))

    evs, malformed, unknown = [], 0, 0
    for idx, rec in events:
        ts = None if rec is None else parse_ts(rec.get("ts"))
        if ts is None:
            malformed += 1
            continue
        evs.append((ts, idx, rec))
    evs.sort(key=lambda x: (x[0], x[1]))  # stable: depth needs a timeline
    start = evs[0][0] if evs else 0.0
    end = evs[-1][0] if evs else 0.0
    span = end - start
    epochs, proofs, provs, prov_series = {}, {}, {}, {}
    depth_tl, depth, prev, cur = [], 0, 0, None

    def erec(eid):
        return epochs.setdefault(eid, dict(
            open=None, close=None, capacity=None, reserved=0.0, submitted=0,
            verified=0, vts=[], depth_max=0, waits=[]))

    def prec(pid):
        return proofs.setdefault(pid, dict(
            submit=None, pickups=[], proved=[], verified=[], prover=None,
            epoch=None))

    def pstat(p):
        return provs.setdefault(p, dict(
            pickups=0, proved=0, prove_s=[], pickups_at=[], flips=0))

    def bump_depth(ts, delta):
        nonlocal depth, prev
        depth = max(0, depth + delta)
        depth_tl.append((ts, depth))
        if cur is not None:
            e = erec(cur)
            e["depth_max"] = max(e["depth_max"], depth)
        if delta > 0 and prev < o["depth"] <= depth:
            add("WARN", "depth-spike", "-",
                f"queue depth {depth} crossed {o['depth']:.0f}"
                + (f" in epoch {cur}" if cur else ""))
        prev = depth

    for ts, _idx, rec in evs:
        ev = rec.get("event")
        pid = str(rec.get("proof", "?"))
        if ev == "epoch-open":
            eid = str(rec.get("epoch", "?"))
            if cur is None:
                cur = eid
                erec(eid)["open"] = ts
        elif ev == "epoch-close":
            eid = str(rec.get("epoch", "?"))
            e = erec(eid)
            e["close"] = ts
            cap = num(rec.get("capacity"))
            if cap is None:
                add("WARN", "uncapped-epoch", "-",
                    f"epoch {eid} closed w/o declared capacity")
            else:
                e["capacity"] = cap
                if e["reserved"] > cap:
                    add("BLOCK", "oversubscribed", "-",
                        f"epoch {eid}: reservations {e['reserved']:.0f} "
                        f"vs capacity {cap:.0f}")
                if e["verified"] > cap:
                    add("BLOCK", "capacity-exceed", "-",
                        f"epoch {eid}: {e['verified']} proofs verified "
                        f"vs capacity {cap:.0f}")
                if e["verified"] < e["reserved"]:
                    add("INFO", "unused-reserve", "-",
                        f"epoch {eid}: reserved {e['reserved']:.0f}, "
                        f"verified {e['verified']} "
                        f"({e['reserved'] - e['verified']:.0f} slots idle)")
            if cur == eid:
                cur = None
        elif ev == "submit":
            r = prec(pid)
            first = r["submit"] is None
            r["submit"] = ts if first else r["submit"]
            r["epoch"] = cur if r["epoch"] is None else r["epoch"]
            # first wait only: retries / dup lines must not add phantom slots
            if first and not r["pickups"] and not r["verified"]:
                if cur is not None:
                    erec(cur)["submitted"] += 1
                bump_depth(ts, +1)
        elif ev == "pickup":
            r = prec(pid)
            waiting = (r["submit"] is not None and not r["pickups"]
                       and not r["verified"])
            p = str(rec.get("prover", "-"))
            st = pstat(p)
            st["pickups"] += 1
            st["pickups_at"].append(ts)
            r["pickups"].append(ts)
            r["prover"] = p
            if r["submit"] is None:
                add("WARN", "orphan-pickup", pid, "pickup without a submit")
            else:
                wait = ts - r["submit"]
                if r["epoch"] is not None:
                    erec(r["epoch"])["waits"].append(wait)
                if wait > o["wait"]:
                    add("BLOCK", "starved-proof", pid, f"waited {wait:.0f}s for"
                        f" pickup (max {o['wait']:.0f}s)")
            if waiting:
                bump_depth(ts, -1)
        elif ev == "proved":
            r = prec(pid)
            st = pstat(str(rec.get("prover", "-")))
            st["proved"] += 1
            secs = num(rec.get("secs"))
            if secs is None and r["pickups"]:
                secs = ts - r["pickups"][-1]
            if secs is not None:
                st["prove_s"].append(secs)
            if len(r["proved"]) >= 1:
                add("INFO", "re-proved", pid, f"{len(r['proved']) + 1} proved"
                    f" events for one proof")
            r["proved"].append(ts)
        elif ev == "verified":
            r = prec(pid)
            eid = rec.get("epoch", cur)
            first = not r["verified"]
            if not first:
                add("WARN", "double-verify", pid,
                    f"{len(r['verified']) + 1} verified events")
            if not r["proved"]:
                add("WARN", "verify-without-prove", pid,
                    "verified before any proved")
            elif ts - r["proved"][-1] > o["late"]:
                add("INFO", "late-verify", pid, f"verified {ts - r['proved'][-1]:.0f}s"
                    f" after proved (window {o['late']:.0f}s)")
            r["verified"].append(ts)
            if first:
                if r["submit"] is not None and not r["pickups"]:
                    bump_depth(ts, -1)  # completed with dropped pickup
                if eid is None:
                    add("INFO", "verify-unattributed", pid, "verified with no"
                        " epoch and none open")
                else:
                    e = erec(str(eid))
                    e["verified"] += 1
                    e["vts"].append(ts)
                    if e["close"] is not None and ts > e["close"]:
                        add("BLOCK", "epoch-overrun", "-", f"epoch {eid}: "
                            f"proof verified {ts - e['close']:.0f}s after close")
        elif ev in ("prover-online", "prover-offline"):
            p = str(rec.get("prover", "-"))
            state = "on" if ev == "prover-online" else "off"
            series = prov_series.setdefault(p, [])
            if not series or series[-1] != state:
                series.append(state)
        elif ev == "reserve":
            e = erec(str(rec.get("epoch", "?")))
            e["open"] = e["open"] or ts
            slots = num(rec.get("slots"))
            if slots is not None:
                e["reserved"] += slots
        else:
            unknown += 1

    if malformed:
        add("WARN", "malformed-line", "-",
            f"{malformed} unparsable/ts-less line(s)")
    if unknown:
        add("WARN", "unknown-event", "-", f"{unknown} unknown event type(s)")

    # end-of-capture lifecycle
    for pid, r in proofs.items():
        if r["submit"] is None:
            continue  # orphan pickup already flagged
        if r["verified"]:
            continue  # done, even if the pickup line was dropped
        if not r["pickups"]:
            if end - r["submit"] > o["wait"]:
                add("BLOCK", "starved-proof", pid,
                    f"never picked up {end - r['submit']:.0f}s after "
                    f"submit (max {o['wait']:.0f}s)")
            else:
                add("INFO", "queued-proof", pid,
                    f"still queued {end - r['submit']:.0f}s after submit")
        else:
            add("INFO", "open-proof", pid, f"picked up but unverified "
                f"{end - r['submit']:.0f}s after submit")

    # flapping + idle-while-backlog (the auto-scale trigger): during any
    # maximal run of queue depth >= threshold, a known prover that took
    # nothing the whole run left capacity on the table
    for p, series in prov_series.items():
        flips = max(0, len(series) - 1)
        pstat(p)["flips"] = flips
        if flips > o["flaps"]:
            add("WARN", "prover-flap", "-", f"prover {p}: {flips} "
                f"online/offline transitions")
    runs, run_start = [], None
    for t, d in depth_tl:
        if d >= o["depth"] and run_start is None:
            run_start = t
        elif d < o["depth"] and run_start is not None:
            runs.append((run_start, t))
            run_start = None
    if run_start is not None:
        runs.append((run_start, end))
    for t1, t2 in runs:
        if t2 - t1 < o["idle"]:
            continue
        for p in sorted(set(provs) | set(prov_series)):
            if not any(t1 < u <= t2
                       for u in provs[p]["pickups_at"] if p in provs):
                add("WARN", "idle-while-backlog", "-", f"prover {p} took"
                    f" nothing for {t2 - t1:.0f}s (>= {o['idle']:.0f}s) while"
                    f" queue depth stayed >= {o['depth']:.0f}")

    rows = []
    for eid, e in epochs.items():
        waits = sorted(e["waits"])
        p95 = waits[min(len(waits) - 1, max(0, -(-95 * len(waits) // 100)
                                            - 1))] if waits else None
        rows.append(dict(epoch=eid, capacity=e["capacity"],
                         reserved=e["reserved"], submitted=e["submitted"],
                         verified=e["verified"], max_depth=e["depth_max"],
                         util=(e["verified"] / e["capacity"]
                               if e["capacity"] else None),
                         med_wait=median(waits) if waits else None,
                         p95_wait=p95))
    prows = []
    for p in sorted(provs, key=lambda x: -provs[x]["pickups"]):
        st = provs[p]
        prows.append(dict(prover=p, pickups=st["pickups"], proved=st["proved"],
                          med_prove=(median(st["prove_s"]) if st["prove_s"]
                                     else None),
                          per_hour=(st["pickups"] / span * 3600.0
                                    if span > 0 else None),
                          flips=st["flips"]))
    f.sort(key=lambda x: SEVS.index(x["severity"]))
    return f, rows, prows


def render(findings):
    counts = {s: sum(1 for x in findings if x["severity"] == s)
              for s in SEVS}
    print(f"summary: {counts['BLOCK']} block, {counts['WARN']} warn, "
          f"{counts['INFO']} info")
    for x in findings:
        print(f"[{x['severity']}] {x['kind']} ({x['proof']}): {x['detail']}")
    return counts


def _table(rows, spec):
    print(" ".join(k for k, _fm in spec))
    for r in rows:
        print(" ".join(str(r[k]) if fm is None else
                       ("-" if r[k] is None else format(r[k], fm))
                       for k, fm in spec))


def render_report(epochs, provers):
    _table(epochs,
           [("epoch", None), ("capacity", ".0f"), ("reserved", ".0f"),
            ("submitted", None), ("verified", None), ("util", ".0%"),
            ("max_depth", None), ("med_wait", ".0f"), ("p95_wait", ".0f")])
    _table(provers,
           [("prover", None), ("pickups", None), ("proved", None),
            ("med_prove", ".0f"), ("per_hour", ".2f"), ("flips", None)])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("capture", help="JSONL file, one event per line")
    ap.add_argument("--wait-secs", dest="wait", type=float, default=DEF["wait"])
    ap.add_argument("--depth", type=int, default=DEF["depth"])
    ap.add_argument("--flaps", type=int, default=DEF["flaps"])
    ap.add_argument("--idle-secs", dest="idle", type=float, default=DEF["idle"])
    ap.add_argument("--late-secs", dest="late", type=float, default=DEF["late"])
    ap.add_argument("--report", action="store_true",
                    help="print epoch + prover dashboard tables")
    ap.add_argument("--json", action="store_true",
                    help="emit findings (and rows) as JSON")
    args = ap.parse_args(argv)
    try:
        recs = list(load_records(args.capture))
    except OSError as e:
        print(f"error: cannot read {args.capture}: {e}", file=sys.stderr)
        return 2
    findings, epochs, provers = analyze(recs, vars(args))
    if args.json:
        print(json.dumps({"findings": findings, "epochs": epochs,
                          "provers": provers}, ensure_ascii=False))
    else:
        render(findings)
        if args.report:
            render_report(epochs, provers)
    return 1 if any(x["severity"] != "INFO" for x in findings) else 0


def _kinds(finds):
    return sorted({x["kind"] for x in finds})


def _ev(ts, **kw):
    return dict(ts=ts, **kw)  # fixture builder


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


    # clean pipeline silent; epoch + prover rows hand-computed
    clean = [_ev(100, event="epoch-open", epoch="e1"),
             _ev(150, event="prover-online", prover="A"),
             _ev(200, event="submit", proof="P1"),
             _ev(500, event="pickup", proof="P1", prover="A"),
             _ev(800, event="proved", proof="P1", prover="A", secs=300),
             _ev(900, event="verified", proof="P1", epoch="e1"),
             _ev(1000, event="epoch-close", epoch="e1", capacity=10)]
    lc = list(enumerate(clean))
    finds, erows, prows = analyze(lc)
    assert finds == [], finds
    assert erows == [dict(epoch="e1", capacity=10.0, reserved=0.0,
                          submitted=1, verified=1, util=0.1, max_depth=1,
                          med_wait=300.0, p95_wait=300.0)], erows
    assert prows == [dict(prover="A", pickups=1, proved=1,
                          med_prove=300.0, per_hour=4.0, flips=0)], prows

    # starved: pickup 1000s after submit vs max 900 (hand-computed)
    slow = lc[:3] + [(3, _ev(1200, event="pickup", proof="P1", prover="A")),
                     (4, _ev(1250, event="proved", proof="P1", prover="A")),
                     (5, _ev(1260, event="verified", proof="P1", epoch="e1")),
                     (6, _ev(1300, event="epoch-close", epoch="e1",
                             capacity=10))]
    got = analyze(slow)[0]
    assert _kinds(got) == ["starved-proof"]
    assert "waited 1000s" in got[0]["detail"], got

    # capacity-exceed: 2 verified vs capacity 1; util row = 2.0
    over = [(0, _ev(100, event="epoch-open", epoch="e1"))]
    for i in range(2):
        over += [(1 + 4 * i, _ev(200 + 10 * i, event="submit", proof=f"Q{i}")),
                 (2 + 4 * i, _ev(210 + 10 * i, event="pickup", proof=f"Q{i}",
                                 prover="A")),
                 (3 + 4 * i, _ev(220 + 10 * i, event="proved", proof=f"Q{i}",
                                 prover="A")),
                 (4 + 4 * i, _ev(230 + 10 * i, event="verified",
                                 proof=f"Q{i}", epoch="e1"))]
    over.append((9, _ev(300, event="epoch-close", epoch="e1", capacity=1)))
    got, erows, _ = analyze(over)
    assert _kinds(got) == ["capacity-exceed"]
    assert "2 proofs verified vs capacity 1" in got[0]["detail"], got
    assert erows[0]["verified"] == 2 and abs(erows[0]["util"] - 2.0) < 1e-9
    # duplicate verified events count one slot, not two
    dv = [(0, _ev(100, event="epoch-open", epoch="e1")),
          (1, _ev(200, event="submit", proof="P1")),
          (2, _ev(210, event="pickup", proof="P1", prover="A")),
          (3, _ev(220, event="proved", proof="P1", prover="A")),
          (4, _ev(230, event="verified", proof="P1", epoch="e1")),
          (5, _ev(240, event="verified", proof="P1", epoch="e1")),
          (6, _ev(300, event="epoch-close", epoch="e1", capacity=1))]
    got, erows, _ = analyze(dv)
    assert _kinds(got) == ["double-verify"], got
    assert erows[0]["verified"] == 1 and abs(erows[0]["util"] - 1.0) < 1e-9

    # oversubscribed (6+5=11 > 10) + unused-reserve INFO (0 verified)
    res = [(0, _ev(100, event="reserve", epoch="e1", slots=6)),
           (1, _ev(150, event="reserve", epoch="e1", slots=5)),
           (2, _ev(200, event="epoch-close", epoch="e1", capacity=10))]
    got = analyze(res)[0]
    ks = _kinds(got)
    assert "oversubscribed" in ks and "unused-reserve" in ks, got
    assert "reservations 11" in next(
        x for x in got if x["kind"] == "oversubscribed")["detail"], got

    # epoch-overrun: verified 100s after close
    overr = lc[:5] + [(5, _ev(1100, event="verified", proof="P1", epoch="e1")),
                      (6, _ev(1000, event="epoch-close", epoch="e1",
                              capacity=10))]
    got = analyze(overr)[0]
    assert _kinds(got) == ["epoch-overrun"]
    assert "100s after close" in got[0]["detail"], got

    # depth-spike: one rising edge crossing 10; knob --depth 13 silent
    deep = [(0, _ev(100, event="epoch-open", epoch="e1"))]
    deep += [(1 + i, _ev(200 + i, event="submit", proof=f"D{i}"))
             for i in range(12)]
    deep.append((13, _ev(300, event="epoch-close", epoch="e1", capacity=100)))
    got = analyze(deep, dict(wait=1e9))[0]
    spikes = [x for x in got if x["kind"] == "depth-spike"]
    assert len(spikes) == 1 and "crossed 10" in spikes[0]["detail"], got
    assert all(x["kind"] != "depth-spike"
               for x in analyze(deep, dict(wait=1e9, depth=13))[0])
    # wait=50: same 12 submits (89..100s old) -> never-picked starved
    got = analyze(deep, dict(wait=50))[0]
    starved = [x for x in got if x["kind"] == "starved-proof"]
    assert len(starved) == 12 and "never picked up" in starved[0]["detail"]
    # 12 submits of one proof: one slot, no spike
    dups = [(0, _ev(100, event="epoch-open", epoch="e1"))]
    dups += [(1 + i, _ev(200 + i, event="submit", proof="SAME"))
             for i in range(12)]
    dups.append((13, _ev(300, event="epoch-close", epoch="e1", capacity=100)))
    got, erows, _ = analyze(dups, dict(wait=1e9))
    assert all(x["kind"] != "depth-spike" for x in got), got
    assert erows[0]["submitted"] == 1 and erows[0]["max_depth"] == 1, erows
    # extra pickup must not dequeue a different waiting proof
    hid = [(0, _ev(100, event="submit", proof="Q")),
           (1, _ev(110, event="submit", proof="R")),
           (2, _ev(120, event="pickup", proof="Q", prover="A")),
           (3, _ev(130, event="pickup", proof="Q", prover="A"))]
    got = analyze(hid, dict(wait=1e9))[0]
    queued = [x for x in got if x["kind"] == "queued-proof"]
    assert len(queued) == 1 and queued[0]["proof"] == "R", got

    # hygiene: verify-without-prove, double-verify, orphan-pickup
    hyg = [(0, _ev(100, event="submit", proof="H")),
           (1, _ev(110, event="pickup", proof="H", prover="A")),
           (2, _ev(120, event="verified", proof="H", epoch="e1")),
           (3, _ev(130, event="verified", proof="H", epoch="e1")),
           (4, _ev(140, event="pickup", proof="GHOST", prover="A"))]
    ks = set(_kinds(analyze(hyg)[0]))
    assert {"verify-without-prove", "double-verify",
            "orphan-pickup"} <= ks, ks
    # verified with a dropped pickup is finished, not starved/queued
    nopick = [(0, _ev(100, event="submit", proof="P1")),
              (1, _ev(200, event="proved", proof="P1", prover="A")),
              (2, _ev(300, event="verified", proof="P1", epoch="e1"))]
    ks = set(_kinds(analyze(nopick, dict(wait=50))[0]))
    assert "starved-proof" not in ks and "queued-proof" not in ks, ks

    # re-proved / late-verify / open-proof / unattributed / uncapped
    info = [(0, _ev(100, event="submit", proof="R")),
            (1, _ev(110, event="pickup", proof="R", prover="A")),
            (2, _ev(120, event="proved", proof="R", prover="A")),
            (3, _ev(130, event="proved", proof="R", prover="A")),
            (4, _ev(900, event="verified", proof="R")),
            (5, _ev(950, event="submit", proof="S")),
            (6, _ev(960, event="pickup", proof="S", prover="A")),
            (7, _ev(1000, event="epoch-close", epoch="e1"))]
    ks = set(_kinds(analyze(info)[0]))
    assert {"re-proved", "late-verify", "open-proof", "verify-unattributed",
            "uncapped-epoch"} <= ks, ks

    # flap: 4 transitions > 3; knob --flaps 4 silent
    flapy = [(i, _ev(10 * i, event=("prover-online" if i % 2 == 0
                                    else "prover-offline"), prover="B"))
             for i in range(5)]
    assert "prover-flap" in _kinds(analyze(flapy)[0])
    assert analyze(flapy, dict(flaps=4))[0] == []

    # idle-while-backlog: run 100->4000 (3900s), C drains, B takes nothing
    idle = [(0, _ev(0, event="prover-online", prover="B")),
            (1, _ev(50, event="prover-online", prover="C"))]
    idle += [(2 + i, _ev(100, event="submit", proof=f"I{i}"))
             for i in range(10)]
    idle += [(12 + i, _ev(4000 + i, event="pickup", proof=f"I{i}",
                          prover="C")) for i in range(10)]
    idle.append((22, _ev(4600, event="epoch-close", epoch="e1", capacity=10)))
    got = analyze(idle, dict(wait=1e9))[0]
    idle_f = [x for x in got if x["kind"] == "idle-while-backlog"]
    assert len(idle_f) == 1
    assert "prover B" in idle_f[0]["detail"] and "3900s" in idle_f[0]["detail"]
    assert all(x["kind"] != "idle-while-backlog"
               for x in analyze(idle, dict(wait=1e9, idle=5000))[0])

    # malformed / ts-less / unknown-event lines (hand-counted)
    junk = [(0, None), (1, _ev("not-a-time", event="submit", proof="X")),
            (2, _ev(5, event="dance-off", proof="Y"))]
    det = {x["kind"]: x["detail"] for x in analyze(junk)[0]}
    assert det == {"malformed-line": "2 unparsable/ts-less line(s)",
                   "unknown-event": "1 unknown event type(s)"}, det

    # ISO timestamps parse; wait + prove arithmetic identical to epoch
    iso = [(0, _ev("2026-09-14T10:00:00Z", event="epoch-open", epoch="e1")),
           (1, _ev("2026-09-14T10:00:30Z", event="submit", proof="P1")),
           (2, _ev("2026-09-14T10:00:50Z", event="pickup", proof="P1",
                   prover="A")),
           (3, _ev("2026-09-14T10:01:20Z", event="proved", proof="P1",
                   prover="A")),
           (4, _ev("2026-09-14T10:01:30Z", event="verified", proof="P1",
                   epoch="e1")),
           (5, _ev("2026-09-14T10:02:00Z", event="epoch-close", epoch="e1",
                   capacity=10))]
    _, erows, prows = analyze(iso)
    assert abs(erows[0]["med_wait"] - 20.0) < 1e-6, erows
    assert abs(prows[0]["med_prove"] - 30.0) < 1e-6, (erows, prows)

    # CLI contract: rc 0 clean/INFO (+json/report shape), 2 unreadable,
    # 1 on BLOCK/WARN; junk line surfaced
    rc, out = run(clean, ["--json"])
    doc = json.loads(out)
    assert rc == 0 and not doc["findings"]
    assert doc["epochs"][0]["epoch"] == "e1" and doc["provers"][0]["prover"] == "A"
    rc, out = run(clean, ["--report"])
    assert rc == 0 and "max_depth" in out and "per_hour" in out, out
    assert "e1" in out and out.count("A ") >= 1, out  # name columns
    assert main(["/nonexistent.jsonl"]) == 2
    rc, out = run(['{"broken', _ev(1, event="submit", proof="Z")])
    assert rc == 1 and "1 unparsable" in out, out
    # INFO-only (queued-proof) is rc 0; WARN/BLOCK still fail
    rc, out = run([_ev(1, event="submit", proof="Z")])
    assert rc == 0 and "queued-proof" in out, out

    print("zk-queue-audit self-test OK (14 groups: lifecycle, starved "
          "x2, capacity/reserve, overrun, depth-spike, hygiene, infos, "
          "flap, idle-backlog, malformed/unknown, ISO, CLI, json/report)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this line)
    else:
        raise SystemExit(main())
