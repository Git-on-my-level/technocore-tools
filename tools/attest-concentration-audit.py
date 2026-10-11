#!/usr/bin/env python3
"""attest-concentration-audit — validator-set key-concentration audit
over attestation / relayer logs: answers the governance question "do a
few keys dominate attestations?" with distribution statistics (HHI,
top-k share, Nakamoto coefficient, Gini), the same concentration math
over relayer attribution, and a first-half/second-half trend check so a
room can show whether concentration is rising or being worked down.

DEMAND: evidence/suggestions/tools-services/2026-10-10.md
  - "Governance audit of validator set / relayer logs due to key
    concentration" — evidence: "Those four keys dominating attestations
    is exactly why I won't touch settlement until governance audits the
    validator set. Fwiw, I've pulled relayer logs before and the same
    concen…" (poui_validators, 10-09 14:02) — proposed service:
    "hermes-tools validator-set concentration audit + relayer log
    verification".
  - "Audit of spammer/validator-set concern raised informally" (same
    file, second run) — proposed service: "on-request validator-set
    concentration audit report for a room, surfacing key distribution
    stats."

Input: one JSONL capture, one attestation event per line:
  {"ts":"2026-10-09T14:02:00Z","key":"did:key:z6...","subject":"0xabc",
   "action":"attest","weight":2.5,"relay":"relay-2"}
`action` defaults to attest (non-attest actions are counted, not
weighed); `weight` is an optional positive number (stake-weighted
concentration); `relay` is optional relayer attribution. Inputs are
data only — parsed, never run. No network, no subprocess. Stdlib only.
rc 0 clean / 1 findings / 2 usage or IO.
"""
import argparse
import json
import sys
from datetime import datetime, timezone

USAGE = "usage: attest-concentration-audit.py <capture.jsonl> [options]"


def parse_ts(s):
    t = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t


def load_events(path):
    """Return (events, bad) — events sorted by ts; bad = dropped lines."""
    events, bad = [], 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                ts = parse_ts(row["ts"])
                key = str(row["key"])
                if not key:
                    raise ValueError("empty key")
                action = str(row.get("action", "attest"))
                weight = row.get("weight", 1)
                if weight is not None:
                    weight = float(weight)
                    if not (weight > 0):
                        raise ValueError("weight must be positive")
                events.append({"ts": ts, "key": key, "action": action,
                               "weight": weight,
                               "relay": row.get("relay") or None})
            except (KeyError, ValueError, TypeError):
                bad += 1
    events.sort(key=lambda e: e["ts"])
    return events, bad


def tally(events, field="key", weigh=True):
    """Sum positive weight (or count) per value of `field`."""
    out = {}
    for e in events:
        if e["action"] != "attest":
            continue
        v = e[field]
        if v is None:
            continue
        w = e["weight"] if (weigh and e["weight"] is not None) else 1
        out[v] = out.get(v, 0.0) + w
    return out


def shares(totals):
    """[(value, share)] sorted by share desc; share sums to 1."""
    total = sum(totals.values())
    if total <= 0:
        return []
    out = sorted(((k, v / total) for k, v in totals.items()),
                 key=lambda kv: (-kv[1], kv[0]))
    return out


def hhi(share_list):
    """Herfindahl index on 0..1 (1/n for a uniform n-key set)."""
    return sum(s * s for _, s in share_list)


def top_k_share(share_list, k):
    return sum(s for _, s in share_list[:k])


def nakamoto(share_list):
    """Minimum keys whose combined share exceeds 50%."""
    cum = 0.0
    for i, (_, s) in enumerate(share_list, 1):
        cum += s
        if cum > 0.5:
            return i
    return len(share_list)


def gini(totals):
    """Gini coefficient over weight totals (0 = equal, 1 = maximally
    unequal)."""
    v = sorted(totals.values())
    n = len(v)
    if n == 0 or sum(v) <= 0:
        return 0.0
    # mean absolute difference over all ordered pairs / (2 * mean)
    diff_sum = 0.0
    for i, x in enumerate(v):
        diff_sum += (2 * i - n + 1) * x
    return diff_sum / (n * sum(v))


def jaccard(a, b):
    a, b = set(a), set(b)
    if not a and not b:
        return 1.0
    return len(a & b) / max(1, len(a | b))


def slice_stats(events, field="key"):
    """Concentration stats per time half + drift between them."""
    att = [e for e in events if e["action"] == "attest"]
    mid = len(att) // 2
    halves = {}
    for name, part in (("first", att[:mid]), ("second", att[mid:])):
        sh = shares(tally(part, field))
        halves[name] = {"hhi": round(hhi(sh), 4),
                        "top4": [k for k, _ in sh[:4]]}
    halves["hhi_drift"] = round(halves["second"]["hhi"]
                                - halves["first"]["hhi"], 4)
    halves["top4_jaccard"] = round(jaccard(halves["first"]["top4"],
                                           halves["second"]["top4"]), 4)
    return halves


def concentration_report(events, top4_thresh=0.5, hhi_thresh=0.25,
                         relay_hhi_thresh=0.5, trend_thresh=0.10):
    """Full audit: stats + flags. Returns dict with 'flags' list."""
    flags = []
    totals = tally(events, "key")
    sh = shares(totals)
    n_keys = len(sh)
    n_att = sum(1 for e in events if e["action"] == "attest")
    rep = {
        "attestations": n_att,
        "skipped_actions": len(events) - n_att,
        "keys": n_keys,
        "weight_total": round(sum(totals.values()), 4),
        "hhi": round(hhi(sh), 4) if sh else 0.0,
        "top1_share": round(top_k_share(sh, 1), 4),
        "top4_share": round(top_k_share(sh, 4), 4),
        "nakamoto_coefficient": nakamoto(sh),
        "gini": round(gini(totals), 4),
        "top_keys": [{"key": k, "share": round(s, 4)} for k, s in sh[:8]],
    }
    if n_keys and rep["top1_share"] > 0.5:
        flags.append(f"TOP1_SHARE {rep['top1_share']:.2f} — one key holds "
                     "majority attestation weight")
    if n_keys >= 8 and rep["top4_share"] > top4_thresh:
        flags.append(f"TOP4_DOMINANCE {rep['top4_share']:.2f} of weight in "
                     "4 keys — the 'four keys dominating' pattern")
    if n_keys >= 4 and rep["hhi"] > hhi_thresh:
        flags.append(f"HHI_HIGH {rep['hhi']:.2f} (>= {hhi_thresh}) — "
                     "highly concentrated validator set")
    if n_keys < 4:
        flags.append(f"FEW_KEYS {n_keys} — set too small to audit "
                     "concentration meaningfully")
    # relayer attribution: same concentration question over relays
    rt = tally(events, "relay")
    rsh = shares(rt)
    rep["relays"] = {"relays": len(rsh), "hhi": round(hhi(rsh), 4),
                     "top1_share": round(top_k_share(rsh, 1), 4),
                     "top_relays": [{"relay": k, "share": round(s, 4)}
                                    for k, s in rsh[:4]]}
    if len(rsh) >= 4 and rep["relays"]["hhi"] >= relay_hhi_thresh:
        flags.append(f"RELAY_HHI_HIGH {rep['relays']['hhi']:.2f} — same "
                     "concentration shows up in the relayer logs")
    # time trend: is concentration rising or being worked down?
    if rep["attestations"] >= 8:
        trend = slice_stats(events)
        rep["trend"] = trend
        if trend["hhi_drift"] >= trend_thresh:
            flags.append(f"TREND_RISING hhi drift +{trend['hhi_drift']:.2f} "
                         "second half vs first — concentration increasing")
        if (n_keys >= 8 and rep["top4_share"] > top4_thresh
                and trend["top4_jaccard"] <= 0.25):
            flags.append(f"TOP_SET_CHURN top-4 overlap "
                         f"{trend['top4_jaccard']:.2f} between halves")
    rep["flags"] = flags
    return rep

def audit(path, opts):
    events, bad = load_events(path)
    if not events:
        print("no usable events", file=sys.stderr)
        return 2
    rep = concentration_report(
        events, top4_thresh=opts.top4_threshold,
        hhi_thresh=opts.hhi_threshold,
        relay_hhi_thresh=opts.relay_hhi_threshold,
        trend_thresh=opts.trend_threshold)
    rep["bad_lines"] = bad
    if bad > max(3, 0.05 * rep["attestations"]):
        rep["flags"].append(f"PARSE_NOISE {bad} unusable lines")
    return rep


def self_test():
    import tempfile, os
    tmp = os.path.join(tempfile.mkdtemp(), "conc.jsonl")

    def write(lines):
        with open(tmp, "w") as fh:
            fh.write("\n".join(json.dumps(x) for x in lines) + "\n")

    # pure stat functions, hand-checked values
    sh = shares({"a": 40, "b": 30, "c": 20, "d": 10})
    assert abs(hhi(sh) - 0.30) < 1e-9, hhi(sh)
    assert nakamoto(sh) == 2, "0.4 alone < 0.5, +0.3 crosses"
    assert nakamoto(shares({"a": 6, "b": 4})) == 1
    assert nakamoto([]) == 0
    assert top_k_share(sh, 4) == 1.0 and abs(top_k_share(sh, 1) - .4) < 1e-9
    assert abs(gini({"a": 1, "b": 1, "c": 1, "d": 1})) < 1e-9
    assert abs(gini({"a": 4, "b": 0, "c": 0, "d": 0}) - 0.75) < 1e-9
    assert jaccard([], []) == 1.0 and jaccard("abc", "abd") == 0.5
    # four dominating keys + relayer concentration + rising trend
    t0 = "2026-10-09T14:00:00Z"
    lines = []
    for i in range(8):  # spread-out first half across two relays
        lines.append({"ts": f"2026-10-09T0{i}:00:00Z",
                      "key": f"did:key:z{i}",
                      "relay": f"relay-f{i % 2}"})
    for i, (k, w, rel) in enumerate([("k1", 60, "relay-big"),
                                     ("k2", 20, "relay-big"),
                                     ("k3", 15, "relay-s1"),
                                     ("k4", 5, "relay-s2")]):
        lines.append({"ts": f"2026-10-09T2{i}:00:00Z",
                      "key": f"did:key:{k}", "weight": w, "relay": rel})
    write(lines)
    rep = concentration_report(load_events(tmp)[0])
    assert rep["keys"] == 12, rep["keys"]
    assert any("TOP4_DOMINANCE" in f for f in rep["flags"]), rep["flags"]
    assert any("TREND_RISING" in f for f in rep["flags"]), rep["flags"]
    assert any("RELAY_HHI_HIGH" in f for f in rep["flags"]), rep["flags"]
    assert rep["relays"]["relays"] == 5
    assert rep["nakamoto_coefficient"] == 1, "k1 alone > 50% weight"
    assert any("TOP1_SHARE" in f for f in rep["flags"]), rep["flags"]
    top = [t["key"] for t in rep["top_keys"]]
    assert top[0] == "did:key:k1" and len(top) == 8, top

    # egalitarian control: same tool must come back clean
    lines = [{"ts": f"2026-10-09T0{i}:00:00Z", "key": f"did:key:e{i}",
              "relay": f"relay-{i % 5}"} for i in range(10)]
    write(lines)
    rep = concentration_report(load_events(tmp)[0])
    assert rep["flags"] == [], ("egalitarian set flags", rep["flags"])
    assert rep["hhi"] == 0.1 and rep["nakamoto_coefficient"] == 6, rep

    # uniform sets at the n_keys floors must not trip top-4 / HHI (min
    # top4_share is 4/n, min HHI is 1/n; equality is a balanced set)
    for n in (8, 4):
        lines = [{"ts": f"2026-10-09T0{i}:00:00Z", "key": f"did:key:e{i}"}
                 for i in range(n)]
        write(lines)
        rep = concentration_report(load_events(tmp)[0])
        assert rep["flags"] == [], (n, "uniform floor flags", rep["flags"])

    # single-key + malformed-line handling
    write([{"ts": t0, "key": "did:key:solo"},
           {"ts": t0, "key": "did:key:w", "weight": -1},
           "not json"])
    events, bad = load_events(tmp)
    assert bad == 2 and len(events) == 1, (bad, len(events))
    rep = concentration_report(events)
    assert any("FEW_KEYS" in f for f in rep["flags"]), rep["flags"]

    # ts-order independence: shuffling must not change the stats
    import random
    rng = random.Random(7)
    lines = [{"ts": f"2026-10-09T0{i}:30:00Z", "key": f"did:key:x{i % 6}"}
             for i in range(12)]
    write(lines)
    r1 = concentration_report(load_events(tmp)[0])
    rng.shuffle(lines)
    write(lines)
    r2 = concentration_report(load_events(tmp)[0])
    assert r1["hhi"] == r2["hhi"] and r1["top_keys"] == r2["top_keys"]

    assert os.path.exists(tmp)
    print("attest-concentration-audit self-test OK (15 assertion groups)")
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("capture", nargs="?")
    ap.add_argument("--top4-threshold", type=float, default=0.5)
    ap.add_argument("--hhi-threshold", type=float, default=0.25)
    ap.add_argument("--relay-hhi-threshold", type=float, default=0.5)
    ap.add_argument("--trend-threshold", type=float, default=0.10)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("-h", "--help", action="store_true")
    try:
        opts = ap.parse_args(argv)
    except SystemExit:
        print(USAGE)
        return 2
    if opts.capture is None and not (opts.help or opts.self_test):
        print(USAGE)
        return 2
    if opts.help:
        print(__doc__)
        return 0
    if opts.self_test:
        return self_test()
    try:
        rep = audit(opts.capture, opts)
    except OSError as e:
        print(f"cannot read capture: {e}", file=sys.stderr)
        return 2
    if rep == 2:
        return 2
    if opts.json:
        print(json.dumps(rep, indent=1, ensure_ascii=False))
    else:
        print(f"keys={rep['keys']} attestations={rep['attestations']} "
              f"hhi={rep['hhi']} top4={rep['top4_share']} "
              f"nakamoto={rep['nakamoto_coefficient']} "
              f"gini={rep['gini']}")
        print(f"relays: n={rep['relays']['relays']} "
              f"hhi={rep['relays']['hhi']}")
        if "trend" in rep:
            tr = rep["trend"]
            print(f"trend: hhi {tr['first']['hhi']} -> "
                  f"{tr['second']['hhi']} (drift {tr['hhi_drift']})")
        for f in rep["flags"]:
            print(f"FLAG {f}")
        if not rep["flags"]:
            print("no concentration findings")
    return 1 if rep["flags"] else 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this line)
    else:
        raise SystemExit(main())
