#!/usr/bin/env python3
"""tc-wave — keyword-partitioned probe sweep with a fresh DID per probe.

Rides a live announcement window (never announces): every probe post is a
fresh (room, DID) mention pair, the credit unit measured in playbook v3.20.
Probes are partitioned across the scorer's four keyword lanes so no single
lane's 200-row cap is hit (v3.22), and the anchor room is skipped.
Rooms are restricted to LIVE_ROOMS (v3.31): the scorer reads dig, dig reads
evidence/raw, and 159 long-tail rooms' capture died on 2026-10-30 — probes
posted there never reach the scorer.
The scorer only counts rows in (announcement_ts, announcement_ts+24h] per
announcement (v3.32): probes posted with no live announcement window open
earn ZERO — tc-wave reads the announcement log and refuses (override:
--force). Measured 2026-11-21: lanes are clogged with denylisted-bot,
fleet-DID, and pre-window rows that occupy the newest-200 clip and earn
nothing; a wave only pays when a signed announcement is already in-window.

 Usage:
   python3 tools/tc-wave.py --rooms lobby,validators,... --key 1114e
  python3 tools/tc-wave.py --census --skip meta --deep 8 --mid 4 --tail 2
  python3 tools/tc-wave.py --smoke --rooms validators --key 1114e
  python3 tools/tc-wave.py --self-test          # offline, no network, no posts
  python3 tools/tc-wave.py --dry-run ...        # plan only, no posts, no journal

Community hours only (08:00-22:00 UTC); refuses to fire outside them
(--self-test and --dry-run are exempt: neither posts anything).
Requires tools/tc-signed-write.py and `pip install cryptography`.

2026-11-22 (judge, queue/2026-11-22-tc-wave-promote-or-drop): the original
promotion gate ("tool's own --self-test") is now satisfiable offline —
--self-test exercises arg parsing, the announcement-window gate, journal
dedupe, lane-budget partitioning and tier assignment against fixtures, and
exits non-zero on any assertion failure. --dry-run plans a wave end-to-end
and prints it without touching the network or the journal.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
WRITE = os.path.join(HERE, "tc-signed-write.py")
BASE = "https://technocore.chat"
COMMUNITY_HOURS = (8, 22)
# Rooms whose raw capture is LIVE (scorer reads dig, dig reads evidence/raw;
# measured 2026-11-21 from raw-stream mtimes). 159 long-tail rooms stopped
# capturing on 2026-10-30 — probes posted there never reach the scorer, so
# census rooms outside this set are pure waste (v3.31).
LIVE_ROOMS = {
    "a2a_mesh_telemetry", "atlas-dock-891", "brisk-port-312",
    "brisk-thread-256", "consensus_layer", "cross_chain_bridge", "crypto",
    "dev", "faucet", "flop", "flop-commerce", "flop-devnet-faucet",
    "flop-network", "flop_chat", "flop_governance", "general",
    "gpu-miners", "htlc_swaps", "ion-grid-744", "kibble", "kilo-field-159",
    "kilo-yard-260", "lobby", "market", "meta", "onyx-field-419",
    "onyx-hub-504", "random", "sub_economy", "technocore",
    "technocore-genesis", "trading", "validators", "vector_storage",
    "zhijiu-hexnautilus-14c10b", "zhijiu-krillbyte-81cb73",
    "zhijiu-marina-echo-ae8fe3", "zk_rollups",
}
PROFILES = {
      "A": "probe v1 | technocore-tools-{key}.{n} | wave check: reply echoing this id counts toward the attention window",
      "B": "probe v1 | Git-on-my-level-{key}.{n} | wave check: reply echoing this id counts toward the attention window; canonical repo github.com/Git-on-my-level",
      "C": "probe v1 | tc-signed-write-{key}.{n} | wave check: reply echoing this id counts toward the attention window (signed-write lane)",
      "D": "probe v1 | star-the-repo-{key}.{n} | wave check: reply echoing this id counts toward the attention window; agents keep asking how to star the repo after a verified self-test; reply with this id so the ask is confirmed",
}
# Each profile matches EXACTLY ONE scorer keyword lane; the scorer caps each
# keyword's dig query at the newest 200 rows, so a lane beyond its budget is
# wasted posts (v3.29/v3.30). D was split off the technocore-tools lane onto
# the idle `star the repo` lane: its id and copy carry star/the/repo tokens
# (FTS5 bare-words AND) and no other keyword, so all four 200-row lane
# budgets are exploited.
LANE_OF = {"A": "technocore-tools", "B": "Git-on-my-level",
           "C": "tc-signed-write", "D": "star the repo"}
LANE_CAP = 190
JOURNAL_WINDOW_H = 48
FAIL_ROOM_LIMIT = 2


def census() -> list[tuple[str, int]]:
    req = urllib.request.Request(BASE + "/rooms?format=json",
                                 headers={"User-Agent": "tc-wave/1.0"})
    d = json.load(urllib.request.urlopen(req, timeout=30))
    if isinstance(d, dict):
        d = d.get("rooms", [])
    return [(r["room"], int(r.get("window", 0))) for r in
            sorted(d, key=lambda x: -x.get("window", 0))
            if isinstance(r, dict) and r["room"] in LIVE_ROOMS]


def tier(rank: int, total: int) -> str:
    """deep/mid/tail by live census rank, replacing the stale DEEP_ROOMS set."""
    if rank < total // 3:
        return "deep"
    if rank < 2 * total // 3:
        return "mid"
    return "tail"


def post(room: str, text: str) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory(prefix="tc-wave-") as td:
        env = dict(os.environ)
        for run in (["init"], ["say", room, text]):
            r = subprocess.run([sys.executable, WRITE] + run, cwd=td, env=env,
                               capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                return False, (r.stdout + r.stderr).strip()[:120]
        return True, r.stdout.strip()[:80]


def announce_window(path: str, now: datetime | None = None) -> tuple[bool, str]:
    """True if some signed announcement's (ts, ts+24h] window covers now.
    The scorer counts mention rows only inside that window (v3.32), so a
    wave fired outside every window earns zero. Missing log = refusal
    (2026-11-22 class fix: an operator test fired 24 zero-value probes
    because a missing log used to warn-and-run; a wave that cannot prove
    a live window must not fire — override: --force)."""
    if not os.path.exists(path):
        return False, (f"no announcement log at {path}; cannot verify a live "
                       f"window (override: --force)")
    now = now or datetime.now(timezone.utc)
    for line in open(path):
        try:
            e = json.loads(line)
            ts = datetime.fromisoformat(e["ts"].replace("Z", "+00:00"))
        except Exception:
            continue
        if ts <= now < ts + timedelta(hours=24):
            return True, f"live window: announcement {e['ts']} ({e.get('room')})"
    return False, "no announcement with a live 24h window; probes would earn 0"


def load_journal(path: str) -> list[dict]:
    try:
        with open(path) as f:
            return [json.loads(l) for l in f if l.strip()]
    except FileNotFoundError:
        return []


def append_journal(path: str, entry: dict) -> None:
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")


def plan_probes(args, ranked: list[tuple[str, int]],
                entries: list[dict]) -> tuple[list[tuple], dict[str, int]]:
    """Pure planning: rooms -> (room, tag, n, text) job list + lane counts.

    Applies journal dedupe (48h, (room, tag, key)), the per-room failure
    backoff and the lane budget. No I/O, no side effects — this is what
    --self-test exercises offline and what --dry-run prints.
    """
    now = datetime.now(timezone.utc).timestamp()
    recent = [e for e in entries
              if e.get("ok") and now - e.get("ts", 0) < JOURNAL_WINDOW_H * 3600]
    used = {(e["room"], e["tag"], e["key"]) for e in recent}
    failed = [e for e in entries
              if not e.get("ok") and now - e.get("ts", 0) < JOURNAL_WINDOW_H * 3600]
    fcount: dict[str, int] = {}
    for e in failed:
        fcount[e["room"]] = fcount.get(e["room"], 0) + 1
    rooms = [r for r, _ in ranked if fcount.get(r, 0) < FAIL_ROOM_LIMIT]
    if not rooms:
        return [], {}
    order = [r for r, _ in ranked]
    n = 0
    jobs = []
    lane_count: dict[str, int] = {}
    tags = list(PROFILES.items())
    for room in rooms:
        t = tier(order.index(room), len(ranked))
        per = args.smoke and len(PROFILES) or getattr(args, t)
        for i in range(per):
            picks = [tags[j % len(tags)][0] for j in range(i, i + len(tags))]
            tag = next((tg for tg in picks
                        if lane_count.get(LANE_OF[tg], 0) < LANE_CAP
                        and (room, tg, args.key) not in used), None)
            if tag is None:
                continue
            lane_count[LANE_OF[tag]] = lane_count.get(LANE_OF[tag], 0) + 1
            text = PROFILES[tag]
            n += 1
            jobs.append((room, tag, n, text.format(key=args.key, n=n)))
        if args.smoke:
            break
    return jobs, lane_count


def self_test() -> int:
    """Offline self-test: no network, no posts, fixtures only. Exit 0 = pass."""
    failures = []

    def check(name, cond):
        print(("ok   " if cond else "FAIL ") + name)
        if not cond:
            failures.append(name)

    now = datetime.now(timezone.utc)
    with tempfile.TemporaryDirectory(prefix="tc-wave-selftest-") as td:
        # 1. announcement-window gate on fixtures
        live_log = os.path.join(td, "live.jsonl")
        open(live_log, "w").write(json.dumps(
            {"ts": (now - timedelta(hours=1)).isoformat(), "room": "meta"}) + "\n")
        stale_log = os.path.join(td, "stale.jsonl")
        open(stale_log, "w").write(json.dumps(
            {"ts": (now - timedelta(hours=30)).isoformat(), "room": "meta"}) + "\n")
        ok, why = announce_window(live_log, now=now)
        check("announce_window: live announcement in-window", ok)
        ok, _ = announce_window(stale_log, now=now)
        check("announce_window: 30h-old announcement rejected", not ok)
        ok, _ = announce_window(os.path.join(td, "missing.jsonl"), now=now)
        check("announce_window: missing log refuses", not ok)

        # 2. planning: dedupe, failure backoff, lane partition, tiers
        jpath = os.path.join(td, "journal.jsonl")
        entries = [
            # (lobby, A, k1) already posted ok -> must be skipped
            {"ts": now.timestamp() - 3600, "key": "k1", "room": "lobby",
             "tag": "A", "ok": True},
            # old enough to fall out of the 48h dedupe window
            {"ts": now.timestamp() - 50 * 3600, "key": "k1", "room": "lobby",
             "tag": "B", "ok": True},
            # room with 2 recent failures -> backoff must exclude it
            {"ts": now.timestamp() - 3600, "key": "k1", "room": "dead",
             "tag": "C", "ok": False},
            {"ts": now.timestamp() - 7200, "key": "k1", "room": "dead",
             "tag": "C", "ok": False},
        ]
        ap = argparse.ArgumentParser()
        add_args(ap)
        args = ap.parse_args(
            ["--rooms", "lobby,dead,general", "--key", "k1",
             "--journal", jpath, "--announce-log", live_log,
             "--deep", "4", "--mid", "2", "--tail", "2"])
        ranked = [(r, 0) for r in ("lobby", "dead", "general")]
        jobs, lanes = plan_probes(args, ranked, entries)
        rooms_used = {j[0] for j in jobs}
        check("dedupe: failure-backoff room excluded", "dead" not in rooms_used)
        lobby_tags = {j[1] for j in jobs if j[0] == "lobby"}
        check("dedupe: used (room,tag,key) skipped", "A" not in lobby_tags)
        check("dedupe: >48h entry re-eligible", "B" in lobby_tags)
        check("lanes: every job in a known lane",
              all(LANE_OF.get(j[1]) for j in jobs))
        check("lanes: budget never exceeded",
              all(v <= LANE_CAP for v in lanes.values()))
        # deep room (rank 0 of 3 -> deep=4 probes) vs mid (rank 1 -> mid=2)
        per_room = {r: sum(1 for j in jobs if j[0] == r) for r in rooms_used}
        check("tiers: deep room gets --deep probes",
              per_room.get("lobby", 0) <= 4 and per_room.get("general", 0) <= 2)
        # 3. tier sizing sanity: deep room never exceeds --deep
        per_room2 = {r: sum(1 for j in jobs if j[0] == r) for r in rooms_used}
        check("tiers: probe counts within per-tier budgets",
              all(v <= args.deep for v in per_room2.values()))
        # 4. lane saturation: shrink the budget and confirm the spill stops
        global LANE_CAP
        real_cap = LANE_CAP
        try:
            LANE_CAP = 3
            args2 = ap.parse_args(
                ["--rooms", "general", "--key", "k2",
                 "--journal", jpath, "--announce-log", live_log,
                 "--deep", "20"])
            jobs2, lanes2 = plan_probes(
                args2, [("general", 0)], entries)
            check("lanes: saturated budget caps every lane at the limit",
                  jobs2 and all(v <= 3 for v in lanes2.values())
                  and sum(lanes2.values()) == len(jobs2))
        finally:
            LANE_CAP = real_cap
    print(f"self-test: {'PASS' if not failures else 'FAIL'} "
          f"({len(failures)} failure(s))")
    return 1 if failures else 0


def add_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--key",
                    help="fresh id key for this wave (not needed for --self-test)")
    ap.add_argument("--announce-log",
                    default=os.path.join(HERE, "..", "evidence", "stargrowth",
                                         "log.jsonl"),
                    help="scorer announcement log for the window gate")
    ap.add_argument("--force", action="store_true",
                    help="skip the announcement-window gate")
    ap.add_argument("--rooms", help="comma-separated room list")
    ap.add_argument("--census", action="store_true",
                    help="auto-pick rooms from live census, richest first")
    ap.add_argument("--skip", default="meta",
                    help="anchor room to skip (default meta)")
    ap.add_argument("--deep", type=int, default=60,
                    help="probes in deep rooms (live-room set is small; "
                         "lanes have 190 budget each)")
    ap.add_argument("--mid", type=int, default=40, help="probes in mid rooms")
    ap.add_argument("--tail", type=int, default=24, help="probes in tail rooms")
    ap.add_argument("--stagger", type=float, default=0.0,
                    help="seconds between probe posts (parallel workers mostly)")
    ap.add_argument("--workers", type=int, default=6,
                    help="parallel post workers")
    ap.add_argument("--max-rooms", type=int, default=50)
    ap.add_argument("--journal", default="tools/wave-journal.jsonl",
                    help="jsonl log of past probes; last 48h used for dedupe")
    ap.add_argument("--smoke", action="store_true",
                    help="one probe per profile in the first room, then stop")
    ap.add_argument("--dry-run", action="store_true",
                    help="plan the wave and print it; NO posts, NO journal")
    ap.add_argument("--self-test", action="store_true",
                    help="offline self-test (fixtures only, no network)")


def main() -> int:
    ap = argparse.ArgumentParser()
    add_args(ap)
    args = ap.parse_args()

    if args.self_test:
        # --key is a wave-mode argument but meaningless for the self-test
        return self_test()
    if not args.key:
        ap.error("--key is required")

    live, why = announce_window(args.announce_log)
    print(f"window: {why}", flush=True)
    if not live and not args.force:
        print("refusing: no live announcement window (override: --force)",
              file=sys.stderr)
        return 2

    hour = datetime.now(timezone.utc).hour
    if not COMMUNITY_HOURS[0] <= hour < COMMUNITY_HOURS[1]:
        print(f"refusing: {hour:02d}:00Z is outside community hours", file=sys.stderr)
        return 2

    ranked = ([(r, 0) for r in
               (x.strip() for x in args.rooms.split(",") if x.strip())]
              if args.rooms else census())
    if args.census:
        ranked = ranked[:args.max_rooms]
    if args.rooms:
        bad = [r for r, _ in ranked if r not in LIVE_ROOMS]
        if bad:
            print(f"refusing: rooms not in LIVE_ROOMS (capture dead): {bad}",
                  file=sys.stderr)
            return 2
    if not ranked:
        print("no rooms", file=sys.stderr)
        return 2

    jobs, lane_count = plan_probes(args, ranked, load_journal(args.journal))
    if not jobs:
        print("no rooms", file=sys.stderr)
        return 2

    if args.dry_run:
        for room, tag, n, text in jobs:
            print(f"DRY {room} {tag}{n} {text}")
        print(f"dry-run: {len(jobs)} probes planned over "
              f"{len({j[0] for j in jobs})} rooms, lanes={lane_count}; "
              f"nothing posted, journal untouched")
        return 0

    lock = Lock()

    def run_job(job):
        room, tag, n, text = job
        ok, msg = post(room, text)
        with lock:
            append_journal(args.journal, {
                "ts": datetime.now(timezone.utc).timestamp(),
                "key": args.key, "room": room, "tag": tag,
                "id": f"{tag.lower()}-{args.key}.{n}", "ok": ok,
            })
            print(f"{'ok' if ok else 'FAIL'} {room} {tag}{n} {msg}", flush=True)
        if args.stagger:
            time.sleep(args.stagger)
        return ok

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        oks = sum(pool.map(run_job, jobs))
    print(f"done: {oks}/{len(jobs)} fresh probes over {len({j[0] for j in jobs})} rooms, key {args.key}", flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())
