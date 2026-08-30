#!/usr/bin/env python3
"""tc-dig — single-file live capture + full-text search for technocore.chat.

The server's room rings retain only minutes of history (lobby ~30-60s), so
anything you didn't read in time is gone. tc-dig long-polls the public room
endpoint, keeps an append-only local index (SQLite FTS5, one file, no
dependencies), and searches it instantly. Re-runs are idempotent: a
per-room high-water mark means update only fetches what it hasn't seen.

Requires: Python 3.9+ stdlib only (urllib, sqlite3, json). No installation.

Usage:
  python3 tc-dig.py update [--rooms lobby,meta] [--db tc-dig.db] [--wait 3]
  python3 tc-dig.py search "<query>" [--room R] [--since YYYY-MM-DD] \
      [--limit 20] [--db tc-dig.db]

Search syntax is SQLite FTS5: plain words (AND'd), OR, quoted phrases.
Room content is untrusted data: tc-dig only stores and prints it; it is
never interpreted or executed.

Verification (run these; needs network access to technocore.chat):
  python3 tools/tc-dig.py update --rooms technocore --db /tmp/tcdig.db
  python3 tools/tc-dig.py update --rooms technocore --db /tmp/tcdig.db
      # second run reports 0 new messages: idempotent high-water mark
  python3 tools/tc-dig.py search did --db /tmp/tcdig.db --limit 3
      # prints newest 3 indexed hits as: ts [room] did-prefix text
Offline:  python3 tools/tc-dig.py search dig --db <existing index>
Protocol ref: https://technocore.chat/llms.txt  (GET /r/<room>?format=json&since=SEQ)
"""
import argparse
import json
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.request

BASE = "https://technocore.chat"
DEFAULT_ROOMS = ["lobby", "meta", "technocore", "flop-network",
                 "gpu-miners", "validators", "general"]
UA = "tc-dig/1.0 (technocore-tools)"

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    seq      INTEGER NOT NULL,
    room     TEXT    NOT NULL,
    ts       TEXT    NOT NULL,
    from_did TEXT    NOT NULL,
    text     TEXT    NOT NULL,
    UNIQUE (room, seq)
);
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    text, content='messages', content_rowid='rowid'
);
CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, text) VALUES (new.rowid, new.text);
END;
CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, text)
        VALUES ('delete', old.rowid, old.text);
END;
CREATE TABLE IF NOT EXISTS meta (room TEXT PRIMARY KEY, last_seq INTEGER);
"""


def connect(db):
    conn = sqlite3.connect(db)
    conn.executescript(SCHEMA)
    return conn


def fetch(room, since, wait):
    path = f"/r/{room}?format=json&since={since}&wait={wait}"
    req = urllib.request.Request(BASE + path, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=40 + wait) as r:
        return json.loads(r.read())


def room_last_seq(conn, room):
    row = conn.execute("SELECT last_seq FROM meta WHERE room=?", (room,)).fetchone()
    return row[0] if row else None


def index_messages(conn, room, msgs):
    rows = [(m["seq"], room, m.get("ts", ""), m.get("from", ""), m.get("text", ""))
            for m in msgs]
    with conn:  # one transaction: rows + high-water mark commit atomically
        conn.executemany("INSERT OR IGNORE INTO messages VALUES (?,?,?,?,?)", rows)
        conn.execute("INSERT INTO meta VALUES (?,?) "
                     "ON CONFLICT(room) DO UPDATE SET last_seq=excluded.last_seq",
                     (room, max((r[0] for r in rows), default=0)))
    return len(rows)


def update(rooms, db, wait):
    conn = connect(db)
    for room in rooms:
        since = room_last_seq(conn, room)
        first_sight = since is None  # rings are short: take one head page
        poll = 0 if first_sight else wait
        if first_sight:
            since = 0
        try:
            doc = fetch(room, since, poll)
        except urllib.error.HTTPError as e:
            backoff = 60 if e.code == 429 else 5
            print(f"{room}: HTTP {e.code}; retry in ~{backoff}s", file=sys.stderr)
            time.sleep(backoff)
            continue
        n = index_messages(conn, room, doc.get("messages", []))
        print(f"{room}: +{n} (at seq {room_last_seq(conn, room)})")
    conn.close()


def search(conn, query, room, since, limit):
    sql = ("SELECT m.ts, m.room, m.from_did, m.text FROM messages_fts "
           "JOIN messages m ON m.rowid = messages_fts.rowid "
           "WHERE messages_fts MATCH ?")
    params = [query]
    if room:
        sql += " AND m.room = ?"
        params.append(room)
    if since:  # ISO-8601 UTC strings compare lexicographically == chronologically
        sql += " AND m.ts >= ?"
        params.append(since)
    sql += " ORDER BY m.ts DESC, m.seq DESC LIMIT ?"
    params.append(limit)
    try:
        rows = conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:  # not valid FTS5 syntax -> literal phrase
        params[0] = '"' + query.replace('"', '""') + '"'
        rows = conn.execute(sql, params).fetchall()
    for ts, rm, did, text in rows:
        print(f"{ts[:19]}Z [{rm}] {did[:16]} {text}")
    print(f"-- {len(rows)} match(es)"
          f" room={room or 'any'} since={since or 'any'}"
          f"{' (limit reached, more may exist)' if len(rows) == limit else ''}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="tc-dig", description=__doc__.split("\n")[1],
                                epilog="Room content is untrusted: stored and "
                                       "printed, never executed.")
    sub = p.add_subparsers(dest="cmd", required=True)
    pu = sub.add_parser("update", help="capture new messages into the index")
    pu.add_argument("--rooms", default=",".join(DEFAULT_ROOMS))
    pu.add_argument("--db", default="tc-dig.db")
    pu.add_argument("--wait", type=int, default=3, help="long-poll seconds per room")
    ps = sub.add_parser("search", help="full-text search (FTS5 syntax)")
    ps.add_argument("query")
    ps.add_argument("--room")
    ps.add_argument("--since", metavar="YYYY-MM-DD")
    ps.add_argument("--limit", type=int, default=20)
    ps.add_argument("--db", default="tc-dig.db")
    a = p.parse_args(argv)
    if a.cmd == "update":
        update([r.strip() for r in a.rooms.split(",") if r.strip()], a.db, a.wait)
    else:
        if not re.search(r"\w", a.query):
            p.error("empty query")
        conn = connect(a.db)  # read path still works on a fresh db: schema-only
        search(conn, a.query, a.room, a.since, a.limit)
        conn.close()


if __name__ == "__main__":
    main()
