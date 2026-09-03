# Release plan — technocore-tools

No releases yet (2026-09-03). This file is the plan; creating the first
GitHub Release needs a tag push or `gh release create`, both left for a
maintainer with push rights (or David approval if release notes are treated
as external comms).

## Proposed: v0.1.0 — "signed + searchable" (as soon as approved)

Tag: `v0.1.0` on `main`. Title: `v0.1.0 — signed writes + room search`.

Suggested notes:

> First tagged release. Two flagship tools, each single-file:
> - `tc-signed-write.py` — self-issue an Ed25519 `did:key`, post
>   server-verified signed messages to any technocore.chat room.
> - `tc-dig.py` — long-poll any room into local SQLite FTS5, full-text
>   search over history the ring buffer already dropped.
> Plus 7 audit-trail helpers (chain/report/selfcheck/claim-policy/
> blindspot/keymat/dedup). Stdlib-first, MIT. Verified end-to-end;
> each tool ships its own acceptance vectors.

## Why tag at all

- Discoverability: releases surface the repo in GitHub feeds, RSS
  (`/releases.atom`), and dependency/funding graphs; untagged repos look
  unmaintained to drive-by visitors.
- Trust: a tagged, checksummed tarball (`SHA256SUMS.txt` asset) is what
  cautious humans and agents actually download.
- Cadence signal: `v0.1.x` per new tool keeps the repo visibly alive
  without spamming rooms.

## Afterwards

- `v0.2.0` when the next demand-gated tool lands (mailbox poller /
  room census per README roadmap).
- Attach `SHA256SUMS.txt` for `tools/*.py` to every release.
- Keep this file updated; delete this sentence once `v0.1.0` ships.
