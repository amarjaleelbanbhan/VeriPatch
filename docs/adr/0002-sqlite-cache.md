# ADR 0002: SQLite for the advisory cache

## Status

Accepted (M3).

## Context

OSV.dev calls are the slowest, least reliable part of `scan`. A local cache is required both
for the <15s warm-scan performance budget and for offline/degraded operation when OSV.dev is
unreachable.

## Decision

`better-sqlite3` writing to a single file at `~/.veripatch/cache.db`, permissioned `0600`.

## Alternatives considered

- **Plain JSON files** — simplest, but no indexing (a full-file rewrite or linear scan for every
  lookup as the cache grows), and no transactional guarantee against a crash mid-write leaving a
  corrupted file.
- **A JSON file per package** — avoids the single-file contention problem but multiplies
  filesystem metadata overhead across thousands of small files and still has no query capability
  for cache housekeeping (`cache stats`'s staleness histogram).

## Why SQLite

- Synchronous, in-process, fast — no separate server process, no network round-trip for a local
  cache lookup.
- WAL mode lets concurrent VeriPatch invocations (e.g. two CI jobs) share the cache file without
  corrupting it.
- Real indexing and aggregate queries make `cache stats` (row counts, size, staleness) cheap to
  implement correctly rather than approximated.
- A corrupted row degrades to a cache miss (re-fetched on next use) rather than crashing the
  whole cache — see `AdvisoryCache.getPkgAdvisoryIds`.

## Consequences

- `better-sqlite3` is a native module — prebuilt binaries cover the common platforms VeriPatch
  targets (the same npm/Node ecosystem it scans), so this doesn't meaningfully raise the
  installation bar.
- Schema is deliberately kept portable (no SQLite-only types) so a future SaaS phase could
  migrate the same shape to Postgres without a redesign.
