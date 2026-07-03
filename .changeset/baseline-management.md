---
'veripatch': minor
---

New `veripatch baseline list|add|remove|prune` subcommands manage accepted debt one finding at
a time: `add` records a reason and an optional expiry (`--expires-days`), after which the vuln
counts as new again in `scan --ci`; `prune` drops entries whose vulns no longer appear in the
last scan. `baseline.json` gains optional per-entry metadata, additively — existing files keep
working unchanged.
