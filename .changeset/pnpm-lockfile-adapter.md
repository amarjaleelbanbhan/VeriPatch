---
'veripatch': minor
---

`scan` now supports pnpm projects: `pnpm-lock.yaml` v6 (pnpm 8) and v9 (pnpm 9+) are parsed
into the same dependency graph as npm and yarn lockfiles, with peer-resolution suffixes merged
into one node per package version. Lockfile auto-detection covers all three managers (npm →
yarn → pnpm precedence, with a warning naming any ignored lockfile). `verify` and `update`
refuse pnpm projects explicitly for now, matching the yarn behavior.
