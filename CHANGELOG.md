# veripatch

## 0.3.0

### Minor Changes

- [`adba3ed`](https://github.com/amarjaleelbanbhan/VeriPatch/commit/adba3ed9457a46fa85522dfa97b57998e45ba48e) Thanks [@amarjaleelbanbhan](https://github.com/amarjaleelbanbhan)! - Redesigned `veripatch scan` and `veripatch verify` terminal output to the polish level of
  modern developer tools. `scan` now shows a brand header, a Project Summary card (package
  manager, packages scanned, vulnerabilities, verified fixes, manual review), a ranked Top
  Vulnerabilities table (package, severity, current version, safe version, verification status),
  a Verification section that explains each real verdict in plain language, and a final
  recommendation box. A progress spinner narrates the real scan phases. Everything is built on a
  zero-dependency UI toolkit that measures by visible width (perfect alignment even with color),
  auto-detects terminal width, degrades to ASCII where Unicode isn't supported, and emits zero
  escape codes when piped to a file or a non-TTY (`NO_COLOR` / `FORCE_COLOR` honored). `--json`
  output is unchanged.

## 0.2.0

### Minor Changes

- [`140144c`](https://github.com/amarjaleelbanbhan/VeriPatch/commit/140144c4d978909913e0eaa5dc27ed1f16e7f79f) Thanks [@amarjaleelbanbhan](https://github.com/amarjaleelbanbhan)! - New `veripatch baseline list|add|remove|prune` subcommands manage accepted debt one finding at
  a time: `add` records a reason and an optional expiry (`--expires-days`), after which the vuln
  counts as new again in `scan --ci`; `prune` drops entries whose vulns no longer appear in the
  last scan. `baseline.json` gains optional per-entry metadata, additively — existing files keep
  working unchanged.

- [`281d079`](https://github.com/amarjaleelbanbhan/VeriPatch/commit/281d07973609a0566467ef8015d4cd854a9d8ec7) Thanks [@amarjaleelbanbhan](https://github.com/amarjaleelbanbhan)! - npm workspaces are now scanned correctly from the monorepo root: workspace members'
  dependencies (including cross-workspace references through link entries) appear in the graph
  with provenance chains that name the owning workspace, e.g. `root > @ws/lib > vulnerable-dep`.
  Workspace members themselves are never reported as vulnerabilities — they are first-party code.

- [`6f297e4`](https://github.com/amarjaleelbanbhan/VeriPatch/commit/6f297e4bc34d8c8d46057149e17668f3d1065414) Thanks [@amarjaleelbanbhan](https://github.com/amarjaleelbanbhan)! - Transitive-dependency fixes are now applied the way a human would commit them: both the verify
  sandbox and `veripatch update` write an npm `overrides` entry and regenerate the lockfile,
  instead of running `npm install pkg@to` — which would have added the package as a new root
  dependency. Direct dependencies keep the plain versioned install.

- [`10feb88`](https://github.com/amarjaleelbanbhan/VeriPatch/commit/10feb88858f4da639c0625f8876a0061705a8163) Thanks [@amarjaleelbanbhan](https://github.com/amarjaleelbanbhan)! - `verify --all` can run sandbox verifications in parallel: new `verifyConcurrency` config key
  (default 1, max 8) and `--concurrency` flag. Each verification keeps its own container,
  network, and staging copy; per-candidate output is buffered and printed in input order, so the
  transcript stays deterministic regardless of which sandbox finishes first.

- [`6872cbf`](https://github.com/amarjaleelbanbhan/VeriPatch/commit/6872cbf4d0c5e9f153eb9929ad033af933e7081d) Thanks [@amarjaleelbanbhan](https://github.com/amarjaleelbanbhan)! - `scan` now supports pnpm projects: `pnpm-lock.yaml` v6 (pnpm 8) and v9 (pnpm 9+) are parsed
  into the same dependency graph as npm and yarn lockfiles, with peer-resolution suffixes merged
  into one node per package version. Lockfile auto-detection covers all three managers (npm →
  yarn → pnpm precedence, with a warning naming any ignored lockfile). `verify` and `update`
  refuse pnpm projects explicitly for now, matching the yarn behavior.

- [`c78b9cb`](https://github.com/amarjaleelbanbhan/VeriPatch/commit/c78b9cbf9aeaa8ca9a7910d671b8c2916d935880) Thanks [@amarjaleelbanbhan](https://github.com/amarjaleelbanbhan)! - `scan` now supports yarn projects: both classic (v1) and berry (v2+) `yarn.lock` files are
  parsed into the same dependency graph as npm lockfiles, with auto-detection when multiple
  lockfiles coexist (`package-lock.json` wins, with a warning). Reports gain a `packageManager`
  field. `verify` and `update` refuse yarn projects explicitly for now — they replay fixes with
  npm, and silently writing a `package-lock.json` into a yarn project would corrupt it.

## 0.1.1

### Patch Changes

- [`e31cfad`](https://github.com/amarjaleelbanbhan/VeriPatch/commit/e31cfad78405496be6ce72948eae8dd14822aac6) Thanks [@amarjaleelbanbhan](https://github.com/amarjaleelbanbhan)! - Fix a critical bug where the CLI silently did nothing (exit 0, no output) when invoked through a globally-installed npm symlink on Linux/macOS -- the vast majority of real installs. `veripatch scan`, `veripatch --version`, and every other command were affected. Windows was unaffected (npm generates a `.cmd` wrapper there instead of a symlink), which is why this went unnoticed until a real end-to-end test against the published package on a Linux CI runner.

## 0.1.0

Initial release. From here on, this file is maintained by
[changesets](https://github.com/changesets/changesets) — every subsequent entry is generated
from PR-attached changesets, not written by hand.

### Added

- **`scan`** — parses `package-lock.json` (v2/v3, with a degraded package.json-only fallback),
  fetches advisories from [OSV.dev](https://osv.dev) (SQLite-cached, TTL-based, offline
  stale-serve), ranks vulnerabilities by severity, and resolves a deterministic fix per vuln
  (direct bump for a direct dependency, `npm overrides` for a transitive one). `--ci` mode diffs
  against a committed `baseline.json` (`--write-baseline` to create one) so pre-existing debt
  doesn't fail builds.
- **`verify`** — applies a candidate fix inside a hardened Docker sandbox (non-root, all
  capabilities dropped, `no-new-privileges`, resource-limited, network-phased: registry-only
  during install, fully isolated for build/test), re-scans the bumped lockfile to prove the
  vulnerability is actually gone, and computes a deterministic `HIGH`/`MEDIUM`/`FAIL`/
  `INCONCLUSIVE` confidence verdict from exit codes and the rescan alone — never from log-text
  heuristics.
- **`report`** — re-renders `report.json` / `report.md` / a GitHub-flavored `pr-comment` from
  stored run artifacts, without re-running scan or verify.
- **`update`** — applies a verified fix to the real working tree, refusing unless the
  verification confidence is `HIGH`/`MEDIUM` and the git tree is clean (both overridable).
  Never commits or pushes.
- **`doctor`** — diagnoses Node version, Docker reachability, sandbox image pullability,
  lockfile presence, OSV.dev reachability, cache writability, and config validity.
- **`cache clear`/`cache stats`** — manage the local advisory cache.
- A composite **GitHub Action** (`action.yml`) wrapping `scan`/`verify` with inline annotations,
  an uploaded `report.json` artifact, and an optional sticky PR comment.

### Security

- Every sandboxed install runs `npm ci --ignore-scripts` — the primary defense against a
  malicious `postinstall` script, since the network-phase boundary alone constrains which
  network the container is on, not which domains it can reach. See
  [docs/SECURITY.md](docs/SECURITY.md) for the full threat model and documented residual risks.
