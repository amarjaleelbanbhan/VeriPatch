# veripatch

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
