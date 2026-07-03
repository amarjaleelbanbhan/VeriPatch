# CLI Reference

## Global flags

| Flag              | Description                                                                         |
| ----------------- | ----------------------------------------------------------------------------------- |
| `--json`          | Machine-readable output on stdout (stdout is reserved for this; logs go to stderr). |
| `--verbose`       | Debug-level logging.                                                                |
| `--config <path>` | Path to a `.veripatchrc` file (default: `./.veripatchrc`).                          |
| `--no-color`      | Disable ANSI color in human-readable output.                                        |
| `--cwd <dir>`     | Project directory to operate in (default: current directory).                       |

## Exit codes

A single mapper (`src/cli/exit-code.ts`) decides every exit code:

| Code | Meaning                                                                                                                                                                                                                                                  |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `0`  | Success — no vulnerabilities at/above threshold (`scan`), or a verification completed with _any_ verdict including FAIL (`verify`), or the command otherwise succeeded.                                                                                  |
| `1`  | `scan` found vulnerabilities at/above the severity threshold (or new-vs-baseline in `--ci` mode). `doctor` found at least one failing check. **`verify` never returns 1** — a FAIL confidence verdict is a successful verification, not a command error. |
| `2`  | A tool/user/environment error (bad config, missing lockfile, Docker unreachable, etc.).                                                                                                                                                                  |

## `veripatch scan`

Parses the lockfile, fetches advisories, ranks vulnerabilities, resolves a deterministic fix
per vuln, and writes `.veripatch/last-scan.json`.

Supported lockfiles: `package-lock.json` (v2/v3), `yarn.lock` (classic v1 and berry), and
`pnpm-lock.yaml` (v6/v9), auto-detected. When several are present, precedence is npm → yarn →
pnpm and a warning names each ignored file.

| Flag                 | Description                                                                                                                                                                                        |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--ci`               | Exit 1 only for vulnerabilities _new_ relative to `.veripatch/baseline.json` (or any, if no baseline exists).                                                                                      |
| `--dev` / `--no-dev` | Include/exclude devDependencies.                                                                                                                                                                   |
| `--severity <level>` | Minimum severity to report: `low\|medium\|high\|critical`.                                                                                                                                         |
| `--write-baseline`   | Accept every vulnerability found in _this_ scan as pre-existing debt — writes `.veripatch/baseline.json`. Run once, commit the file, then use `--ci` in CI to fail only on genuinely new findings. |

No lockfile present → **degraded mode**: dependencies are inferred from `package.json` ranges
pinned to their minimum satisfying version, a banner warns results are incomplete, and `verify`
refuses to run (there's no exact resolved tree to reproduce).

## `veripatch verify [vulnId]`

Requires a reachable Docker daemon. Re-runs `scan` internally if `last-scan.json` is missing or
older than 24 hours. npm projects only for now — the sandbox replays fixes with npm, so yarn
and pnpm projects get an explicit refusal (`scan` fully supports them; see the roadmap).

| Flag                 | Description                                                                                                                                                                |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--all`              | Verify every feasible vulnerability from the last scan, continuing past individual FAILs.                                                                                  |
| `--severity <level>` | With `--all`, only verify vulns at/above this severity.                                                                                                                    |
| `--concurrency <n>`  | Sandbox verifications to run in parallel (1–8, default from `verifyConcurrency` config). Output is buffered per candidate and printed in order, so it stays deterministic. |

Prints a live per-step ticker (✅/❌/–) and, on completion, the confidence verdict. Persists run
artifacts to `.veripatch/runs/<runId>/` (each step's log tail plus the full `VerificationResult`
as `result.json`).

## `veripatch report [vulnId]`

Re-renders an evidence report from stored artifacts — never re-runs `scan` or `verify`. Merges
the most recent verification (from `.veripatch/runs/*/result.json`) into the last scan before
rendering.

| Flag                | Description                                                                                                                                     |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `--format <format>` | `md` (default), `json`, or `pr-comment` (GitHub-flavored, wraps step logs in `<details>`; what the GitHub Action posts as a sticky PR comment). |

Always writes both `report.json` and `report.md` (or `report-<vulnId>.{json,md}` for a single
vuln) to the report directory, and prints the requested `--format` to stdout for piping into CI.

## `veripatch update <vulnId>`

Applies a verified fix to the **real** working tree by replaying the exact change the sandbox
proved safe: `npm install <pkg>@<to> --package-lock-only` for direct dependencies, or an npm
`overrides` entry + lockfile regeneration for transitive ones. Never commits, never pushes;
prints a diff summary and a suggested commit message.

Refuses unless:

- the vuln's last verification confidence is `HIGH` or `MEDIUM` (`--force` overrides, with a
  warning — not recommended),
- the git working tree is clean (`--allow-dirty` overrides).

## `veripatch doctor`

Diagnoses the environment: Node ≥20, Docker reachability, whether the sandbox image can be
pulled, lockfile presence, OSV.dev reachability, advisory-cache writability, config validity.
Each check is independent — one failure doesn't block the rest from reporting. Exit `1` if any
check fails (the one command where a non-zero exit isn't reserved for "vulnerabilities found").

## `veripatch baseline list|add|remove|prune`

Manages accepted pre-existing debt (`.veripatch/baseline.json`) one finding at a time —
`scan --write-baseline` remains the all-at-once form.

| Subcommand        | Description                                                                                                                                                       |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `list`            | Every baselined vuln with its reason, added date, and expiry (`[EXPIRED]` when lapsed).                                                                           |
| `add <vulnId>`    | Accept one finding from the last scan as debt. `--reason <text>` records why; `--expires-days <n>` makes the acceptance lapse, after which the vuln is new again. |
| `remove <vulnId>` | Stop accepting a vuln as debt (removes every package entry for that advisory).                                                                                    |
| `prune`           | Drop entries whose vulns no longer appear in the last scan — debt that's been paid off.                                                                           |

Entries always come from real findings in `last-scan.json`, never from arbitrary ids.

## `veripatch cache clear|stats`

`clear` empties the local advisory cache (`~/.veripatch/cache.db`). `stats` prints row counts,
on-disk size, and the age of the oldest/newest cached entry.
