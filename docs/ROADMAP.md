# VeriPatch Roadmap

Source of truth for delivery status. Milestones come from the
[implementation blueprint](../VeriPatch_BLUEPRINT.md) (§10–§11); each milestone lands as a
train of small Conventional-Commit changes.

## MVP → v0.1.0

- [x] **M0 — Repo bootstrap**: toolchain (TS strict, tsup, ESLint layer boundaries, Prettier,
      Vitest + coverage), CI matrix, layered skeleton, license and docs stubs.
- [x] **M1 — Core models + config**: domain types with zod schemas, `Result<T>`/`AppError`,
      structured logger with redaction, config loader with 4-layer precedence.
- [x] **M2 — Lockfile parser**: hardened reader (size cap, null-proto), package-lock v2/v3
      walkers, degraded mode (no lockfile), hostile-input corpus, contract tests.
- [x] **M3 — Advisory client + cache**: OSV querybatch client (chunking, retry/backoff),
      detail hydration, SQLite cache with TTL + offline stale-serve, sanitizer.
- [x] **M4 — Rule engine**: semver vulnerability matching (edge-case table), severity
      ranking + filters, deterministic fix resolution (direct/override/parent-bump),
      same-package invariant.
- [x] **M5 — `scan` command**: ScanService, ranked table renderer, `--json`, exit-code
      mapper, `last-scan.json`, `--ci` baseline diff, perf budget (<15s warm on 1,500 deps).
- [x] **M6 — Sandbox + `verify`**: staging copy, hardened Docker runtime (non-root,
      cap-drop, network phases), pipeline steps, deterministic confidence, security e2e.
- [x] **M7 — Reports + `update` + `doctor`**: JSON/MD/pr-comment evidence reports, safe
      fix apply with refusal rules, environment diagnostics, cache utilities.
- [x] **M8 — GitHub Action + docs + release**: composite action, full documentation set,
      changesets + provenance publish pipeline, v0.1.0 cut. The actual first `npm publish` is
      blocked on npm-side setup only this repo's owner can perform — see the note below.

### Publishing v0.1.0 (owner action required)

All MVP engineering is done and `release.yml` is ready to run, but the very first publish needs
two things only the npm/GitHub account owner can set up:

1. **npm trusted publishing (OIDC)** — on the `veripatch` package's npm settings, add this repo
   (`amarjaleelbanbhan/VeriPatch`) and the `release.yml` workflow as a trusted publisher. This
   is what lets `release.yml`'s `id-token: write` permission authenticate to npm without a
   long-lived `NPM_TOKEN` secret.
2. **First publish** — since npm requires the package name to not already exist for trusted
   publishing to be configurable, the very first `npm publish` for a brand-new package name may
   need to happen once manually (`npm publish --provenance` from a maintainer's authenticated
   machine) before OIDC trust can be attached; after that, `release.yml` takes over for every
   subsequent version.

Once those are in place, merging the changesets bot's "Version Packages" PR triggers the actual
publish automatically — no further manual steps.

## Phase 2 (v0.2.x)

- [x] **M9 — yarn lockfile adapter**: classic (v1) strict-grammar parser + berry (v2+) YAML,
      package.json-derived dev/direct reachability, CLI auto-detection with npm-precedence,
      explicit verify/update refusal (the sandbox replays fixes with npm only for now).
- [ ] **M10 — pnpm lockfile adapter**: pnpm-lock.yaml v6/v9 → DepGraph, same corpus discipline.
- [ ] **M11 — npm workspaces / monorepos**: per-workspace attribution, scan/verify from the root.
- [ ] **M12 — parallel verification**: bounded job pool, deterministic result ordering.
- [ ] **M13 — baseline management UX + richer overrides strategies.**

## Later phases

- Reachability analysis (call-graph priority downgrade)
- GitHub App (webhook verify queue, gVisor/Firecracker sandbox)
- VS Code extension; AI-assisted explanations (AI explains, never decides)
- SaaS/enterprise (hosted verification, SSO, audit logs) — CLI stays free

See [blueprint §15](../VeriPatch_BLUEPRINT.md) for the full future roadmap.
