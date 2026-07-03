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
- [ ] **M7 — Reports + `update` + `doctor`**: JSON/MD/pr-comment evidence reports, safe
      fix apply with refusal rules, environment diagnostics, cache utilities.
- [ ] **M8 — GitHub Action + docs + release**: composite action, full documentation set,
      changesets + provenance publish, v0.1.0.

## Post-MVP (Phase 2+)

- yarn / pnpm lockfile adapters; npm workspaces & monorepos
- Parallel verification with a job pool
- Reachability analysis (call-graph priority downgrade)
- GitHub App (webhook verify queue, gVisor/Firecracker sandbox)
- VS Code extension; AI-assisted explanations (AI explains, never decides)
- SaaS/enterprise (hosted verification, SSO, audit logs) — CLI stays free

See [blueprint §15](../VeriPatch_BLUEPRINT.md) for the full future roadmap.
