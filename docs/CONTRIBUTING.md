# Contributing

## Setup

```bash
git clone https://github.com/amarjaleelbanbhan/VeriPatch.git
cd VeriPatch
npm install
npm run check   # typecheck + lint + format:check + test
```

Docker is only required to exercise `verify` end-to-end and the real-Docker security e2e suite
(`tests/e2e/security/`) — both self-skip gracefully without a daemon, so you can develop
everything else without it. `npm run build` produces `dist/cli.js`; `node dist/cli.js <command>`
runs it directly.

## Layering rules

`cli → services → core ← adapters`, with `shared` reachable from anywhere. This is enforced by
ESLint (`eslint-plugin-boundaries` + a `no-restricted-imports` rule scoped to `src/core/`), not
just convention — a cross-layer import fails `npm run lint`. See
[docs/ARCHITECTURE.md](ARCHITECTURE.md) for what belongs where. In short:

- New domain logic (matching, severity, fix resolution, confidence) → `core/`, pure, no I/O.
- New I/O (a different lockfile format, a different advisory source) → `adapters/`, implementing
  a `core`-defined port.
- New orchestration → `services/`, depending only on ports and `core`/`shared`.
- New CLI surface → `cli/commands/`, wiring concrete adapters into a service.

## Testing

- **Unit** (`tests/unit/`) mirrors `src/` — one file per module, table-driven fixtures for edge
  cases (semver ranges, CVSS vectors, config precedence).
- **Integration** (`tests/integration/`) exercises real fixture files and a mocked network
  (`msw`) — no live network calls in the default test run.
- **Contract** (`tests/contract/`) is a shared behavioral suite per port; if you add a second
  implementation of an existing port, it must pass the same suite as the first.
- **e2e/security** (`tests/e2e/security/`) needs a real Docker daemon; it self-skips otherwise.
  It runs for real on `ubuntu-latest` in CI (Docker is preinstalled there) and is a no-op on
  `macos-latest`.
- **bench** (`tests/bench/`) enforces the pure rule-engine pipeline's perf budget.

Coverage gate: ≥90% on `src/core` (`vitest.config.ts`), checked in CI via `npm run test:coverage`.

## Adding a fixture

Lockfile/OSV fixtures live in `tests/fixtures/`. When you fix a bug, add the fixture that
reproduces it alongside the fix — this is the regression corpus behind the project's
verification-verdict accuracy metric.

## Commit style

[Conventional Commits](https://www.conventionalcommits.org/): `feat|fix|chore|docs|test|ci|refactor(scope): message`.
Enforced in CI via commitlint on pull requests. One logical change per commit.

## Pull request checklist

- [ ] `npm run check` passes locally
- [ ] New behavior has a test; a bug fix has a regression fixture
- [ ] Public-facing changes (CLI flags, `report.json` shape, config keys) are reflected in
      `docs/CLI.md` / `docs/API.md` / `docs/CONFIGURATION.md`
- [ ] Commit messages follow Conventional Commits
