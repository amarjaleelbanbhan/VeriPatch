# VeriPatch

> Verified remediation for npm vulnerabilities — don't just detect, **prove the fix is safe**.

[![CI](https://github.com/amarjaleelbanbhan/VeriPatch/actions/workflows/ci.yml/badge.svg)](https://github.com/amarjaleelbanbhan/VeriPatch/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Detection of vulnerable npm dependencies is commoditized (`npm audit`, Dependabot, Snyk).
**Verified remediation is not.** Engineers don't apply fixes because of alert fatigue, fear
of breakage, and lack of evidence. VeriPatch closes the gap:

1. **Scan** — rank vulnerabilities by severity × fix feasibility (via [OSV.dev](https://osv.dev)).
2. **Verify** — apply the fix in a hardened Docker sandbox, re-scan to prove the vulnerability
   left the resolved tree, run your build and tests to prove nothing breaks.
3. **Report** — emit audit-grade evidence reports (Markdown + JSON) with deterministic
   confidence verdicts.

## Quickstart

```bash
npm install -g veripatch

veripatch doctor              # diagnose environment (Node, Docker, lockfile, network)
veripatch scan                # ranked vulnerability table in <15s
veripatch verify GHSA-...     # sandboxed proof a fix is safe
veripatch update GHSA-...     # apply a verified fix to your working tree
veripatch report GHSA-...     # re-render evidence without re-running anything
```

`scan` and `report` work everywhere; `verify` requires a reachable Docker daemon.

`scan` understands `package-lock.json` (v2/v3), `yarn.lock` (classic and berry), and
`pnpm-lock.yaml` (v6/v9), auto-detected. `verify`/`update` currently replay fixes with npm, so
they refuse yarn/pnpm projects explicitly rather than corrupting them.

### As a GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: amarjaleelbanbhan/VeriPatch@v0.1.0
  with:
    severity-threshold: high
    fail-on: new
```

See [examples/workflow.yml](examples/workflow.yml) for the full example (triggers, permissions,
baseline mode) and [action.yml](action.yml) for every input.

## How it works

```
scan  → parse lockfile → OSV advisories → rule engine → ranked, fix-resolved report
verify → stage a copy → apply the bump → install (sandboxed, scripts off)
       → re-scan the copy to prove the vuln is gone → build/test (network off)
       → deterministic verdict from exit codes + the re-scan alone
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full data flow and layering.

## Design principles

- **Verification-first** — confidence verdicts derive only from exit codes and VeriPatch's own
  re-scan, never from log-text heuristics (see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)).
- **Security-first** — untrusted project code only ever executes inside a hardened,
  network-restricted container. Zero telemetry. No secrets required. See
  [docs/SECURITY.md](docs/SECURITY.md).
- **CI-native** — machine-readable `report.json` ([docs/API.md](docs/API.md)), deterministic
  exit codes, baseline mode so pre-existing debt doesn't fail builds.

## Documentation

|                                                |                                                                      |
| ---------------------------------------------- | -------------------------------------------------------------------- |
| [docs/CLI.md](docs/CLI.md)                     | Full command reference, flags, exit codes                            |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | `.veripatchrc` reference and precedence                              |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)   | Layering, data flow, confidence rules                                |
| [docs/API.md](docs/API.md)                     | `report.json` schema, ports, OSV usage                               |
| [docs/SECURITY.md](docs/SECURITY.md)           | Threat model, sandbox guarantees, disclosure policy                  |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)   | Setup, layering rules, fixture-adding guide                          |
| [docs/ROADMAP.md](docs/ROADMAP.md)             | What's shipped, what's next                                          |
| [docs/adr/](docs/adr/)                         | Why OSV over NVD, SQLite over Postgres, Docker over subprocess, etc. |

## Status

All MVP milestones (scan, verify, report/update/doctor/cache, GitHub Action) are implemented
and tested. Pre-1.0: the CLI contract and `report.json` schema are considered stable but not
yet field-proven — see [docs/ROADMAP.md](docs/ROADMAP.md) for what's tracked toward v1.0.

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md). Issues and discussion are welcome.

## License

[Apache-2.0](LICENSE)
