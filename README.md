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

## Status

🚧 **Under active development — pre-release.** The roadmap to v0.1.0 is tracked in
[docs/ROADMAP.md](docs/ROADMAP.md).

## Planned quickstart

```bash
npm install -g veripatch
veripatch doctor          # diagnose environment (Node, Docker, lockfile, network)
veripatch scan            # ranked vulnerability table in <15s
veripatch verify CVE-...  # sandboxed proof the fix is safe
veripatch update CVE-...  # apply a verified fix to your working tree
```

## Design principles

- **Verification-first** — confidence verdicts derive only from exit codes and VeriPatch's own
  re-scan, never from log-text heuristics.
- **Security-first** — untrusted project code only ever executes inside a hardened,
  network-restricted container. Zero telemetry. No secrets required.
- **CI-native** — machine-readable `report.json`, deterministic exit codes, baseline mode so
  pre-existing debt doesn't fail builds.

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) (coming with M8). Until then, issues and
discussion are welcome.

## License

[Apache-2.0](LICENSE)
