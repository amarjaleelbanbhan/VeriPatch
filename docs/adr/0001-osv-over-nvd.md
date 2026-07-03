# ADR 0001: OSV.dev over NVD as the advisory source

## Status

Accepted (M3).

## Context

VeriPatch needs a source of npm vulnerability advisories: id, affected version ranges, severity,
and a fixed version where one exists.

## Decision

Use [OSV.dev](https://osv.dev) exclusively.

## Alternatives considered

- **NVD (NIST National Vulnerability Database)** — the "canonical" federal source, but keyed by
  CPE (Common Platform Enumeration), an awkward, error-prone match against npm package names and
  ecosystems. Version-range data is inconsistent in format.
- **Snyk's vulnerability database** — high quality but closed/commercial; would require an API
  key and a paid tier for meaningful volume, conflicting with the zero-secrets, zero-telemetry
  design goal.

## Why OSV.dev

- Ecosystem-native: queries are `{package: {name, ecosystem: "npm"}, version}`, not CPE strings.
- Aggregates GHSA (GitHub Security Advisories), which covers the overwhelming majority of
  npm-relevant disclosures, plus its own OSV-native entries.
- A real batch endpoint (`/v1/querybatch`, ≤1000 queries/call) — essential for scanning a
  1,500-dependency project inside the <15s warm-scan budget.
- Unauthenticated — no API key, no secret to manage or leak.

## Consequences

- OSV's per-advisory enrichment (references, deeper CWE/CVSS metadata) is thinner than NVD's in
  some cases — accepted; VeriPatch computes its own CVSS base score from the vector string when
  present (`adapters/osv/cvss.ts`) rather than depending on NVD's score field.
- OSV.dev availability/rate limits are a real dependency — mitigated by the SQLite cache with a
  24h default TTL and offline stale-serve (`ADR 0002`).
