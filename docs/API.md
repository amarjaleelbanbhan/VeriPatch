# API Reference

VeriPatch has no HTTP server. This document covers its three real API surfaces: the
`report.json` machine output, the ports adapters implement, and OSV.dev usage.

## `report.json` (schemaVersion 1)

Fields are only ever **added**, never removed or repurposed, within a schema version — CI
pipelines can depend on this shape being stable. Full zod schema:
[`src/core/models/scan-output.ts`](../src/core/models/scan-output.ts).

```json
{
  "schemaVersion": 1,
  "tool": { "name": "VeriPatch", "version": "0.1.0" },
  "generatedAt": "2026-01-01T00:00:00.000Z",
  "scan": {
    "lockfileVersion": 3,
    "degraded": false,
    "totalDeps": 1243,
    "dataErrors": 0,
    "stale": false
  },
  "vulns": [
    {
      "id": "GHSA-xxxx-yyyy-zzzz",
      "aliases": ["CVE-2026-1111"],
      "pkg": "axios",
      "installed": "1.5.0",
      "severity": { "cvss": 7.5, "label": "HIGH" },
      "dev": false,
      "paths": [["root", "axios"]],
      "fix": {
        "vulnId": "GHSA-xxxx-yyyy-zzzz",
        "pkg": "axios",
        "from": "1.5.0",
        "to": "1.6.2",
        "bumpType": "minor",
        "strategy": "direct",
        "feasible": true
      },
      "verification": null
    }
  ],
  "summary": { "critical": 0, "high": 1, "medium": 0, "low": 0, "verified": 0 }
}
```

`verification` is `null` until `veripatch verify` has run for that vuln, after which it holds
the full `VerificationResult` (steps, confidence, residual risks, run id). `scan.degraded: true`
means no lockfile was found — dependencies were inferred from `package.json` ranges, and
`verify` will refuse to run.

## Ports

Every adapter implements a `core`-defined interface (`src/core/ports.ts`); a shared behavioral
contract test suite (`tests/contract/`) runs against each implementation.

```ts
interface LockfileParser {
  parse(projectDir: string): Result<DepGraph>;
}

interface AdvisorySource {
  getAdvisories(nodes: DepNode[]): Promise<Result<AdvisoryLookup>>;
  // AdvisoryLookup: { advisories: Advisory[]; stale: boolean; dataErrors: number }
}

interface Sandbox {
  run(plan: SandboxPlan, onStep?: (step: StepResult) => void): Promise<Result<StepResult[]>>;
}

interface Reporter {
  write(
    results: ScanOutput | VerificationResult,
    dir: string,
  ): Result<{ jsonPath: string; mdPath: string }>;
}
```

`Result<T>` is `{ ok: true; value: T } | { ok: false; error: AppError }` — no thrown strings
cross a service boundary anywhere in the codebase. `AppError.kind` is one of `UserError`
(fixable by the caller, exit 2 with a hint), `WorldError` (environment/network, degrade
honestly where possible), or `InternalError` (a VeriPatch bug).

## OSV.dev usage

VeriPatch is an unauthenticated consumer of [OSV.dev](https://osv.dev) — no API key, no
secrets.

- `POST /v1/querybatch` — `{ queries: [{ package: { name, ecosystem: "npm" }, version }] }` →
  advisory-id refs per query. Chunked at the API's 1000-query limit.
- `GET /v1/vulns/{id}` — full advisory JSON, validated against a local zod schema
  (`src/adapters/osv/schema.ts`); an advisory failing validation is dropped and counted in
  `scan.dataErrors`, never silently trusted.
- Retry policy: `429` → exponential backoff with jitter (max 3 attempts); `5xx` → retried twice
  before becoming a `WorldError`; every call has a 10s timeout.
- Results are cached in SQLite (`~/.veripatch/cache.db`) with a configurable TTL
  (`cacheTtlHours`); an expired cache entry is still served offline, flagged `stale: true`, when
  OSV.dev is unreachable — but a package with _no_ cached data at all fails loudly rather than
  silently reporting "no vulnerabilities" for something never actually checked.
