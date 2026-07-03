# Security

## Threat model

**Assets:** the user's source code and secrets, the integrity of a verification verdict, the
host machine running VeriPatch.

**Trust boundaries:**

1. **The scanned project's files** — attacker-controlled input. A `package.json`,
   `package-lock.json`, or installed package can be hostile (crafted to exploit the parser, or
   to run malicious code during install).
2. **OSV.dev's network data** — trusted but validated; a malformed or malicious-looking
   advisory is dropped and counted, never trusted blindly.
3. **The Docker sandbox** — untrusted execution. Anything that runs during `verify` (the
   project's own `npm ci`, build, and test commands) is assumed hostile.

## Mitigations

| Vector                                                     | Mitigation                                                                                                                                                                                                                                                                                                                                                                             |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Malicious `postinstall` in a scanned/bumped dependency     | `npm ci --ignore-scripts` during the sandboxed install step — the script never executes at all, regardless of the container's network state at that point.                                                                                                                                                                                                                             |
| Sandbox container itself                                   | Non-root user (`1000:1000`), `--cap-drop=ALL`, `--security-opt=no-new-privileges`, pid/memory/cpu limits, `--rm` on teardown. Bind-mounts a **staged copy** of the project (`adapters/sandbox/copy.ts`), excluding `node_modules`, `.git`, and any `.env*` file — the container never touches the original working tree or secrets.                                                    |
| Sandbox network                                            | Two phases: a dedicated per-run bridge network during `install`, then fully disconnected before `build`/`test`. This constrains _which network_ the container is attached to, not _which domains_ it can reach — see the residual risk below.                                                                                                                                          |
| Hostile `package.json` / `package-lock.json` / `yarn.lock` | Size-capped before parsing (50MB default), `JSON.parse`/strict-grammar parsers only (never eval), recursive `__proto__`/`constructor`/`prototype` stripping so no later object spread can pollute a prototype, package names validated against the real npm name grammar. yarn classic is parsed by a deliberately rigid grammar — anything outside it is a hard error, never a guess. |
| Poisoned advisory data                                     | HTTPS with certificate validation; every advisory is zod-validated at the OSV adapter boundary; the rule engine's same-package invariant means a "fix" can only ever be a version bump of the _same_ package, never a substitution — enforced structurally in `core/rules/fix-resolver.ts` and covered by property-based tests.                                                        |
| Dependency confusion                                       | `npm ci` resolves strictly from the lockfile's recorded URLs and integrity hashes; a missing integrity entry is a finding, not silently accepted.                                                                                                                                                                                                                                      |
| Report/terminal injection                                  | Every externally sourced string (advisory text, package names, sandboxed process output) is ANSI-stripped and, in Markdown reports, metacharacter-escaped before it renders (`shared/sanitize.ts`).                                                                                                                                                                                    |
| VeriPatch's own supply chain                               | Minimal dependencies, committed lockfile, GitHub Actions pinned by commit SHA, `npm publish --provenance`.                                                                                                                                                                                                                                                                             |
| Privilege on the host                                      | VeriPatch itself only ever writes inside `.veripatch/` (project-local) and `~/.veripatch/` (the advisory cache) — zero telemetry, no secrets handled.                                                                                                                                                                                                                                  |

## Documented residual risks

- **Network isolation is bridge-level, not domain-level.** The install phase's network gives
  the container general egress (matching what installing from the real npm registry requires),
  not an allowlist restricted to the registry alone. A postinstall script _could_ attempt
  network egress during that phase — the actual defense against that specific attack is
  `--ignore-scripts`, not the network boundary. If a future release needs domain-level
  filtering (e.g. for registries not reachable in the container's DNS), that's a real
  enhancement, not a solved problem today.
- **Verdict integrity reflects the project's own checks, not their honesty.** A HIGH or MEDIUM
  confidence verdict means "the project's own build/test commands exited 0" — a project could
  have a build script that always exits 0 regardless of what actually happened. VeriPatch's
  rescan step independently re-checks that the _vulnerability itself_ is gone (that part is not
  self-reported), but it does not re-verify the project's own test assertions. This is stated
  explicitly in every `VerificationResult.residualRisks`.
- **Kernel-sharing.** Docker containers share the host kernel; a container-escape
  vulnerability in the Docker runtime itself is out of scope for VeriPatch to mitigate. A future
  SaaS/multi-tenant phase would need gVisor or Firecracker-level isolation for untrusted repos
  at scale (see [docs/ROADMAP.md](ROADMAP.md)).

## Reporting a vulnerability

Please email **security@veripatch.dev** (or open a private
[GitHub Security Advisory](https://github.com/amarjaleelbanbhan/VeriPatch/security/advisories/new)
if you'd rather not email) with a description and reproduction steps. We aim to acknowledge
within 48 hours and to ship a fix or mitigation within 90 days of confirmation, whichever is
sooner. Please don't open a public issue for undisclosed vulnerabilities.
