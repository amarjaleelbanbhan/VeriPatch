# ADR 0003: Docker for sandboxed verification, not child_process

## Status

Accepted (M6).

## Context

`verify` must run untrusted code: the scanned project's own `npm install`, build, and test
commands, potentially including a malicious dependency's `postinstall` script. This cannot run
directly on the host.

## Decision

Run every step inside a hardened Docker container (`adapters/sandbox/`): non-root, all
capabilities dropped, `no-new-privileges`, pid/memory/cpu-limited, network-phased
(registry-only during install via a dedicated per-run bridge network, fully disconnected before
build/test), operating on a staged copy of the project rather than the original tree.

## Alternatives considered

- **Plain `child_process` on the host** — explicitly forbidden by the project's own design goals:
  no isolation at all between a malicious dependency's install script and the user's machine.
- **gVisor / Firecracker microVMs** — stronger isolation (no shared kernel), but heavier
  operational requirements (a compatible host kernel, more complex CI setup) that don't fit an
  individual developer's laptop or a standard GitHub-hosted CI runner. Documented as the
  intended upgrade path for a future GitHub App phase serving untrusted repos at scale (see
  [docs/ROADMAP.md](../ROADMAP.md)).

## Why Docker (for now)

- Available by default on GitHub-hosted `ubuntu-latest` runners and via Docker
  Desktop/`docker.io` on developer machines — no exotic setup required for the MVP's target
  audience.
- `dockerode` gives programmatic control over every hardening flag needed (cap-drop,
  security-opt, resource limits) without shelling out to the `docker` CLI.
- Structural interfaces (`SandboxRuntime`, `ContainerHandle`, `NetworkHandle` in
  `adapters/sandbox/docker.ts`) decouple the orchestration logic from dockerode concretely, so
  the pipeline sequencing itself is fully unit-tested with in-memory fakes — no Docker daemon
  needed to verify that a failing `install` step correctly skips `build`/`test`, for example.

## Consequences

- **Accepted, documented residual risk:** containers share the host kernel. A Docker-runtime
  escape is out of scope for VeriPatch to mitigate on its own.
- **Accepted, documented residual risk:** the network phase boundary constrains which network
  the container is on, not which domains it can reach — a postinstall script could still attempt
  egress during the still-networked install phase. The actual defense against that specific
  attack is `npm ci --ignore-scripts`, not the network boundary; see
  [docs/SECURITY.md](../SECURITY.md).
- `verify` requires Docker; `scan` deliberately does not, so the core value (ranked, prioritized
  findings) is available to everyone regardless of their local Docker setup.
