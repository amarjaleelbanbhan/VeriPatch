# ADR 0004: Vitest over Jest

## Status

Accepted (M0).

## Context

The project is TypeScript-strict, pure ESM (`"type": "module"`, `NodeNext` module resolution),
and needs fast unit tests plus a coverage gate in CI.

## Decision

Vitest, with the `@vitest/coverage-v8` provider.

## Alternatives considered

- **Jest** — the incumbent, widely known, but native ESM support has historically required
  extra transform configuration and flags; TypeScript-strict + `NodeNext` + Jest has more sharp
  edges than a test runner built ESM-first.

## Why Vitest

- Native ESM and TypeScript support with no separate transform config — the test files import
  the same `.js`-extensioned specifiers as the source under `NodeNext` resolution, unmodified.
- Fast: shares Vite's module graph and transform pipeline, and its watch mode only re-runs
  affected tests.
- A JSON/V8 coverage reporter integrates directly with the ≥90% `src/core` gate in
  `vitest.config.ts`, checked in CI via `npm run test:coverage`.
- `vi.fn()`/`vi.mock()` cover the same mocking needs as Jest's API with a near-identical surface,
  keeping the learning curve flat for contributors coming from Jest.

## Consequences

- Slightly younger ecosystem than Jest's for edge-case plugins — not a real constraint so far;
  every testing need so far (msw for network mocking, fast-check for property-based tests) has
  worked with Vitest without friction.
