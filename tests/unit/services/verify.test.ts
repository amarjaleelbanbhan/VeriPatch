import { describe, expect, it } from 'vitest';
import { verifyCandidate } from '../../../src/services/verify.js';
import type { FixCandidate, StepResult } from '../../../src/core/models/index.js';
import type { Sandbox, SandboxPlan, StepListener } from '../../../src/core/ports.js';
import { AppError } from '../../../src/shared/errors.js';
import { err, ok } from '../../../src/shared/result.js';

const candidate: FixCandidate = {
  vulnId: 'GHSA-1',
  pkg: 'axios',
  from: '1.5.0',
  to: '1.6.0',
  bumpType: 'minor',
  strategy: 'direct',
  feasible: true,
};

const config = {
  testCommand: 'npm test',
  buildCommand: 'npm run build',
  verifyTimeoutMin: 10,
  sandboxImage: 'node:20-slim',
};

function fakeSandbox(steps: StepResult[]): Sandbox {
  return {
    run: (_plan: SandboxPlan, onStep?: StepListener) => {
      for (const step of steps) onStep?.(step);
      return Promise.resolve(ok(steps));
    },
  };
}

function step(overrides: Partial<StepResult> & Pick<StepResult, 'step'>): StepResult {
  return { status: 'pass', durationMs: 1, logTail: '', ...overrides };
}

describe('verifyCandidate', () => {
  it('computes HIGH confidence when everything passes with real tests', async () => {
    const sandbox = fakeSandbox([
      step({ step: 'copy' }),
      step({ step: 'apply' }),
      step({ step: 'install', exitCode: 0 }),
      step({ step: 'rescan' }),
      step({ step: 'build', exitCode: 0 }),
      step({ step: 'test', exitCode: 0, testCounts: { passed: 5, failed: 0, total: 5 } }),
    ]);

    const result = await verifyCandidate(sandbox, { projectDir: '/p', candidate, config });
    if (!result.ok) throw result.error;
    expect(result.value.confidence).toBe('HIGH');
    expect(result.value.candidate).toBe(candidate);
    expect(result.value.runId).toMatch(/^[0-9a-f-]{36}$/);
    expect(result.value.startedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('computes FAIL when rescan shows the vuln is still present', async () => {
    const sandbox = fakeSandbox([
      step({ step: 'copy' }),
      step({ step: 'apply' }),
      step({ step: 'install', exitCode: 0 }),
      step({ step: 'rescan', status: 'fail' }),
      step({ step: 'build', status: 'skipped' }),
      step({ step: 'test', status: 'skipped' }),
    ]);

    const result = await verifyCandidate(sandbox, { projectDir: '/p', candidate, config });
    if (!result.ok) throw result.error;
    expect(result.value.confidence).toBe('FAIL');
  });

  it('propagates a sandbox infrastructure error as a Result error', async () => {
    const sandbox: Sandbox = {
      run: () => Promise.resolve(err(AppError.world('DOCKER_UNAVAILABLE', 'no docker'))),
    };
    const result = await verifyCandidate(sandbox, { projectDir: '/p', candidate, config });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('DOCKER_UNAVAILABLE');
  });

  it('drives the live step ticker via the onStep callback', async () => {
    const steps = [step({ step: 'copy' }), step({ step: 'apply' })];
    const sandbox = fakeSandbox(steps);
    const seen: string[] = [];

    await verifyCandidate(sandbox, { projectDir: '/p', candidate, config }, (s) =>
      seen.push(s.step),
    );
    expect(seen).toEqual(['copy', 'apply']);
  });

  it('flags no-test-coverage as a residual risk when the test step was skipped', async () => {
    const sandbox = fakeSandbox([
      step({ step: 'install', exitCode: 0 }),
      step({ step: 'rescan' }),
      step({ step: 'build', exitCode: 0 }),
      step({ step: 'test', status: 'skipped' }),
    ]);
    const result = await verifyCandidate(sandbox, { projectDir: '/p', candidate, config });
    if (!result.ok) throw result.error;
    expect(result.value.confidence).toBe('MEDIUM');
    expect(result.value.residualRisks.some((r) => r.includes('No test step ran'))).toBe(true);
  });

  it('always includes the verdict-integrity residual risk', async () => {
    const sandbox = fakeSandbox([
      step({ step: 'test', exitCode: 0, testCounts: { passed: 1, failed: 0, total: 1 } }),
    ]);
    const result = await verifyCandidate(sandbox, { projectDir: '/p', candidate, config });
    if (!result.ok) throw result.error;
    expect(result.value.residualRisks.some((r) => r.includes("project's own"))).toBe(true);
  });
});
