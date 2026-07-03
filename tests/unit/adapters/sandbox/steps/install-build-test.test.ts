import { describe, expect, it, vi } from 'vitest';
import { runBuildStep } from '../../../../../src/adapters/sandbox/steps/build.js';
import { runInstallStep } from '../../../../../src/adapters/sandbox/steps/install.js';
import { runTestStep } from '../../../../../src/adapters/sandbox/steps/test.js';

describe('runInstallStep', () => {
  it('runs npm ci with scripts suppressed (postinstall defense)', async () => {
    const exec = vi
      .fn()
      .mockResolvedValue({ exitCode: 0, output: '', timedOut: false, durationMs: 100 });
    const step = await runInstallStep({ exec }, 60_000);
    expect(exec).toHaveBeenCalledWith(['npm', 'ci', '--ignore-scripts'], 60_000);
    expect(step).toMatchObject({ step: 'install', status: 'pass' });
  });

  it('surfaces a timeout distinctly from a failure', async () => {
    const exec = vi
      .fn()
      .mockResolvedValue({ exitCode: -1, output: '', timedOut: true, durationMs: 60_000 });
    const step = await runInstallStep({ exec }, 60_000);
    expect(step.status).toBe('timeout');
  });
});

describe('runBuildStep', () => {
  it('runs the configured build command through a shell', async () => {
    const exec = vi
      .fn()
      .mockResolvedValue({ exitCode: 0, output: '', timedOut: false, durationMs: 5 });
    await runBuildStep({ exec }, 'npm run build', 10_000);
    expect(exec).toHaveBeenCalledWith(['sh', '-c', 'npm run build'], 10_000);
  });

  it('skips without executing when no build command is configured', async () => {
    const exec = vi.fn();
    const step = await runBuildStep({ exec }, '', 10_000);
    expect(exec).not.toHaveBeenCalled();
    expect(step).toEqual({ step: 'build', status: 'skipped', durationMs: 0, logTail: '' });
  });
});

describe('runTestStep', () => {
  it('runs the configured test command and attaches parsed counts', async () => {
    const exec = vi.fn().mockResolvedValue({
      exitCode: 0,
      output: 'Tests  5 passed (5)',
      timedOut: false,
      durationMs: 20,
    });
    const step = await runTestStep({ exec }, 'npm test', 60_000);
    expect(exec).toHaveBeenCalledWith(['sh', '-c', 'npm test'], 60_000);
    expect(step.testCounts).toEqual({ passed: 5, failed: 0, total: 5 });
  });

  it('omits testCounts when the output has no recognizable summary', async () => {
    const exec = vi
      .fn()
      .mockResolvedValue({ exitCode: 0, output: 'ok', timedOut: false, durationMs: 20 });
    const step = await runTestStep({ exec }, 'npm test', 60_000);
    expect(step.testCounts).toBeUndefined();
  });

  it('skips without executing when no test command is configured', async () => {
    const exec = vi.fn();
    const step = await runTestStep({ exec }, '   ', 60_000);
    expect(exec).not.toHaveBeenCalled();
    expect(step.status).toBe('skipped');
  });
});
