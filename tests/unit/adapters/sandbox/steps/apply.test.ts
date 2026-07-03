import { describe, expect, it, vi } from 'vitest';
import { runApplyStep } from '../../../../../src/adapters/sandbox/steps/apply.js';
import type { FixCandidate } from '../../../../../src/core/models/index.js';

const candidate: FixCandidate = {
  vulnId: 'GHSA-1',
  pkg: 'axios',
  from: '1.5.0',
  to: '1.6.0',
  bumpType: 'minor',
  strategy: 'direct',
  feasible: true,
};

describe('runApplyStep', () => {
  it('runs npm install pkg@to --package-lock-only', async () => {
    const exec = vi
      .fn()
      .mockResolvedValue({ exitCode: 0, output: 'up to date', timedOut: false, durationMs: 10 });
    const step = await runApplyStep({ exec }, candidate, 5000);

    expect(exec).toHaveBeenCalledWith(
      ['npm', 'install', 'axios@1.6.0', '--package-lock-only'],
      5000,
    );
    expect(step).toMatchObject({ step: 'apply', status: 'pass' });
  });

  it('reports a failing apply as fail', async () => {
    const exec = vi
      .fn()
      .mockResolvedValue({ exitCode: 1, output: 'ETARGET', timedOut: false, durationMs: 5 });
    const step = await runApplyStep({ exec }, candidate, 5000);
    expect(step.status).toBe('fail');
  });

  describe('override strategy (transitive dependency)', () => {
    const overrideCandidate: FixCandidate = { ...candidate, strategy: 'override' };

    it('writes an overrides entry, then regenerates the lockfile — never installs pkg@to', async () => {
      const exec = vi
        .fn()
        .mockResolvedValue({ exitCode: 0, output: '', timedOut: false, durationMs: 10 });
      const step = await runApplyStep({ exec }, overrideCandidate, 5000);

      expect(exec).toHaveBeenCalledTimes(2);
      const [nodeCmd] = exec.mock.calls[0] as [string[]];
      expect(nodeCmd[0]).toBe('node');
      expect(nodeCmd[1]).toBe('-e');
      // pkg and version travel as argv, not interpolated into the script
      expect(nodeCmd.slice(-2)).toEqual(['axios', '1.6.0']);
      expect(exec).toHaveBeenLastCalledWith(['npm', 'install', '--package-lock-only'], 5000);
      expect(step).toMatchObject({ step: 'apply', status: 'pass' });
    });

    it('fails fast when the manifest edit itself fails', async () => {
      const exec = vi
        .fn()
        .mockResolvedValue({ exitCode: 1, output: 'EACCES', timedOut: false, durationMs: 5 });
      const step = await runApplyStep({ exec }, overrideCandidate, 5000);
      expect(exec).toHaveBeenCalledTimes(1);
      expect(step.status).toBe('fail');
    });
  });
});
