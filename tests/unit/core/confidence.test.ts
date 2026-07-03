import { describe, expect, it } from 'vitest';
import { computeConfidence } from '../../../src/core/confidence.js';
import type { StepResult } from '../../../src/core/models/index.js';

function step(overrides: Partial<StepResult> & Pick<StepResult, 'step'>): StepResult {
  return { status: 'pass', durationMs: 100, logTail: '', ...overrides };
}

const copyPass = step({ step: 'copy' });
const applyPass = step({ step: 'apply' });
const installPass = step({ step: 'install', exitCode: 0 });
const buildPass = step({ step: 'build', exitCode: 0 });
const rescanAbsent = step({ step: 'rescan', status: 'pass' });
const rescanPresent = step({ step: 'rescan', status: 'fail' });
const testPassWithCounts = step({
  step: 'test',
  exitCode: 0,
  testCounts: { passed: 10, failed: 0, total: 10 },
});
const testPassNoCounts = step({ step: 'test', status: 'skipped' });

describe('computeConfidence — exhaustive truth table (blueprint §2 priority order)', () => {
  it('rule 1: rescan shows the vuln still present -> FAIL, even if everything else passed', () => {
    const steps = [copyPass, applyPass, installPass, rescanPresent, buildPass, testPassWithCounts];
    expect(computeConfidence(steps)).toBe('FAIL');
  });

  it('rule 1 outranks rule 3: rescan fail beats a timeout elsewhere', () => {
    const steps = [
      copyPass,
      applyPass,
      step({ step: 'install', status: 'timeout' }),
      rescanPresent,
    ];
    expect(computeConfidence(steps)).toBe('FAIL');
  });

  it('rule 2: install exit != 0 -> FAIL (breaking)', () => {
    const steps = [
      copyPass,
      applyPass,
      step({ step: 'install', status: 'fail', exitCode: 1 }),
      rescanAbsent,
    ];
    expect(computeConfidence(steps)).toBe('FAIL');
  });

  it('rule 2: build exit != 0 -> FAIL', () => {
    const steps = [installPass, rescanAbsent, step({ step: 'build', status: 'fail', exitCode: 2 })];
    expect(computeConfidence(steps)).toBe('FAIL');
  });

  it('rule 2: test exit != 0 -> FAIL', () => {
    const steps = [
      installPass,
      rescanAbsent,
      buildPass,
      step({ step: 'test', status: 'fail', exitCode: 1 }),
    ];
    expect(computeConfidence(steps)).toBe('FAIL');
  });

  it('rule 2 outranks rule 3: a breaking exit beats a timeout in another step', () => {
    const steps = [
      installPass,
      rescanAbsent,
      step({ step: 'build', status: 'fail', exitCode: 1 }),
      step({ step: 'test', status: 'timeout' }),
    ];
    expect(computeConfidence(steps)).toBe('FAIL');
  });

  it('rule 3: any timeout with no rescan/breaking failure -> INCONCLUSIVE', () => {
    expect(
      computeConfidence([installPass, rescanAbsent, step({ step: 'build', status: 'timeout' })]),
    ).toBe('INCONCLUSIVE');
    expect(computeConfidence([step({ step: 'install', status: 'timeout' })])).toBe('INCONCLUSIVE');
    expect(
      computeConfidence([
        installPass,
        rescanAbsent,
        buildPass,
        step({ step: 'test', status: 'timeout' }),
      ]),
    ).toBe('INCONCLUSIVE');
  });

  it('rule 4: all pass and tests ran with total > 0 -> HIGH', () => {
    const steps = [copyPass, applyPass, installPass, rescanAbsent, buildPass, testPassWithCounts];
    expect(computeConfidence(steps)).toBe('HIGH');
  });

  it('rule 5: all pass but tests skipped -> MEDIUM', () => {
    const steps = [copyPass, applyPass, installPass, rescanAbsent, buildPass, testPassNoCounts];
    expect(computeConfidence(steps)).toBe('MEDIUM');
  });

  it('rule 5: all pass but no test step at all -> MEDIUM', () => {
    const steps = [copyPass, applyPass, installPass, rescanAbsent, buildPass];
    expect(computeConfidence(steps)).toBe('MEDIUM');
  });

  it('rule 5: test step passed but reports zero total (empty suite) -> MEDIUM, not HIGH', () => {
    const steps = [
      installPass,
      rescanAbsent,
      buildPass,
      step({ step: 'test', exitCode: 0, testCounts: { passed: 0, failed: 0, total: 0 } }),
    ];
    expect(computeConfidence(steps)).toBe('MEDIUM');
  });

  it('an empty step list is MEDIUM (nothing failed, nothing timed out, no tests ran)', () => {
    expect(computeConfidence([])).toBe('MEDIUM');
  });
});
