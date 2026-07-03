import { describe, expect, it } from 'vitest';
import {
  exitCodeFor,
  renderChecklist,
  type DoctorCheck,
} from '../../../../src/cli/commands/doctor.js';

describe('exitCodeFor', () => {
  it('is 0 when every check passes', () => {
    const checks: DoctorCheck[] = [
      { name: 'a', pass: true },
      { name: 'b', pass: true },
    ];
    expect(exitCodeFor(checks)).toBe(0);
  });

  it('is 1 when any check fails', () => {
    const checks: DoctorCheck[] = [
      { name: 'a', pass: true },
      { name: 'b', pass: false },
    ];
    expect(exitCodeFor(checks)).toBe(1);
  });

  it('is 0 for an empty check list', () => {
    expect(exitCodeFor([])).toBe(0);
  });
});

describe('renderChecklist', () => {
  it('marks passing checks with a checkmark and no hint', () => {
    const out = renderChecklist([{ name: 'Node >= 20', pass: true }]);
    expect(out).toBe('✅ Node >= 20');
  });

  it('marks failing checks with an x and includes the hint', () => {
    const out = renderChecklist([{ name: 'Docker reachable', pass: false, hint: 'Start Docker.' }]);
    expect(out).toContain('❌ Docker reachable');
    expect(out).toContain('Start Docker.');
  });

  it('renders one line per check', () => {
    const out = renderChecklist([
      { name: 'a', pass: true },
      { name: 'b', pass: false, hint: 'fix b' },
    ]);
    expect(out.split('\n')).toHaveLength(3); // "a" + "b" + hint line
  });
});
