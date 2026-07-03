import { describe, expect, it } from 'vitest';
import { errorExitCode, scanExitCode } from '../../../src/cli/exit-code.js';
import { AppError } from '../../../src/shared/errors.js';

describe('scanExitCode', () => {
  it('non-ci mode: 0 clean, 1 any vuln', () => {
    expect(scanExitCode({ ci: false, newVulnCount: 0, totalVulnCount: 0 })).toBe(0);
    expect(scanExitCode({ ci: false, newVulnCount: 0, totalVulnCount: 3 })).toBe(1);
  });

  it('ci mode: counts only new-vs-baseline vulns', () => {
    expect(scanExitCode({ ci: true, newVulnCount: 0, totalVulnCount: 10 })).toBe(0);
    expect(scanExitCode({ ci: true, newVulnCount: 1, totalVulnCount: 10 })).toBe(1);
  });

  it('never returns 2', () => {
    expect(scanExitCode({ ci: true, newVulnCount: 999, totalVulnCount: 999 })).not.toBe(2);
  });
});

describe('errorExitCode', () => {
  it('every AppError kind maps to 2', () => {
    expect(errorExitCode(AppError.user('X', 'x'))).toBe(2);
    expect(errorExitCode(AppError.world('X', 'x'))).toBe(2);
    expect(errorExitCode(AppError.internal('X', 'x'))).toBe(2);
  });
});
