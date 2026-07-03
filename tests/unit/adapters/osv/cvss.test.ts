import { describe, expect, it } from 'vitest';
import { cvss3BaseScore, deriveSeverity, scoreToLabel } from '../../../../src/adapters/osv/cvss.js';

describe('cvss3BaseScore against published reference scores', () => {
  // Vectors and scores from NVD entries — the calculator must reproduce them exactly.
  const table: [string, number][] = [
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N', 6.5],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H', 5.9],
    ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', 9.9],
    ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0.0],
    ['CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', 1.6],
  ];

  it.each(table)('%s → %d', (vector, expected) => {
    expect(cvss3BaseScore(vector)).toBe(expected);
  });

  it('rejects unknown versions and malformed vectors', () => {
    expect(cvss3BaseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N')).toBeUndefined();
    expect(cvss3BaseScore('CVSS:3.1/AV:X/AC:L')).toBeUndefined();
    expect(cvss3BaseScore('garbage')).toBeUndefined();
  });
});

describe('scoreToLabel', () => {
  it('follows the CVSS qualitative bands', () => {
    expect(scoreToLabel(9.8)).toBe('CRITICAL');
    expect(scoreToLabel(9.0)).toBe('CRITICAL');
    expect(scoreToLabel(8.9)).toBe('HIGH');
    expect(scoreToLabel(7.0)).toBe('HIGH');
    expect(scoreToLabel(6.9)).toBe('MEDIUM');
    expect(scoreToLabel(4.0)).toBe('MEDIUM');
    expect(scoreToLabel(3.9)).toBe('LOW');
    expect(scoreToLabel(0)).toBe('LOW');
  });
});

describe('deriveSeverity fallback chain', () => {
  it('prefers a parsable CVSS vector', () => {
    const s = deriveSeverity(['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'], 'LOW');
    expect(s).toEqual({ cvss: 9.8, label: 'CRITICAL' });
  });

  it('falls back to the database text label (MODERATE → MEDIUM)', () => {
    const s = deriveSeverity(['CVSS:4.0/whatever'], 'MODERATE');
    expect(s.label).toBe('MEDIUM');
  });

  it('defaults unknown risk to MEDIUM, never LOW', () => {
    expect(deriveSeverity([], undefined).label).toBe('MEDIUM');
  });
});
