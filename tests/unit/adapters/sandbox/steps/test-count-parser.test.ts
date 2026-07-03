import { describe, expect, it } from 'vitest';
import { parseTestCounts } from '../../../../../src/adapters/sandbox/steps/test-count-parser.js';

describe('parseTestCounts', () => {
  it('parses an embedded Jest/Vitest JSON reporter object', () => {
    const output = `some setup logs\n{"numTotalTests":10,"numPassedTests":9,"numFailedTests":1}\nmore logs`;
    expect(parseTestCounts(output)).toEqual({ total: 10, passed: 9, failed: 1 });
  });

  it('parses the Vitest default reporter summary (all passing)', () => {
    expect(parseTestCounts('Test Files  3 passed (3)\nTests  12 passed (12)')).toEqual({
      passed: 12,
      failed: 0,
      total: 12,
    });
  });

  it('parses the Vitest default reporter summary with failures', () => {
    expect(parseTestCounts('Tests  10 passed | 2 failed (12)')).toEqual({
      passed: 10,
      failed: 2,
      total: 12,
    });
  });

  it('parses the Jest default reporter summary (all passing)', () => {
    expect(parseTestCounts('Tests:       9 passed, 9 total')).toEqual({
      passed: 9,
      failed: 0,
      total: 9,
    });
  });

  it('parses the Jest default reporter summary with failures', () => {
    expect(parseTestCounts('Tests:       1 failed, 8 passed, 9 total')).toEqual({
      passed: 8,
      failed: 1,
      total: 9,
    });
  });

  it('returns undefined for output with no recognizable summary', () => {
    expect(parseTestCounts('no test runner output here')).toBeUndefined();
    expect(parseTestCounts('')).toBeUndefined();
  });

  it('ignores a JSON blob without numTotalTests', () => {
    expect(parseTestCounts('{"unrelated": true}')).toBeUndefined();
  });
});
