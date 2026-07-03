import type { StepResult } from '../../../core/models/index.js';

/**
 * Extracts pass/fail/total counts from a test run's output (blueprint T6.5:
 * "vitest/jest json"). Confidence still derives from the exit code alone
 * (rule 2, §2) — these counts only decide HIGH vs MEDIUM (rule 4/5), so
 * parsing structured reporter output here is not the "log-text heuristic"
 * the confidence rules forbid for pass/fail itself.
 *
 * Recognizes, in order: an embedded Jest/Vitest JSON-reporter object, then
 * each tool's well-known default-reporter summary line.
 */
export function parseTestCounts(output: string): NonNullable<StepResult['testCounts']> | undefined {
  const json = parseJsonReporter(output);
  if (json !== undefined) return json;

  const vitest = /Tests\s+(\d+)\s+passed(?:\s*\|\s*(\d+)\s+failed)?\s*\((\d+)\)/.exec(output);
  if (vitest?.[1] !== undefined && vitest[3] !== undefined) {
    return {
      passed: Number(vitest[1]),
      failed: vitest[2] !== undefined ? Number(vitest[2]) : 0,
      total: Number(vitest[3]),
    };
  }

  const jest = /Tests:\s+(?:(\d+)\s+failed,\s*)?(\d+)\s+passed,\s*(\d+)\s+total/.exec(output);
  if (jest?.[2] !== undefined && jest[3] !== undefined) {
    return {
      passed: Number(jest[2]),
      failed: jest[1] !== undefined ? Number(jest[1]) : 0,
      total: Number(jest[3]),
    };
  }

  return undefined;
}

function parseJsonReporter(output: string): NonNullable<StepResult['testCounts']> | undefined {
  const match = /\{[^{}]*"numTotalTests"[^{}]*\}/.exec(output);
  if (match === null) return undefined;
  try {
    const parsed = JSON.parse(match[0]) as {
      numTotalTests?: number;
      numPassedTests?: number;
      numFailedTests?: number;
    };
    if (typeof parsed.numTotalTests !== 'number') return undefined;
    return {
      total: parsed.numTotalTests,
      passed: parsed.numPassedTests ?? 0,
      failed: parsed.numFailedTests ?? 0,
    };
  } catch {
    return undefined;
  }
}
