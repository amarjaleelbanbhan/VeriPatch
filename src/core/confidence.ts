import type { Confidence, StepResult } from './models/index.js';

/**
 * Deterministic confidence computation (blueprint §2, applied in this exact
 * priority order). Derived ONLY from exit codes and VeriPatch's own re-scan —
 * never from log-text heuristics — so a project cannot talk its way into a
 * HIGH verdict.
 *
 * 1. rescan shows the vuln still present -> FAIL (fix was ineffective)
 * 2. install/build/test exited non-zero  -> FAIL (fix broke the project)
 * 3. any step timed out                  -> INCONCLUSIVE
 * 4. all pass, tests ran with total > 0   -> HIGH
 * 5. all pass, tests skipped/absent       -> MEDIUM
 */
export function computeConfidence(steps: StepResult[]): Confidence {
  const rescan = steps.find((s) => s.step === 'rescan');
  if (rescan?.status === 'fail') return 'FAIL';

  const breaking = steps.find(
    (s) => (s.step === 'install' || s.step === 'build' || s.step === 'test') && s.status === 'fail',
  );
  if (breaking !== undefined) return 'FAIL';

  if (steps.some((s) => s.status === 'timeout')) return 'INCONCLUSIVE';

  const test = steps.find((s) => s.step === 'test');
  if (test?.status === 'pass' && (test.testCounts?.total ?? 0) > 0) return 'HIGH';

  return 'MEDIUM';
}
