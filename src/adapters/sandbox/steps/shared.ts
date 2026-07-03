import { sanitizeExternalString } from '../../../shared/sanitize.js';
import type { StepName, StepResult } from '../../../core/models/index.js';
import type { ExecOutcome } from '../docker.js';

const LOG_TAIL_LINES = 40;

/** Sanitized, last-N-lines tail — verbatim logs stay on disk; only this enters reports. */
export function tailLog(output: string): string {
  const sanitized = sanitizeExternalString(output);
  const lines = sanitized.split('\n');
  return lines.slice(-LOG_TAIL_LINES).join('\n');
}

export function stepFromExec(
  step: StepName,
  outcome: ExecOutcome,
  extra: Partial<Pick<StepResult, 'testCounts'>> = {},
): StepResult {
  const status = outcome.timedOut ? 'timeout' : outcome.exitCode === 0 ? 'pass' : 'fail';
  return {
    step,
    status,
    ...(outcome.timedOut ? {} : { exitCode: outcome.exitCode }),
    durationMs: Math.round(outcome.durationMs),
    logTail: tailLog(outcome.output),
    ...extra,
  };
}

export function skippedStep(step: StepName): StepResult {
  return { step, status: 'skipped', durationMs: 0, logTail: '' };
}

/** A step "gates" the rest of the pipeline when there's nothing meaningful left to verify. */
export function isGating(step: StepResult): boolean {
  return step.status === 'fail' || step.status === 'timeout';
}
