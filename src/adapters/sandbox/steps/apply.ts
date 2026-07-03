import type { FixCandidate, StepResult } from '../../../core/models/index.js';
import type { ExecOutcome } from '../docker.js';
import { stepFromExec } from './shared.js';

export interface ContainerExecutor {
  exec(cmd: string[], timeoutMs: number): Promise<ExecOutcome>;
}

/** `npm install pkg@to --package-lock-only` — updates the lockfile without touching node_modules. */
export async function runApplyStep(
  container: ContainerExecutor,
  candidate: FixCandidate,
  timeoutMs: number,
): Promise<StepResult> {
  const outcome = await container.exec(
    ['npm', 'install', `${candidate.pkg}@${candidate.to}`, '--package-lock-only'],
    timeoutMs,
  );
  return stepFromExec('apply', outcome);
}
