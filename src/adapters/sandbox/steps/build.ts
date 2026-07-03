import type { StepResult } from '../../../core/models/index.js';
import { skippedStep, stepFromExec } from './shared.js';
import type { ContainerExecutor } from './apply.js';

/** Runs the project's configured build command; skipped if left blank. Network-isolated phase. */
export async function runBuildStep(
  container: ContainerExecutor,
  buildCommand: string,
  timeoutMs: number,
): Promise<StepResult> {
  if (buildCommand.trim().length === 0) return skippedStep('build');
  const outcome = await container.exec(['sh', '-c', buildCommand], timeoutMs);
  return stepFromExec('build', outcome);
}
