import type { StepResult } from '../../../core/models/index.js';
import { skippedStep, stepFromExec } from './shared.js';
import { parseTestCounts } from './test-count-parser.js';
import type { ContainerExecutor } from './apply.js';

/** Runs the project's configured test command; skipped if left blank. Network-isolated phase. */
export async function runTestStep(
  container: ContainerExecutor,
  testCommand: string,
  timeoutMs: number,
): Promise<StepResult> {
  if (testCommand.trim().length === 0) return skippedStep('test');
  const outcome = await container.exec(['sh', '-c', testCommand], timeoutMs);
  const testCounts = parseTestCounts(outcome.output);
  return stepFromExec('test', outcome, testCounts !== undefined ? { testCounts } : {});
}
