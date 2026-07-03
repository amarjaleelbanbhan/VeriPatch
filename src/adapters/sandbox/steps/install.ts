import type { StepResult } from '../../../core/models/index.js';
import { stepFromExec } from './shared.js';
import type { ContainerExecutor } from './apply.js';

/**
 * `npm ci --ignore-scripts` against the bumped lockfile (registry-only
 * network phase). --ignore-scripts is the primary defense against a
 * malicious postinstall script (blueprint §9): the dedicated per-run
 * network gives install-phase registry access, not domain-level egress
 * filtering, so a postinstall script running with network still attached
 * could otherwise phone home. Suppressing script execution entirely closes
 * that gap regardless of network configuration.
 */
export async function runInstallStep(
  container: ContainerExecutor,
  timeoutMs: number,
): Promise<StepResult> {
  const outcome = await container.exec(['npm', 'ci', '--ignore-scripts'], timeoutMs);
  return stepFromExec('install', outcome);
}
