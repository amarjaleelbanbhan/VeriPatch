import type { FixCandidate, StepResult } from '../../../core/models/index.js';
import type { ExecOutcome } from '../docker.js';
import { stepFromExec } from './shared.js';

export interface ContainerExecutor {
  exec(cmd: string[], timeoutMs: number): Promise<ExecOutcome>;
}

/**
 * Applies the candidate bump to the staged copy, honoring its strategy:
 *
 * - 'direct': `npm install pkg@to --package-lock-only` — bumps the root
 *   manifest's own range, exactly what a human would commit.
 * - 'override': writes an npm `overrides` entry into package.json and
 *   regenerates the lockfile. A transitive dependency is not the root's to
 *   install — plain `npm install pkg@to` would ADD it as a root dependency,
 *   changing the project's semantics instead of forcing nested resolution.
 *
 * The package.json edit runs inside the container (node -e, argv-passed
 * values, no shell) so the pipeline stays "everything executes sandboxed".
 */
export async function runApplyStep(
  container: ContainerExecutor,
  candidate: FixCandidate,
  timeoutMs: number,
): Promise<StepResult> {
  if (candidate.strategy === 'override') {
    const writeOverride = await container.exec(
      [
        'node',
        '-e',
        // pkg/to arrive via argv, never string-interpolated into code —
        // both are validated upstream, but the boundary costs nothing.
        `const fs = require('fs');
const [pkgName, toVersion] = process.argv.slice(1);
const manifest = JSON.parse(fs.readFileSync('package.json', 'utf8'));
manifest.overrides = { ...(manifest.overrides ?? {}), [pkgName]: toVersion };
fs.writeFileSync('package.json', JSON.stringify(manifest, null, 2) + '\\n');`,
        candidate.pkg,
        candidate.to,
      ],
      timeoutMs,
    );
    if (writeOverride.exitCode !== 0 || writeOverride.timedOut) {
      return stepFromExec('apply', writeOverride);
    }
    const outcome = await container.exec(['npm', 'install', '--package-lock-only'], timeoutMs);
    return stepFromExec('apply', outcome);
  }

  const outcome = await container.exec(
    ['npm', 'install', `${candidate.pkg}@${candidate.to}`, '--package-lock-only'],
    timeoutMs,
  );
  return stepFromExec('apply', outcome);
}
