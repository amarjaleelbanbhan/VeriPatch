import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { AppError } from '../../shared/errors.js';
import { err, ok, type Result } from '../../shared/result.js';

/**
 * Stages an isolated copy of the project for the sandbox to mount (blueprint
 * §9): the container never touches the original working tree, and secrets /
 * VCS metadata / prior tool state never enter it in the first place.
 */
const EXCLUDED_NAMES = new Set(['node_modules', '.git', '.veripatch']);
const ENV_FILE_PREFIX = '.env';

export interface StagedProject {
  stagingDir: string;
}

export function stageProjectCopy(projectDir: string): Result<StagedProject> {
  const stagingDir = path.join(os.tmpdir(), `veripatch-sandbox-${randomUUID()}`);
  try {
    fs.cpSync(projectDir, stagingDir, {
      recursive: true,
      filter: (source) => !isExcluded(source),
    });
    // The container runs as a fixed non-root uid (blueprint §9) regardless of
    // which uid actually owns these files on the host — Docker bind mounts
    // don't remap ownership, so without this the container gets EACCES on a
    // host whose uid differs from the container's. Safe here specifically
    // because this is a throwaway copy, mounted only into our own hardened
    // container, deleted right after the run.
    makeWorldReadWritable(stagingDir);
  } catch (cause) {
    return err(
      AppError.world(
        'SANDBOX_STAGE_FAILED',
        `Could not stage a sandbox copy of ${projectDir}`,
        undefined,
        cause,
      ),
    );
  }
  return ok({ stagingDir });
}

function makeWorldReadWritable(root: string): void {
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const entryPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      fs.chmodSync(entryPath, 0o777);
      makeWorldReadWritable(entryPath);
    } else if (entry.isFile()) {
      fs.chmodSync(entryPath, 0o666);
    }
  }
  fs.chmodSync(root, 0o777);
}

export function cleanupStagedProject(staged: StagedProject): void {
  fs.rmSync(staged.stagingDir, { recursive: true, force: true });
}

function isExcluded(sourcePath: string): boolean {
  const name = path.basename(sourcePath);
  return EXCLUDED_NAMES.has(name) || name.startsWith(ENV_FILE_PREFIX);
}
