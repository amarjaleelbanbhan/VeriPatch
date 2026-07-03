import fs from 'node:fs';
import path from 'node:path';
import { AppError } from '../../shared/errors.js';
import { err, ok, type Result } from '../../shared/result.js';
import type { DepGraph } from '../../core/models/index.js';
import type { LockfileParser } from '../../core/ports.js';
import { parseDegraded } from './degraded.js';
import { readJsonFile } from './safe-read.js';
import { RawLockfileSchema } from './schema.js';
import { walkPackages } from './walker.js';

export const LOCKFILE_NAME = 'package-lock.json';

/**
 * npm lockfile → DepGraph. Dispatches on lockfileVersion:
 * - v2/v3 share the `packages` map and one hardened walker
 * - v1 is rejected with an upgrade hint (npm 7+ rewrites it automatically)
 * - no lockfile at all falls back to degraded package.json parsing
 */
export class NpmLockfileParser implements LockfileParser {
  parse(projectDir: string): Result<DepGraph> {
    const lockPath = path.join(projectDir, LOCKFILE_NAME);
    if (!fs.existsSync(lockPath)) {
      return parseDegraded(projectDir);
    }

    const rawResult = readJsonFile(lockPath);
    if (!rawResult.ok) return rawResult;

    const lockParsed = RawLockfileSchema.safeParse(rawResult.value);
    if (!lockParsed.success) {
      return err(
        AppError.user(
          'LOCKFILE_INVALID',
          `${LOCKFILE_NAME} has an unexpected shape`,
          'Regenerate it with npm install.',
        ),
      );
    }

    const lock = lockParsed.data;
    if (lock.lockfileVersion !== 2 && lock.lockfileVersion !== 3) {
      return err(
        AppError.user(
          'LOCKFILE_UNSUPPORTED_VERSION',
          `Unsupported lockfileVersion ${String(lock.lockfileVersion)}`,
          'VeriPatch supports lockfile v2/v3. Update npm (>=7) and run npm install to upgrade.',
        ),
      );
    }

    const nodes = walkPackages(lock);
    if (!nodes.ok) return nodes;

    return ok({ nodes: nodes.value, lockfileVersion: lock.lockfileVersion, degraded: false });
  }
}
