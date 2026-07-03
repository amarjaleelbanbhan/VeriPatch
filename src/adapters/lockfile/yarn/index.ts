import fs from 'node:fs';
import path from 'node:path';
import { AppError } from '../../../shared/errors.js';
import { err, ok, type Result } from '../../../shared/result.js';
import type { DepGraph } from '../../../core/models/index.js';
import type { LockfileParser } from '../../../core/ports.js';
import { parseDegraded } from '../degraded.js';
import { readJsonFile, readTextFile } from '../safe-read.js';
import { RawPackageJsonSchema } from '../schema.js';
import { parseBerryLockfile } from './berry.js';
import { parseClassicLockfile } from './classic.js';
import { buildYarnGraph } from './graph.js';
import type { YarnEntries } from './entries.js';

export const YARN_LOCKFILE_NAME = 'yarn.lock';

/** Berry files always carry a __metadata block; classic (v1) never does. */
const BERRY_MARKER = /^__metadata:/m;

/**
 * yarn.lock → DepGraph. Dispatches on format:
 * - berry (v2+): YAML with __metadata.version
 * - classic (v1): yarn's own indentation format
 * - no lockfile at all falls back to degraded package.json parsing
 *
 * Root membership and dev-ness come from package.json — yarn.lock is a flat
 * descriptor→resolution map and does not record either.
 */
export class YarnLockfileParser implements LockfileParser {
  parse(projectDir: string): Result<DepGraph> {
    const lockPath = path.join(projectDir, YARN_LOCKFILE_NAME);
    if (!fs.existsSync(lockPath)) {
      return parseDegraded(projectDir);
    }

    const rawResult = readTextFile(lockPath);
    if (!rawResult.ok) return rawResult;
    const raw = rawResult.value;

    let entries: YarnEntries;
    let lockfileVersion: number;
    if (BERRY_MARKER.test(raw)) {
      const berry = parseBerryLockfile(raw);
      if (!berry.ok) return berry;
      entries = berry.value.entries;
      lockfileVersion = berry.value.metadataVersion;
    } else {
      const classic = parseClassicLockfile(raw);
      if (!classic.ok) return classic;
      entries = classic.value;
      lockfileVersion = 1;
    }

    const pkgResult = readJsonFile(path.join(projectDir, 'package.json'));
    if (!pkgResult.ok) {
      return err(
        AppError.user(
          'NO_MANIFEST',
          `yarn.lock found but no readable package.json in ${projectDir}`,
          'yarn.lock alone cannot say which dependencies are direct or dev-only.',
        ),
      );
    }
    const pkg = RawPackageJsonSchema.safeParse(pkgResult.value);
    if (!pkg.success) {
      return err(AppError.user('MANIFEST_INVALID', 'package.json has an unexpected shape'));
    }

    const nodes = buildYarnGraph(entries, pkg.data);
    if (!nodes.ok) return nodes;

    return ok({
      nodes: nodes.value,
      lockfileVersion,
      packageManager: 'yarn' as const,
      degraded: false,
    });
  }
}
