import fs from 'node:fs';
import path from 'node:path';
import type { PackageManager } from '../../core/models/index.js';
import type { LockfileParser } from '../../core/ports.js';
import { LOCKFILE_NAME, NpmLockfileParser } from './index.js';
import { YARN_LOCKFILE_NAME, YarnLockfileParser } from './yarn/index.js';

export interface DetectedLockfile {
  parser: LockfileParser;
  /** null when no lockfile exists — the parser will produce a degraded graph. */
  packageManager: PackageManager;
  /** Lockfiles that are present but lost the precedence race (mixed-manager repos). */
  ignored: string[];
}

/**
 * Picks the lockfile parser for a project directory. Precedence when several
 * lockfiles coexist: npm, then yarn — package-lock.json is what `veripatch
 * update` and the verify sandbox manipulate, so when both are present the npm
 * view is the one VeriPatch can act on. The losers are reported so the CLI can
 * warn rather than silently choosing.
 */
export function detectLockfile(projectDir: string): DetectedLockfile {
  const has = (name: string): boolean => fs.existsSync(path.join(projectDir, name));

  if (has(LOCKFILE_NAME)) {
    return {
      parser: new NpmLockfileParser(),
      packageManager: 'npm',
      ignored: has(YARN_LOCKFILE_NAME) ? [YARN_LOCKFILE_NAME] : [],
    };
  }
  if (has(YARN_LOCKFILE_NAME)) {
    return { parser: new YarnLockfileParser(), packageManager: 'yarn', ignored: [] };
  }
  // No lockfile: the npm parser owns the degraded package.json fallback.
  return { parser: new NpmLockfileParser(), packageManager: null, ignored: [] };
}
