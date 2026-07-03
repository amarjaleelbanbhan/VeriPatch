import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Resolves VeriPatch's own package version at runtime by walking up from
 * wherever this module physically lives. Necessary because tsup bundles
 * src/cli/index.ts into a single dist/cli.js, so the source-tree distance
 * to package.json (two levels) differs from the published-package distance
 * (one level) — walking up avoids hardcoding either.
 */
function resolveVersion(): string {
  let dir = path.dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const candidate = path.join(dir, 'package.json');
    if (fs.existsSync(candidate)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(candidate, 'utf8')) as {
          name?: string;
          version?: string;
        };
        if (pkg.name === 'veripatch' && pkg.version !== undefined) return pkg.version;
      } catch {
        // fall through to the next ancestor directory
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return '0.0.0';
}

export const VERIPATCH_VERSION = resolveVersion();
