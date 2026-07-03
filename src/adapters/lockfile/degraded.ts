import path from 'node:path';
import semver from 'semver';
import { AppError } from '../../shared/errors.js';
import { err, ok, type Result } from '../../shared/result.js';
import { DepGraphSchema, type DepGraph, type DepNode } from '../../core/models/index.js';
import { readJsonFile } from './safe-read.js';
import { RawPackageJsonSchema } from './schema.js';

/**
 * Degraded mode (blueprint §6): no lockfile — parse package.json ranges only.
 * Each range is pinned to its minimum satisfying version, which is the honest
 * floor for advisory matching. Results are flagged degraded; verify is disabled.
 */
export function parseDegraded(projectDir: string): Result<DepGraph> {
  const pkgPath = path.join(projectDir, 'package.json');
  const rawResult = readJsonFile(pkgPath);
  if (!rawResult.ok) {
    return err(
      AppError.user(
        'NO_MANIFEST',
        `Neither package-lock.json nor a readable package.json found in ${projectDir}`,
        'Run VeriPatch inside an npm project.',
      ),
    );
  }

  const parsed = RawPackageJsonSchema.safeParse(rawResult.value);
  if (!parsed.success) {
    return err(AppError.user('MANIFEST_INVALID', `package.json has an unexpected shape`));
  }

  const nodes: DepNode[] = [];
  const sections: { deps: Record<string, string> | undefined; dev: boolean }[] = [
    { deps: parsed.data.dependencies, dev: false },
    { deps: parsed.data.optionalDependencies, dev: false },
    { deps: parsed.data.devDependencies, dev: true },
  ];
  for (const { deps, dev } of sections) {
    for (const [name, range] of Object.entries(deps ?? {})) {
      const version = minVersionOf(range);
      if (version === undefined) continue; // git/file/url specs — nothing honest to match against
      nodes.push({ name, version, paths: [['root', name]], dev, direct: true });
    }
  }

  const graph = { nodes, lockfileVersion: null, degraded: true };
  const validated = DepGraphSchema.safeParse(graph);
  if (!validated.success) {
    const issue = validated.error.issues[0];
    return err(
      AppError.user(
        'MANIFEST_HOSTILE_ENTRY',
        `package.json dependency rejected: ${issue?.message ?? 'invalid'}`,
      ),
    );
  }
  return ok(validated.data);
}

function minVersionOf(range: string): string | undefined {
  try {
    return semver.minVersion(range)?.version;
  } catch {
    return undefined;
  }
}
