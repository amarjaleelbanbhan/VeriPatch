import fs from 'node:fs';
import path from 'node:path';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import { AppError } from '../../../shared/errors.js';
import { err, ok, type Result } from '../../../shared/result.js';
import type { DepGraph, DepNode } from '../../../core/models/index.js';
import type { LockfileParser } from '../../../core/ports.js';
import { parseDegraded } from '../degraded.js';
import { buildFlatGraphNodes } from '../graph-builder.js';
import { readTextFile, stripDangerousKeys } from '../safe-read.js';

export const PNPM_LOCKFILE_NAME = 'pnpm-lock.yaml';

/**
 * pnpm-lock.yaml → DepGraph. Supports lockfileVersion 6.x (pnpm 8: deps
 * inline on `/name@version` package keys, roots at the top level) and 9.x
 * (pnpm 9+: edges in `snapshots`, roots under `importers`). Only the root
 * importer (".") is walked — workspace members are a separate milestone.
 *
 * Version references may carry peer-resolution suffixes ("1.2.3(react@18)");
 * nodes are keyed by the bare version, so peer variants of one install merge.
 */
export class PnpmLockfileParser implements LockfileParser {
  parse(projectDir: string): Result<DepGraph> {
    const lockPath = path.join(projectDir, PNPM_LOCKFILE_NAME);
    if (!fs.existsSync(lockPath)) {
      return parseDegraded(projectDir);
    }

    const rawResult = readTextFile(lockPath);
    if (!rawResult.ok) return rawResult;

    let doc: unknown;
    try {
      doc = parseYaml(rawResult.value);
    } catch (cause) {
      return err(
        AppError.user(
          'LOCKFILE_INVALID',
          `${PNPM_LOCKFILE_NAME} is not valid YAML`,
          'Regenerate the lockfile with pnpm install.',
          cause,
        ),
      );
    }

    const parsed = RawPnpmLockSchema.safeParse(stripDangerousKeys(doc));
    if (!parsed.success) {
      return err(
        AppError.user(
          'LOCKFILE_INVALID',
          `${PNPM_LOCKFILE_NAME} has an unexpected shape`,
          'Regenerate the lockfile with pnpm install.',
        ),
      );
    }
    const lock = parsed.data;

    const major = Math.trunc(Number.parseFloat(lock.lockfileVersion));
    if (major !== 6 && major !== 9) {
      return err(
        AppError.user(
          'LOCKFILE_UNSUPPORTED_VERSION',
          `Unsupported pnpm lockfileVersion ${lock.lockfileVersion}`,
          'VeriPatch supports pnpm lockfile v6 and v9. Update pnpm and run pnpm install.',
        ),
      );
    }

    const nodes = major === 9 ? walkV9(lock) : walkV6(lock);
    if (!nodes.ok) return nodes;

    return ok({
      nodes: nodes.value,
      lockfileVersion: major,
      packageManager: 'pnpm' as const,
      degraded: false,
    });
  }
}

const RootDepSchema = z.object({ version: z.union([z.string(), z.number()]).optional() }).loose();
const RootDepsSchema = z.record(z.string(), RootDepSchema).optional();

const RawPnpmPackageSchema = z
  .object({
    resolution: z.object({ integrity: z.string().optional() }).loose().optional(),
    dependencies: z.record(z.string(), z.union([z.string(), z.number()])).optional(),
    optionalDependencies: z.record(z.string(), z.union([z.string(), z.number()])).optional(),
  })
  .loose();

const RawPnpmLockSchema = z
  .object({
    lockfileVersion: z.coerce.string(),
    // v6 roots (single-project layout)
    dependencies: RootDepsSchema,
    devDependencies: RootDepsSchema,
    optionalDependencies: RootDepsSchema,
    // v9 roots
    importers: z
      .record(
        z.string(),
        z
          .object({
            dependencies: RootDepsSchema,
            devDependencies: RootDepsSchema,
            optionalDependencies: RootDepsSchema,
          })
          .loose(),
      )
      .optional(),
    packages: z.record(z.string(), RawPnpmPackageSchema).optional(),
    snapshots: z.record(z.string(), RawPnpmPackageSchema).optional(),
  })
  .loose();
type RawPnpmLock = z.infer<typeof RawPnpmLockSchema>;
type RootDeps = z.infer<typeof RootDepsSchema>;

/** "1.2.3(react@18.2.0)(other@1.0.0)" → "1.2.3"; link/foreign specs → undefined. */
function bareVersion(ref: string): string | undefined {
  if (ref.startsWith('link:') || ref.startsWith('file:') || ref.includes('://')) return undefined;
  const paren = ref.indexOf('(');
  const version = paren === -1 ? ref : ref.slice(0, paren);
  return version.length > 0 ? version : undefined;
}

/**
 * Strips the trailing peer-suffix "(...)" group(s), respecting nesting —
 * a peer itself can carry its own peer suffix, e.g.
 * "eslint@9.39.4(jiti@1.21.7)". `lastIndexOf('@')` on the raw key would
 * otherwise land on an '@' inside that nested suffix instead of the real
 * name/version separator, so the suffix must come off first.
 */
function stripPeerSuffix(key: string): string {
  let depth = 0;
  for (let i = 0; i < key.length; i++) {
    if (key[i] === '(') {
      if (depth === 0) return key.slice(0, i);
      depth++;
    } else if (key[i] === ')') {
      depth--;
    }
  }
  return key;
}

/** "name@1.2.3(peers)" or "/name@1.2.3(peers)" → { name, version }. */
function splitPackageKey(key: string): { name: string; version: string } | undefined {
  const trimmed = key.startsWith('/') ? key.slice(1) : key;
  const withoutPeers = stripPeerSuffix(trimmed);
  const at = withoutPeers.lastIndexOf('@');
  if (at <= 0) return undefined;
  const name = withoutPeers.slice(0, at);
  const version = bareVersion(withoutPeers.slice(at + 1));
  if (version === undefined) return undefined;
  return { name, version };
}

interface Accumulator {
  names: Map<string, string>;
  versions: Map<string, string>;
  integrity: Map<string, string>;
  edges: Map<string, string[]>;
}

function addEntry(
  acc: Accumulator,
  name: string,
  version: string,
  pkg: z.infer<typeof RawPnpmPackageSchema> | undefined,
): string {
  const id = `${name}@${version}`;
  acc.names.set(id, name);
  acc.versions.set(id, version);
  const sri = pkg?.resolution?.integrity;
  if (sri !== undefined && !acc.integrity.has(id)) acc.integrity.set(id, sri);

  const targets = acc.edges.get(id) ?? [];
  for (const [depName, depRef] of Object.entries({
    ...(pkg?.dependencies ?? {}),
    ...(pkg?.optionalDependencies ?? {}),
  })) {
    const depVersion = bareVersion(String(depRef));
    if (depVersion === undefined) continue;
    const target = `${depName}@${depVersion}`;
    if (!targets.includes(target)) targets.push(target);
  }
  acc.edges.set(id, targets);
  return id;
}

function resolveRoots(acc: Accumulator, deps: RootDeps): string[] {
  const roots: string[] = [];
  for (const [name, spec] of Object.entries(deps ?? {})) {
    if (spec.version === undefined) continue;
    const version = bareVersion(String(spec.version));
    if (version === undefined) continue;
    const id = `${name}@${version}`;
    if (acc.names.has(id)) roots.push(id);
  }
  return roots;
}

function walk(
  lock: RawPnpmLock,
  edgeSource: Record<string, z.infer<typeof RawPnpmPackageSchema>>,
  roots: { prod: RootDeps; optional: RootDeps; dev: RootDeps },
): Result<DepNode[]> {
  const acc: Accumulator = {
    names: new Map(),
    versions: new Map(),
    integrity: new Map(),
    edges: new Map(),
  };

  // packages carry integrity for both versions; register them first.
  for (const [key, pkg] of Object.entries(lock.packages ?? {})) {
    const split = splitPackageKey(key);
    if (split === undefined) continue; // link:/file: entries — not registry packages
    addEntry(acc, split.name, split.version, pkg);
  }
  // then the edge source (v6: packages again — harmless; v9: snapshots).
  for (const [key, pkg] of Object.entries(edgeSource)) {
    const split = splitPackageKey(key);
    if (split === undefined) continue;
    addEntry(acc, split.name, split.version, pkg);
  }

  // Drop edges pointing at IDs that never materialized as entries.
  for (const [id, targets] of acc.edges) {
    acc.edges.set(
      id,
      targets.filter((t) => acc.names.has(t)),
    );
  }

  return buildFlatGraphNodes({
    ...acc,
    prodRoots: [...resolveRoots(acc, roots.prod), ...resolveRoots(acc, roots.optional)],
    devRoots: resolveRoots(acc, roots.dev),
  });
}

function walkV6(lock: RawPnpmLock): Result<DepNode[]> {
  return walk(lock, lock.packages ?? {}, {
    prod: lock.dependencies,
    optional: lock.optionalDependencies,
    dev: lock.devDependencies,
  });
}

function walkV9(lock: RawPnpmLock): Result<DepNode[]> {
  const rootImporter = lock.importers?.['.'];
  return walk(lock, lock.snapshots ?? {}, {
    prod: rootImporter?.dependencies,
    optional: rootImporter?.optionalDependencies,
    dev: rootImporter?.devDependencies,
  });
}
