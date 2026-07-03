import { AppError } from '../../shared/errors.js';
import { err, ok, type Result } from '../../shared/result.js';
import { DepNodeSchema, type DepNode } from '../../core/models/index.js';
import { MAX_PATHS_PER_NODE, ROOT_LABEL, collectPaths, dedupePaths } from './paths.js';
import type { RawLockfile, RawPackageEntry } from './schema.js';

/**
 * Walks the `packages` map shared by lockfile v2 and v3 into DepNode[].
 *
 * Responsibilities:
 * - derive package names from "node_modules/..." locations (or the `name` field)
 * - resolve each entry's dependency names to concrete locations using npm's
 *   nearest-ancestor node_modules algorithm
 * - collect root→node dependency chains (capped — they explain provenance,
 *   they are not an exhaustive enumeration)
 * - merge duplicate name@version instances installed at different locations
 */

const NODE_MODULES_SEG = 'node_modules/';

interface LocationEntry {
  location: string;
  name: string;
  entry: RawPackageEntry;
}

export function walkPackages(lock: RawLockfile): Result<DepNode[]> {
  const packages = lock.packages ?? {};
  const root = packages[''];
  if (root === undefined) {
    return err(
      AppError.user(
        'LOCKFILE_NO_ROOT',
        'Lockfile has no root ("") entry in packages',
        'Regenerate the lockfile with npm install.',
      ),
    );
  }

  // Index installed entries by location. Skip links/workspace paths (non-goal for MVP)
  // and entries without a version (unresolvable).
  const byLocation = new Map<string, LocationEntry>();
  for (const [location, entry] of Object.entries(packages)) {
    if (location === '') continue;
    if (entry.link === true || entry.version === undefined) continue;
    if (!location.includes(NODE_MODULES_SEG)) continue; // e.g. workspaces "packages/foo"
    const name = entry.name ?? deriveNameFromLocation(location);
    if (name === undefined) continue;
    byLocation.set(location, { location, name, entry });
  }

  // Resolved dependency edges, location → locations.
  const edges = new Map<string, string[]>();
  const rootDeps = allDependencyNames(root, true);
  const rootEdge: string[] = [];
  for (const depName of rootDeps) {
    const target = resolveDependency('', depName, byLocation);
    if (target !== undefined) rootEdge.push(target);
  }
  edges.set('', rootEdge);

  for (const { location, entry } of byLocation.values()) {
    const targets: string[] = [];
    for (const depName of allDependencyNames(entry, false)) {
      const target = resolveDependency(location, depName, byLocation);
      if (target !== undefined) targets.push(target);
    }
    edges.set(location, targets);
  }

  const namesByLocation = new Map(
    [...byLocation.values()].map(({ location, name }) => [location, name]),
  );
  const pathsByLocation = collectPaths(namesByLocation, edges);
  const directLocations = new Set(rootEdge);

  // Merge instances of the same name@version installed at multiple locations.
  const merged = new Map<string, DepNode>();
  for (const { location, name, entry } of byLocation.values()) {
    const key = `${name}@${entry.version ?? ''}`;
    const paths = pathsByLocation.get(location) ?? [[ROOT_LABEL, name]];
    const existing = merged.get(key);
    if (existing === undefined) {
      merged.set(key, {
        name,
        version: entry.version ?? '',
        paths: paths.slice(0, MAX_PATHS_PER_NODE),
        dev: entry.dev === true,
        direct: directLocations.has(location),
        ...(entry.integrity !== undefined ? { integrity: entry.integrity } : {}),
      });
    } else {
      existing.paths = dedupePaths([...existing.paths, ...paths]).slice(0, MAX_PATHS_PER_NODE);
      existing.dev = existing.dev && entry.dev === true;
      existing.direct = existing.direct || directLocations.has(location);
      if (existing.integrity === undefined && entry.integrity !== undefined) {
        existing.integrity = entry.integrity;
      }
    }
  }

  const nodes: DepNode[] = [];
  for (const node of merged.values()) {
    const validated = DepNodeSchema.safeParse(node);
    if (!validated.success) {
      const issue = validated.error.issues[0];
      return err(
        AppError.user(
          'LOCKFILE_HOSTILE_ENTRY',
          `Lockfile entry "${node.name}@${node.version}" rejected: ${issue?.message ?? 'invalid'}`,
          'The lockfile contains entries that do not look like honest npm packages.',
        ),
      );
    }
    nodes.push(validated.data);
  }

  nodes.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  return ok(nodes);
}

/** "node_modules/a/node_modules/@s/b" → "@s/b"; rejects traversal tricks. */
export function deriveNameFromLocation(location: string): string | undefined {
  const idx = location.lastIndexOf(NODE_MODULES_SEG);
  if (idx === -1) return undefined;
  const name = location.slice(idx + NODE_MODULES_SEG.length);
  if (name.length === 0 || name.includes('..')) return undefined;
  return name;
}

function allDependencyNames(entry: RawPackageEntry, isRoot: boolean): string[] {
  const names = new Set<string>([
    ...Object.keys(entry.dependencies ?? {}),
    ...Object.keys(entry.optionalDependencies ?? {}),
    ...Object.keys(entry.peerDependencies ?? {}),
  ]);
  if (isRoot) {
    for (const name of Object.keys(entry.devDependencies ?? {})) names.add(name);
  }
  return [...names];
}

/**
 * npm resolution: from `fromLocation`, the dependency `depName` resolves to the
 * nearest "node_modules/<depName>" walking up the tree.
 */
export function resolveDependency(
  fromLocation: string,
  depName: string,
  byLocation: ReadonlyMap<string, LocationEntry>,
): string | undefined {
  let base = fromLocation;
  for (;;) {
    const candidate =
      base === '' ? `${NODE_MODULES_SEG}${depName}` : `${base}/${NODE_MODULES_SEG}${depName}`;
    if (byLocation.has(candidate)) return candidate;
    if (base === '') return undefined; // unresolved (unmet optional/peer)
    base = parentLocation(base);
  }
}

/** "node_modules/a/node_modules/b" → "node_modules/a"; "node_modules/a" → "". */
function parentLocation(location: string): string {
  const idx = location.lastIndexOf(NODE_MODULES_SEG);
  if (idx <= 0) return '';
  return location.slice(0, idx - 1); // drop trailing "/node_modules/<name>"
}
