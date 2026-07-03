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

  // Index entries by location, in three kinds:
  // - registry installs ("node_modules/...") — the only vulnerability nodes
  // - workspace members ("packages/foo") — first-party code: they name
  //   provenance paths and contribute edges, but are never output nodes
  //   (matching them against registry advisories would be a false positive)
  // - links ("node_modules/foo" → "packages/foo") — aliases that make
  //   cross-workspace dependencies resolve to the workspace entry
  const byLocation = new Map<string, LocationEntry>();
  const workspaces = new Map<string, { name: string; entry: RawPackageEntry }>();
  const linkTargets = new Map<string, string>();
  for (const [location, entry] of Object.entries(packages)) {
    if (location === '') continue;
    if (entry.link === true) {
      if (entry.resolved !== undefined) linkTargets.set(location, entry.resolved);
      continue;
    }
    if (entry.version === undefined) continue;
    if (!location.includes(NODE_MODULES_SEG)) {
      const name = entry.name ?? location.split('/').at(-1);
      if (name !== undefined && name.length > 0) workspaces.set(location, { name, entry });
      continue;
    }
    const name = entry.name ?? deriveNameFromLocation(location);
    if (name === undefined) continue;
    byLocation.set(location, { location, name, entry });
  }

  // A resolution candidate is valid if it's a registry install, or a link
  // whose target is a known workspace (the edge then points at the workspace).
  const lookupCandidate = (candidate: string): string | undefined => {
    if (byLocation.has(candidate)) return candidate;
    const linked = linkTargets.get(candidate);
    if (linked !== undefined && workspaces.has(linked)) return linked;
    return undefined;
  };

  const resolveNames = (fromLocation: string, depNames: string[]): string[] => {
    const targets: string[] = [];
    for (const depName of depNames) {
      const target = resolveDependency(fromLocation, depName, lookupCandidate);
      if (target !== undefined) targets.push(target);
    }
    return targets;
  };

  // Resolved dependency edges, location → locations. The root reaches its own
  // deps plus every workspace member; workspace members reach their declared
  // deps (dev included — each is the root of its own manifest).
  const edges = new Map<string, string[]>();
  const rootEdge = [...resolveNames('', allDependencyNames(root, true)), ...workspaces.keys()];
  edges.set('', rootEdge);

  const manifestDeclared = new Set<string>();
  for (const [location, { entry }] of workspaces) {
    const targets = resolveNames(location, allDependencyNames(entry, true));
    edges.set(location, targets);
    for (const t of targets) manifestDeclared.add(t);
  }

  for (const { location, entry } of byLocation.values()) {
    edges.set(location, resolveNames(location, allDependencyNames(entry, false)));
  }

  const namesByLocation = new Map(
    [...byLocation.values()].map(({ location, name }) => [location, name]),
  );
  for (const [location, { name }] of workspaces) namesByLocation.set(location, name);

  const pathsByLocation = collectPaths(namesByLocation, edges);
  // Direct = declared in a manifest a human can edit: the root's package.json
  // or any workspace member's.
  const directLocations = new Set([
    ...rootEdge.filter((loc) => byLocation.has(loc)),
    ...manifestDeclared,
  ]);

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
 * nearest "node_modules/<depName>" walking up the tree. `lookup` maps a
 * candidate location to its canonical target (itself, or a link's workspace).
 */
export function resolveDependency(
  fromLocation: string,
  depName: string,
  lookup: (candidate: string) => string | undefined,
): string | undefined {
  let base = fromLocation;
  for (;;) {
    const candidate =
      base === '' ? `${NODE_MODULES_SEG}${depName}` : `${base}/${NODE_MODULES_SEG}${depName}`;
    const target = lookup(candidate);
    if (target !== undefined) return target;
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
