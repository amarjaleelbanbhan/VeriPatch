import { AppError } from '../../../shared/errors.js';
import { err, ok, type Result } from '../../../shared/result.js';
import { DepNodeSchema, type DepNode } from '../../../core/models/index.js';
import { MAX_PATHS_PER_NODE, ROOT_ID, ROOT_LABEL, collectPaths, dedupePaths } from '../paths.js';
import type { RawPackageJson } from '../schema.js';
import { hasForeignProtocol, stripNpmProtocol, type YarnEntries } from './entries.js';

/**
 * Builds DepNode[] from normalized yarn entries. Unlike npm's location tree,
 * yarn resolution is direct: a dependency `name@range` resolves to the entry
 * stored under exactly that descriptor. Root dependencies come from
 * package.json — yarn.lock itself does not say which entries are roots, nor
 * which are dev-only, so dev-ness is computed by reachability: a node is dev
 * iff it is reachable from devDependencies but not from regular/optional ones.
 */
export function buildYarnGraph(entries: YarnEntries, pkg: RawPackageJson): Result<DepNode[]> {
  // Node identity: `name@version` (merges duplicate descriptors of one install).
  const names = new Map<string, string>();
  const versions = new Map<string, string>();
  const integrity = new Map<string, string>();
  const edges = new Map<string, string[]>();

  const idOf = (descriptor: string): string | undefined => {
    const entry = entries.get(descriptor);
    return entry === undefined ? undefined : `${entry.name}@${entry.version}`;
  };

  for (const entry of entries.values()) {
    const id = `${entry.name}@${entry.version}`;
    names.set(id, entry.name);
    versions.set(id, entry.version);
    if (entry.integrity !== undefined && !integrity.has(id)) {
      integrity.set(id, entry.integrity);
    }
    const targets = edges.get(id) ?? [];
    for (const [depName, depRange] of Object.entries({
      ...entry.dependencies,
      ...entry.optionalDependencies,
    })) {
      const target = idOf(`${depName}@${depRange}`);
      if (target !== undefined && !targets.includes(target)) targets.push(target);
    }
    edges.set(id, targets);
  }

  const resolveRoots = (deps: Record<string, string> | undefined): string[] => {
    const roots: string[] = [];
    for (const [name, range] of Object.entries(deps ?? {})) {
      if (hasForeignProtocol(range)) continue;
      const target = idOf(`${name}@${stripNpmProtocol(range)}`);
      if (target !== undefined) roots.push(target);
    }
    return roots;
  };

  const prodRoots = [...resolveRoots(pkg.dependencies), ...resolveRoots(pkg.optionalDependencies)];
  const devRoots = resolveRoots(pkg.devDependencies);
  const rootEdge = [...new Set([...prodRoots, ...devRoots])];
  edges.set(ROOT_ID, rootEdge);

  const prodReachable = reach(prodRoots, edges);
  const pathsById = collectPaths(names, edges);
  const directIds = new Set(rootEdge);

  const nodes: DepNode[] = [];
  for (const [id, name] of names) {
    const sri = integrity.get(id);
    const candidate: DepNode = {
      name,
      version: versions.get(id) ?? '',
      paths: dedupePaths(pathsById.get(id) ?? [[ROOT_LABEL, name]]).slice(0, MAX_PATHS_PER_NODE),
      dev: !prodReachable.has(id),
      direct: directIds.has(id),
      ...(sri !== undefined ? { integrity: sri } : {}),
    };
    const validated = DepNodeSchema.safeParse(candidate);
    if (!validated.success) {
      const issue = validated.error.issues[0];
      return err(
        AppError.user(
          'LOCKFILE_HOSTILE_ENTRY',
          `Lockfile entry "${candidate.name}@${candidate.version}" rejected: ${issue?.message ?? 'invalid'}`,
          'The lockfile contains entries that do not look like honest npm packages.',
        ),
      );
    }
    nodes.push(validated.data);
  }

  nodes.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  return ok(nodes);
}

function reach(roots: string[], edges: ReadonlyMap<string, string[]>): Set<string> {
  const seen = new Set<string>(roots);
  const queue = [...roots];
  let id: string | undefined;
  while ((id = queue.shift()) !== undefined) {
    for (const next of edges.get(id) ?? []) {
      if (!seen.has(next)) {
        seen.add(next);
        queue.push(next);
      }
    }
  }
  return seen;
}
