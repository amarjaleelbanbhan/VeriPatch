import { AppError } from '../../shared/errors.js';
import { err, ok, type Result } from '../../shared/result.js';
import { DepNodeSchema, type DepNode } from '../../core/models/index.js';
import { MAX_PATHS_PER_NODE, ROOT_ID, ROOT_LABEL, collectPaths, dedupePaths } from './paths.js';

/**
 * Ecosystem-agnostic DepNode[] assembly for flat lockfiles (yarn, pnpm).
 * The caller resolves its format's references down to opaque node IDs
 * (canonically `name@version`); this builder derives everything the graph
 * model needs from those IDs alone:
 *
 * - provenance paths via the shared root BFS
 * - direct = resolved root dependency
 * - dev = not reachable from any regular/optional root (these formats do
 *   not record dev-ness per entry the way npm's location tree does)
 * - schema validation per node — hostile names are a hard UserError
 */
export interface FlatGraphInput {
  /** Node ID → package name. */
  names: ReadonlyMap<string, string>;
  /** Node ID → resolved version. */
  versions: ReadonlyMap<string, string>;
  /** Node ID → integrity/checksum, where the lockfile records one. */
  integrity: ReadonlyMap<string, string>;
  /** Node ID → dependency node IDs (regular + optional, resolved). */
  edges: Map<string, string[]>;
  /** Node IDs of package.json dependencies + optionalDependencies. */
  prodRoots: string[];
  /** Node IDs of package.json devDependencies. */
  devRoots: string[];
}

export function buildFlatGraphNodes(input: FlatGraphInput): Result<DepNode[]> {
  const { names, versions, integrity, edges, prodRoots, devRoots } = input;

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
