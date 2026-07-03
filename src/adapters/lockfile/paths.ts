/**
 * Root→node dependency-chain collection shared by all lockfile walkers.
 * Nodes are opaque string IDs (npm: install locations, yarn: descriptors);
 * only their display names differ per ecosystem.
 */

/** Enough chains to explain "how did this get here" without combinatorial blowup. */
export const MAX_PATHS_PER_NODE = 8;
export const ROOT_LABEL = 'root';
export const ROOT_ID = '';

/**
 * BFS from the root ID (''), collecting up to MAX_PATHS_PER_NODE name-chains
 * per node. `names` maps every non-root node ID to its package name; `edges`
 * maps node IDs (including the root) to their resolved dependency IDs.
 */
export function collectPaths(
  names: ReadonlyMap<string, string>,
  edges: ReadonlyMap<string, string[]>,
): Map<string, string[][]> {
  const paths = new Map<string, string[][]>();
  interface QueueItem {
    id: string;
    chain: string[];
    visited: Set<string>;
  }
  const queue: QueueItem[] = [{ id: ROOT_ID, chain: [ROOT_LABEL], visited: new Set([ROOT_ID]) }];

  let item: QueueItem | undefined;
  while ((item = queue.shift()) !== undefined) {
    for (const next of edges.get(item.id) ?? []) {
      if (item.visited.has(next)) continue; // cycle guard
      const nextName = names.get(next);
      if (nextName === undefined) continue;
      const existing = paths.get(next) ?? [];
      if (existing.length >= MAX_PATHS_PER_NODE) continue; // saturated — stop expanding through it
      const chain = [...item.chain, nextName];
      existing.push(chain);
      paths.set(next, existing);
      queue.push({ id: next, chain, visited: new Set([...item.visited, next]) });
    }
  }
  return paths;
}

export function dedupePaths(paths: string[][]): string[][] {
  const seen = new Set<string>();
  const out: string[][] = [];
  for (const p of paths) {
    const key = JSON.stringify(p);
    if (!seen.has(key)) {
      seen.add(key);
      out.push(p);
    }
  }
  return out;
}
