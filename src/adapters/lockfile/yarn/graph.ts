import { type Result } from '../../../shared/result.js';
import { type DepNode } from '../../../core/models/index.js';
import { buildFlatGraphNodes } from '../graph-builder.js';
import type { RawPackageJson } from '../schema.js';
import { hasForeignProtocol, stripNpmProtocol, type YarnEntries } from './entries.js';

/**
 * Resolves yarn's descriptor references down to `name@version` node IDs and
 * hands assembly to the shared flat-graph builder. Unlike npm's location
 * tree, yarn resolution is direct: a dependency `name@range` resolves to the
 * entry stored under exactly that descriptor. Root dependencies come from
 * package.json — yarn.lock itself does not say which entries are roots, nor
 * which are dev-only.
 */
export function buildYarnGraph(entries: YarnEntries, pkg: RawPackageJson): Result<DepNode[]> {
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

  return buildFlatGraphNodes({
    names,
    versions,
    integrity,
    edges,
    prodRoots: [...resolveRoots(pkg.dependencies), ...resolveRoots(pkg.optionalDependencies)],
    devRoots: resolveRoots(pkg.devDependencies),
  });
}
