/**
 * Normalized view of one resolved yarn.lock entry, shared by the classic (v1)
 * and berry (v2+) parsers. Descriptors are normalized to `name@range` with any
 * `npm:` protocol prefix stripped, so the graph builder never sees format
 * differences.
 */
export interface YarnEntry {
  name: string;
  version: string;
  integrity?: string;
  /** Dependency name → normalized range. Non-npm protocols are dropped. */
  dependencies: Record<string, string>;
  optionalDependencies: Record<string, string>;
}

/** Parsed lockfile: normalized descriptor (`name@range`) → resolved entry. */
export type YarnEntries = Map<string, YarnEntry>;

/**
 * Splits a yarn descriptor into name and range at the last `@` (scoped names
 * contain one at position 0). Returns undefined for shapes that cannot be an
 * honest descriptor.
 */
export function splitDescriptor(descriptor: string): { name: string; range: string } | undefined {
  const at = descriptor.lastIndexOf('@');
  if (at <= 0) return undefined; // no separator, or bare "@..." with no name
  const name = descriptor.slice(0, at);
  const range = descriptor.slice(at + 1);
  if (name.length === 0 || range.length === 0) return undefined;
  return { name, range: stripNpmProtocol(range) };
}

/** "npm:^1.0.0" → "^1.0.0"; ranges without a protocol pass through. */
export function stripNpmProtocol(range: string): string {
  return range.startsWith('npm:') ? range.slice('npm:'.length) : range;
}

/** True for ranges VeriPatch cannot resolve against the registry (workspace:, patch:, git..., file:). */
export function hasForeignProtocol(range: string): boolean {
  const colon = range.indexOf(':');
  if (colon === -1) return false;
  return range.slice(0, colon) !== 'npm';
}
