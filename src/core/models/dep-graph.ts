import { z } from 'zod';

/**
 * npm package name rules (scoped or bare). Hostile lockfiles must not smuggle
 * shell metacharacters or traversal sequences through package names.
 */
export const NPM_NAME_REGEX = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;

export const DepNodeSchema = z.object({
  name: z.string().min(1).max(214).regex(NPM_NAME_REGEX, 'invalid npm package name'),
  version: z.string().min(1),
  /** Every dependency chain from the root to this node, e.g. [["root","a","b"]]. */
  paths: z.array(z.array(z.string())),
  dev: z.boolean(),
  direct: z.boolean(),
  /** SRI hash from the lockfile; absence is itself a finding (dependency confusion). */
  integrity: z.string().optional(),
});
export type DepNode = z.infer<typeof DepNodeSchema>;

/**
 * Which package manager's lockfile produced the graph. null only in degraded
 * mode — with no lockfile there is nothing to attribute.
 */
export const PackageManagerSchema = z.union([
  z.literal('npm'),
  z.literal('yarn'),
  z.literal('pnpm'),
  z.null(),
]);
export type PackageManager = z.infer<typeof PackageManagerSchema>;

export const DepGraphSchema = z.object({
  nodes: z.array(DepNodeSchema),
  /**
   * The lockfile's own major version number (npm 2/3, yarn 1 or berry 4+,
   * pnpm 6/9...). Which versions are *supported* is each parser's decision,
   * enforced at parse time — the schema only records what was read.
   * null only in degraded mode, where no lockfile exists.
   */
  lockfileVersion: z.union([z.number().int(), z.null()]),
  packageManager: PackageManagerSchema,
  /** True when parsed from package.json ranges only (no lockfile) — verify is disabled. */
  degraded: z.boolean(),
});
export type DepGraph = z.infer<typeof DepGraphSchema>;
