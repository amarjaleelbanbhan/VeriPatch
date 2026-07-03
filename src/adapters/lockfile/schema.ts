import { z } from 'zod';

/**
 * Raw npm lockfile shape — only the fields we consume. Everything else is
 * ignored by design; unknown structure must never crash the parser.
 */
export const RawPackageEntrySchema = z
  .object({
    name: z.string().optional(),
    version: z.string().optional(),
    dev: z.boolean().optional(),
    optional: z.boolean().optional(),
    link: z.boolean().optional(),
    integrity: z.string().optional(),
    dependencies: z.record(z.string(), z.string()).optional(),
    devDependencies: z.record(z.string(), z.string()).optional(),
    optionalDependencies: z.record(z.string(), z.string()).optional(),
    peerDependencies: z.record(z.string(), z.string()).optional(),
  })
  .loose();
export type RawPackageEntry = z.infer<typeof RawPackageEntrySchema>;

export const RawLockfileSchema = z
  .object({
    name: z.string().optional(),
    lockfileVersion: z.number(),
    packages: z.record(z.string(), RawPackageEntrySchema).optional(),
  })
  .loose();
export type RawLockfile = z.infer<typeof RawLockfileSchema>;

export const RawPackageJsonSchema = z
  .object({
    name: z.string().optional(),
    dependencies: z.record(z.string(), z.string()).optional(),
    devDependencies: z.record(z.string(), z.string()).optional(),
    optionalDependencies: z.record(z.string(), z.string()).optional(),
  })
  .loose();
export type RawPackageJson = z.infer<typeof RawPackageJsonSchema>;
