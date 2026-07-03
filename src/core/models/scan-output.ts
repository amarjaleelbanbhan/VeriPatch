import { z } from 'zod';
import { FixCandidateSchema } from './fix.js';
import { SeveritySchema } from './advisory.js';

/**
 * Machine output (blueprint §5.2, schemaVersion 1). Fields are only ever
 * added within a schema version, never removed or repurposed — CI pipelines
 * depend on this shape being stable.
 */
export const ScannedVulnSchema = z.object({
  id: z.string().min(1),
  aliases: z.array(z.string()),
  pkg: z.string().min(1),
  installed: z.string().min(1),
  severity: SeveritySchema,
  dev: z.boolean(),
  paths: z.array(z.array(z.string())),
  fix: FixCandidateSchema,
  /** Populated once `verify` has run for this vuln; null beforehand (M6). */
  verification: z.null(),
});
export type ScannedVuln = z.infer<typeof ScannedVulnSchema>;

export const ScanSummarySchema = z.object({
  critical: z.number().int().nonnegative(),
  high: z.number().int().nonnegative(),
  medium: z.number().int().nonnegative(),
  low: z.number().int().nonnegative(),
  verified: z.number().int().nonnegative(),
});
export type ScanSummary = z.infer<typeof ScanSummarySchema>;

export const ScanOutputSchema = z.object({
  schemaVersion: z.literal(1),
  tool: z.object({ name: z.literal('VeriPatch'), version: z.string() }),
  generatedAt: z.iso.datetime(),
  scan: z.object({
    lockfileVersion: z.union([z.literal(2), z.literal(3), z.null()]),
    degraded: z.boolean(),
    totalDeps: z.number().int().nonnegative(),
    dataErrors: z.number().int().nonnegative(),
    /** True when advisory data was served from an expired cache (offline). */
    stale: z.boolean(),
  }),
  vulns: z.array(ScannedVulnSchema),
  summary: ScanSummarySchema,
});
export type ScanOutput = z.infer<typeof ScanOutputSchema>;
