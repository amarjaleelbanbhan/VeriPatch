import { z } from 'zod';

/**
 * `.veripatch/baseline.json` (blueprint §6/§7): a repo commits this file to
 * accept pre-existing debt without failing CI; `scan --ci` only fails on
 * vulnerabilities that are new relative to it.
 */
export const BASELINE_SCHEMA_VERSION = 1;

export const BaselineSchema = z.object({
  schemaVersion: z.literal(BASELINE_SCHEMA_VERSION),
  /** Stable identity keys, see baselineKeyOf — advisory id + package name. */
  vulnKeys: z.array(z.string()),
});
export type Baseline = z.infer<typeof BaselineSchema>;
