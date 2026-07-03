import { z } from 'zod';

/**
 * `.veripatch/baseline.json` (blueprint §6/§7): a repo commits this file to
 * accept pre-existing debt without failing CI; `scan --ci` only fails on
 * vulnerabilities that are new relative to it.
 */
export const BASELINE_SCHEMA_VERSION = 1;

/**
 * Optional per-key metadata (added within schemaVersion 1): why this debt was
 * accepted, when, and when the acceptance runs out. An expired entry counts
 * as NOT baselined — the vuln shows up as new again in `scan --ci`.
 */
export const BaselineEntrySchema = z.object({
  key: z.string().min(1),
  reason: z.string().optional(),
  addedAt: z.iso.datetime().optional(),
  expiresAt: z.iso.datetime().optional(),
});
export type BaselineEntry = z.infer<typeof BaselineEntrySchema>;

export const BaselineSchema = z.object({
  schemaVersion: z.literal(BASELINE_SCHEMA_VERSION),
  /** Stable identity keys, see baselineKeyOf — advisory id + package name. */
  vulnKeys: z.array(z.string()),
  /** Metadata per key; keys without an entry are accepted indefinitely. */
  entries: z.array(BaselineEntrySchema).optional(),
});
export type Baseline = z.infer<typeof BaselineSchema>;
