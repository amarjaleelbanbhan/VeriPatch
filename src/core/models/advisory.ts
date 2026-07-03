import { z } from 'zod';

export const SeverityLabelSchema = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
export type SeverityLabel = z.infer<typeof SeverityLabelSchema>;

export const SeveritySchema = z.object({
  cvss: z.number().min(0).max(10),
  label: SeverityLabelSchema,
});
export type Severity = z.infer<typeof SeveritySchema>;

export const AffectedSchema = z.object({
  pkg: z.string().min(1),
  /** semver range expressions this advisory applies to. */
  ranges: z.array(z.string()),
  /** First version that fixes the vulnerability, when one exists. */
  fixed: z.string().optional(),
});
export type Affected = z.infer<typeof AffectedSchema>;

/** Normalized advisory — already validated and sanitized at the OSV adapter boundary. */
export const AdvisorySchema = z.object({
  id: z.string().min(1),
  aliases: z.array(z.string()),
  summary: z.string(),
  severity: SeveritySchema,
  affected: z.array(AffectedSchema),
  references: z.array(z.string()),
  /** ISO-8601 last-modified timestamp from the source database. */
  modified: z.string(),
});
export type Advisory = z.infer<typeof AdvisorySchema>;
