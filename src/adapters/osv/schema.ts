import { z } from 'zod';
import { AdvisorySchema, type Advisory } from '../../core/models/index.js';
import { sanitizeExternalString } from '../../shared/sanitize.js';
import { deriveSeverity } from './cvss.js';

/**
 * OSV wire format (https://ossf.github.io/osv-schema/) — only the fields we
 * consume, loose elsewhere. Validation failures drop the advisory and are
 * counted as dataErrors, never silently ignored (blueprint §5.1).
 */

const OsvEventSchema = z
  .object({
    introduced: z.string().optional(),
    fixed: z.string().optional(),
    last_affected: z.string().optional(),
    limit: z.string().optional(),
  })
  .loose();

const OsvRangeSchema = z
  .object({
    type: z.string(),
    events: z.array(OsvEventSchema),
  })
  .loose();

const OsvAffectedSchema = z
  .object({
    package: z
      .object({
        ecosystem: z.string(),
        name: z.string(),
      })
      .loose(),
    ranges: z.array(OsvRangeSchema).optional(),
    versions: z.array(z.string()).optional(),
    database_specific: z.looseObject({ severity: z.string().optional() }).optional(),
  })
  .loose();

export const OsvAdvisorySchema = z
  .object({
    id: z.string().min(1),
    modified: z.string(),
    aliases: z.array(z.string()).optional(),
    summary: z.string().optional(),
    details: z.string().optional(),
    severity: z.array(z.looseObject({ type: z.string(), score: z.string() })).optional(),
    affected: z.array(OsvAffectedSchema).optional(),
    references: z.array(z.looseObject({ url: z.string() })).optional(),
    database_specific: z.looseObject({ severity: z.string().optional() }).optional(),
  })
  .loose();
export type OsvAdvisory = z.infer<typeof OsvAdvisorySchema>;

export const OsvQueryBatchResponseSchema = z
  .object({
    results: z.array(
      z
        .object({
          vulns: z
            .array(z.looseObject({ id: z.string(), modified: z.string().optional() }))
            .optional(),
        })
        .loose(),
    ),
  })
  .loose();

/**
 * Normalize a raw OSV advisory into the core Advisory shape.
 * Returns undefined when the input fails validation (caller counts it).
 */
export function normalizeOsvAdvisory(raw: unknown): Advisory | undefined {
  const parsed = OsvAdvisorySchema.safeParse(raw);
  if (!parsed.success) return undefined;
  const osv = parsed.data;

  const affected: Advisory['affected'] = [];
  for (const entry of osv.affected ?? []) {
    if (entry.package.ecosystem !== 'npm') continue;
    const pkg = entry.package.name;

    for (const range of entry.ranges ?? []) {
      if (range.type !== 'SEMVER' && range.type !== 'ECOSYSTEM') continue;
      const converted = eventsToSemverRanges(range.events);
      for (const { rangeStr, fixed } of converted) {
        affected.push({ pkg, ranges: [rangeStr], ...(fixed !== undefined ? { fixed } : {}) });
      }
    }

    // Explicit version enumerations become exact-match ranges.
    if (entry.versions !== undefined && entry.versions.length > 0) {
      affected.push({ pkg, ranges: entry.versions.map((v) => v.trim()) });
    }
  }

  const candidate: Advisory = {
    id: sanitizeExternalString(osv.id),
    aliases: (osv.aliases ?? []).map(sanitizeExternalString),
    summary: sanitizeExternalString(osv.summary ?? osv.details?.slice(0, 300) ?? ''),
    severity: deriveSeverity(
      (osv.severity ?? []).map((s) => s.score),
      osv.database_specific?.severity,
    ),
    affected,
    references: (osv.references ?? []).map((r) => sanitizeExternalString(r.url)),
    modified: sanitizeExternalString(osv.modified),
  };

  const validated = AdvisorySchema.safeParse(candidate);
  return validated.success ? validated.data : undefined;
}

/**
 * OSV events walk a number line: introduced/fixed/last_affected in order.
 * Convert each introduced..(fixed|last_affected|∞) window into a semver range.
 */
function eventsToSemverRanges(
  events: z.infer<typeof OsvEventSchema>[],
): { rangeStr: string; fixed?: string }[] {
  const out: { rangeStr: string; fixed?: string }[] = [];
  let introduced: string | undefined;

  for (const event of events) {
    if (event.introduced !== undefined) {
      introduced = event.introduced;
      continue;
    }
    if (event.fixed !== undefined) {
      const lower = introduced === undefined || introduced === '0' ? undefined : introduced;
      out.push({
        rangeStr: lower === undefined ? `<${event.fixed}` : `>=${lower} <${event.fixed}`,
        fixed: event.fixed,
      });
      introduced = undefined;
      continue;
    }
    if (event.last_affected !== undefined) {
      const lower = introduced === undefined || introduced === '0' ? undefined : introduced;
      out.push({
        rangeStr:
          lower === undefined ? `<=${event.last_affected}` : `>=${lower} <=${event.last_affected}`,
      });
      introduced = undefined;
    }
  }

  // Open-ended: introduced with no closing event — everything from there up.
  if (introduced !== undefined) {
    out.push({ rangeStr: introduced === '0' ? '*' : `>=${introduced}` });
  }
  return out;
}
