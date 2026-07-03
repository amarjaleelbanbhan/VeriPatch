import { z } from 'zod';

export const BumpTypeSchema = z.enum(['patch', 'minor', 'major']);
export type BumpType = z.infer<typeof BumpTypeSchema>;

export const FixStrategySchema = z.enum(['direct', 'override', 'parent-bump']);
export type FixStrategy = z.infer<typeof FixStrategySchema>;

/**
 * Deterministic remediation proposal. Invariant (security §9): `pkg` MUST equal the
 * vulnerable package name — a fix is a version-only change, never a package swap.
 */
export const FixCandidateSchema = z.object({
  vulnId: z.string().min(1),
  pkg: z.string().min(1),
  from: z.string().min(1),
  to: z.string().min(1),
  bumpType: BumpTypeSchema,
  strategy: FixStrategySchema,
  feasible: z.boolean(),
  /** Populated when feasible is false (e.g. "no fixed version published"). */
  reason: z.string().optional(),
});
export type FixCandidate = z.infer<typeof FixCandidateSchema>;
