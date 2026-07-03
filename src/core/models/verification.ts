import { z } from 'zod';
import { FixCandidateSchema } from './fix.js';

export const StepNameSchema = z.enum(['copy', 'apply', 'install', 'rescan', 'build', 'test']);
export type StepName = z.infer<typeof StepNameSchema>;

export const StepStatusSchema = z.enum(['pass', 'fail', 'skipped', 'timeout']);
export type StepStatus = z.infer<typeof StepStatusSchema>;

export const StepResultSchema = z.object({
  step: StepNameSchema,
  status: StepStatusSchema,
  exitCode: z.number().int().optional(),
  durationMs: z.number().nonnegative(),
  /** Last ~40 lines, ANSI-stripped and MD-escaped before entering any report. */
  logTail: z.string(),
  testCounts: z
    .object({
      passed: z.number().int().nonnegative(),
      failed: z.number().int().nonnegative(),
      total: z.number().int().nonnegative(),
    })
    .optional(),
});
export type StepResult = z.infer<typeof StepResultSchema>;

/**
 * Verdict semantics (blueprint §2 confidence rules — computed ONLY from exit codes
 * and VeriPatch's own re-scan, never log-text heuristics):
 * - HIGH:         fix eliminates the vuln and the project's own tests pass
 * - MEDIUM:       fix eliminates the vuln; no test signal available
 * - FAIL:         fix is ineffective or breaks install/build/test
 * - INCONCLUSIVE: a step timed out — no honest verdict possible
 */
export const ConfidenceSchema = z.enum(['HIGH', 'MEDIUM', 'FAIL', 'INCONCLUSIVE']);
export type Confidence = z.infer<typeof ConfidenceSchema>;

export const VerificationResultSchema = z.object({
  candidate: FixCandidateSchema,
  steps: z.array(StepResultSchema),
  confidence: ConfidenceSchema,
  residualRisks: z.array(z.string()),
  runId: z.string().min(1),
  startedAt: z.iso.datetime(),
});
export type VerificationResult = z.infer<typeof VerificationResultSchema>;
