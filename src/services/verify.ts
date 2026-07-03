import { randomUUID } from 'node:crypto';
import { computeConfidence } from '../core/confidence.js';
import type { FixCandidate, VerificationResult } from '../core/models/index.js';
import type { Sandbox, SandboxConfig, StepListener } from '../core/ports.js';
import type { Result } from '../shared/result.js';
import { map } from '../shared/result.js';

/**
 * Orchestrates one candidate through the sandbox pipeline and computes its
 * confidence verdict (blueprint §2 data flow). Depends only on the
 * core-defined Sandbox port — the concrete Docker implementation is injected
 * by the CLI composition root.
 */
export interface VerifyRequest {
  projectDir: string;
  candidate: FixCandidate;
  config: SandboxConfig;
}

export async function verifyCandidate(
  sandbox: Sandbox,
  request: VerifyRequest,
  onStep?: StepListener,
): Promise<Result<VerificationResult>> {
  const startedAt = new Date().toISOString();
  const runId = randomUUID();

  const stepsResult = await sandbox.run(
    { projectDir: request.projectDir, candidate: request.candidate, config: request.config },
    onStep,
  );

  return map(stepsResult, (steps) => ({
    candidate: request.candidate,
    steps,
    confidence: computeConfidence(steps),
    residualRisks: residualRisksFor(steps),
    runId,
    startedAt,
  }));
}

/**
 * Documented, structural residual risk (blueprint §9 "verdict integrity"):
 * a HIGH/MEDIUM verdict means the project's OWN checks passed — it is not a
 * claim that those checks are honest or sufficient.
 */
function residualRisksFor(steps: VerificationResult['steps']): string[] {
  const risks = [
    "Confidence reflects the project's own build/test exit codes; a project can only be as honest as its own checks.",
  ];
  const test = steps.find((s) => s.step === 'test');
  if (test === undefined || test.status === 'skipped') {
    risks.push('No test step ran — this verdict is not backed by any automated test coverage.');
  }
  return risks;
}
