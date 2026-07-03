import type { FixCandidate, StepResult } from '../../../core/models/index.js';
import type { AdvisorySource, LockfileParser } from '../../../core/ports.js';
import { matchVulnerabilities } from '../../../core/rules/match.js';
import { sanitizeExternalString } from '../../../shared/sanitize.js';

/**
 * Re-scans the sandbox's (post-bump) lockfile to prove the vulnerability
 * actually left the resolved tree (blueprint §2 data flow: "VS->RE: re-scan
 * sandbox lockfile"). Runs in VerifyService's own trust zone against the
 * bind-mounted staging directory — never inside the untrusted container.
 */
export async function runRescanStep(
  parser: LockfileParser,
  advisorySource: AdvisorySource,
  stagingDir: string,
  candidate: FixCandidate,
): Promise<StepResult> {
  const start = performance.now();

  const graphResult = parser.parse(stagingDir);
  if (!graphResult.ok) {
    return failedRescan(start, graphResult.error.message);
  }

  const advisoryResult = await advisorySource.getAdvisories(graphResult.value.nodes);
  if (!advisoryResult.ok) {
    return failedRescan(start, advisoryResult.error.message);
  }

  const vulns = matchVulnerabilities(graphResult.value.nodes, advisoryResult.value.advisories);
  const stillPresent = vulns.some(
    (v) => v.advisory.id === candidate.vulnId && v.node.name === candidate.pkg,
  );

  return {
    step: 'rescan',
    status: stillPresent ? 'fail' : 'pass',
    durationMs: Math.round(performance.now() - start),
    logTail: stillPresent
      ? `${candidate.vulnId} is still present in ${candidate.pkg} after the bump.`
      : `${candidate.vulnId} is no longer present in ${candidate.pkg}.`,
  };
}

function failedRescan(start: number, message: string): StepResult {
  return {
    step: 'rescan',
    status: 'fail',
    durationMs: Math.round(performance.now() - start),
    logTail: sanitizeExternalString(message),
  };
}
