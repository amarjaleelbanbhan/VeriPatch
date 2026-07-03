import { summarizeVulns } from '../core/rules/severity.js';
import type { ScanOutput, VerificationResult } from '../core/models/index.js';

/**
 * Merges a fresh VerificationResult into the matching vuln entry of a scan
 * and recomputes the summary's `verified` count. Pure — no I/O; the report
 * command handles reading/writing the surrounding files.
 */
export function mergeVerification(scan: ScanOutput, verification: VerificationResult): ScanOutput {
  const vulns = scan.vulns.map((vuln) =>
    vuln.id === verification.candidate.vulnId && vuln.pkg === verification.candidate.pkg
      ? { ...vuln, verification }
      : vuln,
  );
  return { ...scan, vulns, summary: summarizeVulns(vulns) };
}
