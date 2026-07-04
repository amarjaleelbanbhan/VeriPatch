import fs from 'node:fs';
import path from 'node:path';
import {
  ScanOutputSchema,
  VerificationResultSchema,
  type ScanOutput,
} from '../../core/models/index.js';
import { mergeVerification } from '../../services/report.js';
import { AppError } from '../../shared/errors.js';
import { err, ok, type Result } from '../../shared/result.js';

export const LAST_SCAN_FILE_NAME = 'last-scan.json';
export const RUNS_DIR_NAME = 'runs';
export const RUN_RESULT_FILE_NAME = 'result.json';

/**
 * Reads last-scan.json and merges in the most recent verification per vuln
 * from .veripatch/runs/*\/result.json — shared by `report` and `update`
 * since both need "the scan, as fully verified so far".
 */
export function loadMergedScan(reportDir: string): Result<ScanOutput> {
  const lastScanPath = path.join(reportDir, LAST_SCAN_FILE_NAME);
  if (!fs.existsSync(lastScanPath)) {
    return err(
      AppError.user(
        'NO_SCAN_FOUND',
        `No ${LAST_SCAN_FILE_NAME} found in ${reportDir}`,
        'Run `veripatch scan` first.',
      ),
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(lastScanPath, 'utf8'));
  } catch (cause) {
    return err(
      AppError.user('SCAN_FILE_MALFORMED', `${lastScanPath} is not valid JSON`, undefined, cause),
    );
  }
  const scanResult = ScanOutputSchema.safeParse(parsed);
  if (!scanResult.success) {
    return err(
      AppError.user('SCAN_FILE_MALFORMED', `${lastScanPath} does not match the scan output schema`),
    );
  }

  return ok(mergeLatestVerifications(scanResult.data, reportDir));
}

/**
 * Merges the most recent verification per vuln from .veripatch/runs/*\/result.json
 * into a scan — shared by `report`, `update`, and `scan` itself, since a
 * fresh `scan` should still show "✓ verified" for a vuln you already ran
 * `veripatch verify` on, not blank it out just because this is a new run.
 */
export function mergeLatestVerifications(scan: ScanOutput, reportDir: string): ScanOutput {
  let merged = scan;
  for (const verification of readAllVerifications(reportDir)) {
    merged = mergeVerification(merged, verification);
  }
  return merged;
}

function readAllVerifications(reportDir: string) {
  const runsDir = path.join(reportDir, RUNS_DIR_NAME);
  if (!fs.existsSync(runsDir)) return [];

  const results = [];
  for (const runId of fs.readdirSync(runsDir)) {
    const resultPath = path.join(runsDir, runId, RUN_RESULT_FILE_NAME);
    if (!fs.existsSync(resultPath)) continue;
    try {
      const parsed = VerificationResultSchema.safeParse(
        JSON.parse(fs.readFileSync(resultPath, 'utf8')),
      );
      if (parsed.success) results.push(parsed.data);
    } catch {
      // a corrupted run artifact is skipped, not fatal to the whole report
    }
  }
  // Latest-per-(vulnId,pkg) wins, in case a vuln was verified more than once.
  const latestByKey = new Map<string, (typeof results)[number]>();
  for (const result of results.sort((a, b) => a.startedAt.localeCompare(b.startedAt))) {
    latestByKey.set(`${result.candidate.vulnId}::${result.candidate.pkg}`, result);
  }
  return [...latestByKey.values()];
}
