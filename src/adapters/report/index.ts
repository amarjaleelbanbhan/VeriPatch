import fs from 'node:fs';
import path from 'node:path';
import type { ScanOutput, VerificationResult } from '../../core/models/index.js';
import type { Reporter, ReportPaths } from '../../core/ports.js';
import { AppError } from '../../shared/errors.js';
import { err, ok, type Result } from '../../shared/result.js';
import { writeJsonReport } from './json.js';
import { renderScanReportMarkdown } from './md.js';

/**
 * Writes both report formats for a scan (blueprint §5.3 Reporter port).
 * A bare VerificationResult carries no severity/package-install context of
 * its own — every VerificationResult this codebase produces is already
 * merged into a ScanOutput vuln entry (services/report.ts) before reaching
 * a reporter, so that is the only shape actually written to disk.
 */
export class FileReporter implements Reporter {
  write(
    results: ScanOutput | VerificationResult,
    dir: string,
    baseName = 'report',
  ): Result<ReportPaths> {
    if (!('schemaVersion' in results)) {
      return err(
        AppError.internal(
          'REPORT_UNSUPPORTED_INPUT',
          'A standalone VerificationResult has no severity/package context to report on its own — merge it into a ScanOutput first.',
        ),
      );
    }

    const jsonPath = path.join(dir, `${baseName}.json`);
    const mdPath = path.join(dir, `${baseName}.md`);

    const jsonResult = writeJsonReport(results, jsonPath);
    if (!jsonResult.ok) return jsonResult;

    try {
      fs.writeFileSync(mdPath, renderScanReportMarkdown(results));
    } catch (cause) {
      return err(
        AppError.world('REPORT_WRITE_FAILED', `Could not write ${mdPath}`, undefined, cause),
      );
    }

    return ok({ jsonPath, mdPath });
  }
}
