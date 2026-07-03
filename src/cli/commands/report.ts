import path from 'node:path';
import { FileReporter } from '../../adapters/report/index.js';
import { renderPrComment, renderScanReportMarkdown } from '../../adapters/report/md.js';
import type { ScanOutput } from '../../core/models/index.js';
import { loadMergedScan } from './shared.js';
import { loadConfig } from '../../shared/config.js';
import { AppError } from '../../shared/errors.js';
import { createLogger } from '../../shared/logger.js';
import { errorExitCode } from '../exit-code.js';

/**
 * `veripatch report [vulnId]` (blueprint §6): re-renders evidence report(s)
 * from stored run artifacts without re-running scan or verify.
 */
export interface ReportCommandFlags {
  cwd: string;
  configPath: string | undefined;
  vulnId: string | undefined;
  format: 'md' | 'json' | 'pr-comment';
}

export function runReportCommand(flags: ReportCommandFlags): number {
  const logger = createLogger({});

  const configResult = loadConfig({
    cwd: flags.cwd,
    ...(flags.configPath !== undefined ? { configPath: flags.configPath } : {}),
    env: process.env,
  });
  if (!configResult.ok) {
    logger.error({ code: configResult.error.code }, configResult.error.message);
    return errorExitCode(configResult.error);
  }
  const reportDir = path.resolve(flags.cwd, configResult.value.config.reportDir);

  const scanResult = loadMergedScan(reportDir);
  if (!scanResult.ok) {
    logger.error({ code: scanResult.error.code }, scanResult.error.message);
    return errorExitCode(scanResult.error);
  }
  let scan = scanResult.value;

  const vulnId = flags.vulnId;
  if (vulnId !== undefined) {
    const vuln = scan.vulns.find((v) => v.id === vulnId || v.aliases.includes(vulnId));
    if (vuln === undefined) {
      const notFound = AppError.user(
        'VULN_NOT_FOUND',
        `No vulnerability "${vulnId}" in the last scan.`,
      );
      logger.error({ code: notFound.code }, notFound.message);
      return errorExitCode(notFound);
    }
    scan = { ...scan, vulns: [vuln] };
  }

  const baseName = flags.vulnId !== undefined ? `report-${flags.vulnId}` : 'report';
  const reporter = new FileReporter();
  const written = reporter.write(scan, reportDir, baseName);
  if (!written.ok) {
    logger.error({ code: written.error.code }, written.error.message);
    return errorExitCode(written.error);
  }

  process.stdout.write(`${renderForFormat(scan, flags.format)}\n`);
  return 0;
}

function renderForFormat(scan: ScanOutput, format: ReportCommandFlags['format']): string {
  switch (format) {
    case 'json':
      return JSON.stringify(scan, null, 2);
    case 'md':
      return renderScanReportMarkdown(scan);
    case 'pr-comment':
      return renderPrComment(scan);
  }
}
