import fs from 'node:fs';
import path from 'node:path';
import { AdvisoryCache, DEFAULT_CACHE_DIR } from '../../adapters/cache/db.js';
import { NpmLockfileParser } from '../../adapters/lockfile/index.js';
import { OsvClient } from '../../adapters/osv/client.js';
import { OsvAdvisorySource } from '../../adapters/osv/index.js';
import { BaselineSchema, type Baseline } from '../../core/models/index.js';
import { diffAgainstBaseline } from '../../services/baseline.js';
import { runScan } from '../../services/scan.js';
import { loadConfig, type Config } from '../../shared/config.js';
import { createLogger } from '../../shared/logger.js';
import { errorExitCode, scanExitCode } from '../exit-code.js';
import { renderScan } from '../render.js';

/**
 * Composition root for `veripatch scan` (blueprint §6). Wires concrete
 * adapters into ScanService, applies baseline diffing for --ci, persists
 * last-scan.json, and renders either the human table or --json output.
 */
export interface ScanCommandFlags {
  cwd: string;
  configPath: string | undefined;
  json: boolean;
  verbose: boolean;
  color: boolean;
  ci: boolean;
  dev: boolean | undefined;
  severity: Config['severityThreshold'] | undefined;
}

const LAST_SCAN_FILE_NAME = 'last-scan.json';
const BASELINE_FILE_NAME = 'baseline.json';

export async function runScanCommand(flags: ScanCommandFlags): Promise<number> {
  const logger = createLogger({ verbose: flags.verbose });

  const configResult = loadConfig({
    cwd: flags.cwd,
    ...(flags.configPath !== undefined ? { configPath: flags.configPath } : {}),
    env: process.env,
    cliFlags: {
      ...(flags.severity !== undefined ? { severityThreshold: flags.severity } : {}),
      ...(flags.dev !== undefined ? { includeDevDeps: flags.dev } : {}),
    },
  });
  if (!configResult.ok) {
    logger.error({ code: configResult.error.code }, configResult.error.message);
    return errorExitCode(configResult.error);
  }
  const { config, warnings } = configResult.value;
  for (const warning of warnings) logger.warn(warning);

  const cacheResult = AdvisoryCache.open(DEFAULT_CACHE_DIR);
  if (!cacheResult.ok) {
    logger.error({ code: cacheResult.error.code }, cacheResult.error.message);
    return errorExitCode(cacheResult.error);
  }
  const cache = cacheResult.value;

  try {
    const scanResult = await runScan(
      {
        parser: new NpmLockfileParser(),
        advisorySource: new OsvAdvisorySource({
          client: new OsvClient(),
          cache,
          cacheTtlHours: config.cacheTtlHours,
          logger,
        }),
      },
      {
        projectDir: flags.cwd,
        severityThreshold: config.severityThreshold,
        ignore: config.ignore,
        includeDevDeps: config.includeDevDeps,
      },
    );

    if (!scanResult.ok) {
      logger.error({ code: scanResult.error.code }, scanResult.error.message);
      return errorExitCode(scanResult.error);
    }
    const output = scanResult.value;

    const reportDir = path.resolve(flags.cwd, config.reportDir);
    fs.mkdirSync(reportDir, { recursive: true });
    fs.writeFileSync(path.join(reportDir, LAST_SCAN_FILE_NAME), JSON.stringify(output, null, 2));

    const baseline = readBaseline(reportDir);
    const { newVulns } = diffAgainstBaseline(output.vulns, baseline);

    if (flags.json) {
      process.stdout.write(`${JSON.stringify(output)}\n`);
    } else {
      process.stdout.write(`${renderScan(output, { color: flags.color })}\n`);
    }

    return scanExitCode({
      ci: flags.ci,
      newVulnCount: newVulns.length,
      totalVulnCount: output.vulns.length,
    });
  } finally {
    cache.close();
  }
}

function readBaseline(reportDir: string): Baseline | undefined {
  const baselinePath = path.join(reportDir, BASELINE_FILE_NAME);
  if (!fs.existsSync(baselinePath)) return undefined;
  try {
    const parsed = BaselineSchema.safeParse(JSON.parse(fs.readFileSync(baselinePath, 'utf8')));
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}
