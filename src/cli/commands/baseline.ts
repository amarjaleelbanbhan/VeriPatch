import fs from 'node:fs';
import path from 'node:path';
import { loadMergedScan } from './shared.js';
import { BaselineSchema, type Baseline } from '../../core/models/index.js';
import {
  activeBaselineKeys,
  addToBaseline,
  baselineKeyOf,
  pruneBaseline,
  removeFromBaseline,
} from '../../services/baseline.js';
import { loadConfig } from '../../shared/config.js';
import { AppError } from '../../shared/errors.js';
import { createLogger, type Logger } from '../../shared/logger.js';
import { errorExitCode } from '../exit-code.js';

/**
 * `veripatch baseline list|add|remove|prune` (blueprint §7): manage accepted
 * pre-existing debt one finding at a time, with a reason and an optional
 * expiry, instead of only the all-or-nothing `scan --write-baseline`.
 */
export interface BaselineCommandFlags {
  cwd: string;
  configPath: string | undefined;
}

export interface BaselineAddFlags extends BaselineCommandFlags {
  vulnId: string;
  reason: string | undefined;
  /** Days from now after which the acceptance expires (vuln counts as new again). */
  expiresDays: number | undefined;
}

const BASELINE_FILE_NAME = 'baseline.json';

export function runBaselineListCommand(flags: BaselineCommandFlags): number {
  const logger = createLogger({});
  const reportDir = resolveReportDir(flags, logger);
  if (typeof reportDir === 'number') return reportDir;

  const baseline = readBaseline(reportDir);
  if (baseline === undefined || baseline.vulnKeys.length === 0) {
    process.stdout.write('Baseline is empty — no accepted debt.\n');
    return 0;
  }

  const active = activeBaselineKeys(baseline);
  const metaByKey = new Map((baseline.entries ?? []).map((e) => [e.key, e]));
  for (const key of baseline.vulnKeys) {
    const meta = metaByKey.get(key);
    const parts = [key];
    if (!active.has(key)) parts.push('[EXPIRED]');
    if (meta?.expiresAt !== undefined && active.has(key)) {
      parts.push(`expires ${meta.expiresAt.slice(0, 10)}`);
    }
    if (meta?.addedAt !== undefined) parts.push(`added ${meta.addedAt.slice(0, 10)}`);
    if (meta?.reason !== undefined) parts.push(`— ${meta.reason}`);
    process.stdout.write(`${parts.join('  ')}\n`);
  }
  return 0;
}

export function runBaselineAddCommand(flags: BaselineAddFlags): number {
  const logger = createLogger({});
  const reportDir = resolveReportDir(flags, logger);
  if (typeof reportDir === 'number') return reportDir;

  const scanResult = loadMergedScan(reportDir);
  if (!scanResult.ok) {
    logger.error({ code: scanResult.error.code }, scanResult.error.message);
    return errorExitCode(scanResult.error);
  }
  const matching = scanResult.value.vulns.filter(
    (v) => v.id === flags.vulnId || v.aliases.includes(flags.vulnId),
  );
  if (matching.length === 0) {
    const notFound = AppError.user(
      'VULN_NOT_FOUND',
      `No vulnerability "${flags.vulnId}" in the last scan.`,
      'Run `veripatch scan` first — baseline entries always come from real findings.',
    );
    logger.error({ code: notFound.code }, notFound.message);
    return errorExitCode(notFound);
  }

  const expiresAt =
    flags.expiresDays !== undefined
      ? new Date(Date.now() + flags.expiresDays * 24 * 60 * 60 * 1000).toISOString()
      : undefined;
  const { baseline, changedKeys } = addToBaseline(readBaseline(reportDir), matching, {
    reason: flags.reason,
    expiresAt,
  });

  if (changedKeys.length === 0) {
    process.stdout.write(`Already baselined: ${matching.map(baselineKeyOf).join(', ')}\n`);
    return 0;
  }
  writeBaseline(reportDir, baseline);
  process.stdout.write(`Accepted as debt: ${changedKeys.join(', ')}\n`);
  return 0;
}

export function runBaselineRemoveCommand(flags: BaselineCommandFlags & { vulnId: string }): number {
  const logger = createLogger({});
  const reportDir = resolveReportDir(flags, logger);
  if (typeof reportDir === 'number') return reportDir;

  const existing = readBaseline(reportDir);
  if (existing === undefined) {
    process.stdout.write('Baseline is empty — nothing to remove.\n');
    return 0;
  }
  const { baseline, changedKeys } = removeFromBaseline(existing, flags.vulnId);
  if (changedKeys.length === 0) {
    process.stdout.write(`"${flags.vulnId}" is not in the baseline.\n`);
    return 0;
  }
  writeBaseline(reportDir, baseline);
  process.stdout.write(`Removed from baseline: ${changedKeys.join(', ')}\n`);
  return 0;
}

export function runBaselinePruneCommand(flags: BaselineCommandFlags): number {
  const logger = createLogger({});
  const reportDir = resolveReportDir(flags, logger);
  if (typeof reportDir === 'number') return reportDir;

  const existing = readBaseline(reportDir);
  if (existing === undefined) {
    process.stdout.write('Baseline is empty — nothing to prune.\n');
    return 0;
  }
  const scanResult = loadMergedScan(reportDir);
  if (!scanResult.ok) {
    logger.error({ code: scanResult.error.code }, scanResult.error.message);
    return errorExitCode(scanResult.error);
  }

  const { baseline, changedKeys } = pruneBaseline(existing, scanResult.value.vulns);
  if (changedKeys.length === 0) {
    process.stdout.write('Nothing to prune — every baselined vuln is still present.\n');
    return 0;
  }
  writeBaseline(reportDir, baseline);
  process.stdout.write(`Pruned (no longer found): ${changedKeys.join(', ')}\n`);
  return 0;
}

/** Returns the resolved report dir, or an exit code when config loading fails. */
function resolveReportDir(flags: BaselineCommandFlags, logger: Logger): string | number {
  const configResult = loadConfig({
    cwd: flags.cwd,
    ...(flags.configPath !== undefined ? { configPath: flags.configPath } : {}),
    env: process.env,
  });
  if (!configResult.ok) {
    logger.error({ code: configResult.error.code }, configResult.error.message);
    return errorExitCode(configResult.error);
  }
  return path.resolve(flags.cwd, configResult.value.config.reportDir);
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

function writeBaseline(reportDir: string, baseline: Baseline): void {
  fs.mkdirSync(reportDir, { recursive: true });
  fs.writeFileSync(
    path.join(reportDir, BASELINE_FILE_NAME),
    JSON.stringify(baseline, null, 2) + '\n',
  );
}
