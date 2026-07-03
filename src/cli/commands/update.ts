import { execFileSync, execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { detectLockfile } from '../../adapters/lockfile/detect.js';
import { loadMergedScan } from './shared.js';
import { loadConfig } from '../../shared/config.js';
import { AppError } from '../../shared/errors.js';
import { createLogger } from '../../shared/logger.js';
import { errorExitCode } from '../exit-code.js';

/**
 * `veripatch update <vulnId>` (blueprint §6): applies a verified fix to the
 * real working tree by replaying the exact bump the sandbox proved safe.
 * Never commits, never pushes — the user reviews and commits themselves.
 */
export interface UpdateCommandFlags {
  cwd: string;
  configPath: string | undefined;
  vulnId: string;
  force: boolean;
  allowDirty: boolean;
}

const ACCEPTABLE_CONFIDENCE = new Set(['HIGH', 'MEDIUM']);

/**
 * On Windows, `npm` resolves to `npm.cmd`, a batch file that `execFileSync`
 * cannot spawn directly (EINVAL) without going through a shell — and Node
 * deprecates (DEP0190) combining shell:true with array-form args, since
 * that argument form is not escaped for the shell. `execSync` with a single,
 * manually quoted command string is the documented safe alternative: `pkg`
 * has already passed npm-name validation and `to` is a validated semver
 * string (see fix-resolver.ts), so neither can contain a quote or shell
 * metacharacter — quoting them here is a formality, not the safety boundary.
 */
function quoteArg(value: string): string {
  return `"${value.replaceAll('"', '\\"')}"`;
}

export function runUpdateCommand(flags: UpdateCommandFlags): number {
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

  const vuln = scanResult.value.vulns.find(
    (v) => v.id === flags.vulnId || v.aliases.includes(flags.vulnId),
  );
  if (vuln === undefined) {
    const notFound = AppError.user(
      'VULN_NOT_FOUND',
      `No vulnerability "${flags.vulnId}" in the last scan.`,
    );
    logger.error({ code: notFound.code }, notFound.message);
    return errorExitCode(notFound);
  }
  if (!vuln.fix.feasible) {
    const infeasible = AppError.user(
      'FIX_INFEASIBLE',
      vuln.fix.reason ?? 'This vulnerability has no feasible fix.',
    );
    logger.error({ code: infeasible.code }, infeasible.message);
    return errorExitCode(infeasible);
  }

  const confidence = vuln.verification?.confidence;
  if (!flags.force && (confidence === undefined || !ACCEPTABLE_CONFIDENCE.has(confidence))) {
    const refused = AppError.user(
      'UPDATE_REFUSED_UNVERIFIED',
      confidence === undefined
        ? `${flags.vulnId} has not been verified — run \`veripatch verify ${flags.vulnId}\` first.`
        : `${flags.vulnId}'s verification confidence is ${confidence}, not HIGH/MEDIUM.`,
      'Pass --force to apply anyway (not recommended).',
    );
    logger.error({ code: refused.code }, refused.message);
    return errorExitCode(refused);
  }
  if (confidence !== undefined && !ACCEPTABLE_CONFIDENCE.has(confidence)) {
    logger.warn(`--force: applying despite a ${confidence} verification confidence.`);
  }

  const detected = detectLockfile(flags.cwd);
  if (detected.packageManager !== null && detected.packageManager !== 'npm') {
    const unsupported = AppError.user(
      'UPDATE_UNSUPPORTED_PACKAGE_MANAGER',
      `This project uses ${detected.packageManager} — \`update\` applies fixes with npm and would write a package-lock.json into a ${detected.packageManager} project.`,
      `Apply the bump manually: \`${detected.packageManager} up ${vuln.pkg}@${vuln.fix.to}\`.`,
    );
    logger.error({ code: unsupported.code }, unsupported.message);
    return errorExitCode(unsupported);
  }

  if (!flags.allowDirty) {
    const dirty = isWorkingTreeDirty(flags.cwd);
    if (dirty !== false) {
      const reason =
        dirty === true
          ? 'The working tree has uncommitted changes.'
          : 'Could not determine whether the working tree is clean (not a git repository, or git is unavailable).';
      const refused = AppError.user(
        'UPDATE_REFUSED_DIRTY',
        reason,
        'Pass --allow-dirty to apply anyway.',
      );
      logger.error({ code: refused.code }, refused.message);
      return errorExitCode(refused);
    }
  }

  try {
    if (vuln.fix.strategy === 'override') {
      // A transitive dependency is not the root's to install — plain
      // `npm install pkg@to` would ADD it as a root dependency. Write the
      // same overrides entry the sandbox verified, then regenerate the
      // lockfile.
      const manifestPath = path.join(flags.cwd, 'package.json');
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as Record<string, unknown>;
      const existingOverrides =
        typeof manifest['overrides'] === 'object' && manifest['overrides'] !== null
          ? (manifest['overrides'] as Record<string, unknown>)
          : {};
      manifest['overrides'] = { ...existingOverrides, [vuln.pkg]: vuln.fix.to };
      fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
      execSync('npm install --package-lock-only', { cwd: flags.cwd, stdio: 'pipe' });
    } else {
      const spec = quoteArg(`${vuln.pkg}@${vuln.fix.to}`);
      execSync(`npm install ${spec} --package-lock-only`, { cwd: flags.cwd, stdio: 'pipe' });
    }
  } catch (cause) {
    const failed = AppError.world(
      'UPDATE_APPLY_FAILED',
      `npm install failed while applying the fix`,
      undefined,
      cause,
    );
    logger.error({ code: failed.code }, failed.message);
    return errorExitCode(failed);
  }

  process.stdout.write(
    `Applied: ${vuln.pkg} ${vuln.fix.from} -> ${vuln.fix.to} (fixes ${flags.vulnId})\n`,
  );
  process.stdout.write(printDiffSummary(flags.cwd));
  process.stdout.write(
    `\nSuggested commit message:\n  fix(deps): bump ${vuln.pkg} to ${vuln.fix.to} (fixes ${flags.vulnId})\n`,
  );
  return 0;
}

/** true = dirty, false = clean, undefined = could not tell (not a repo / git missing). */
function isWorkingTreeDirty(cwd: string): boolean | undefined {
  try {
    const output = execFileSync('git', ['status', '--porcelain'], { cwd, stdio: 'pipe' }).toString(
      'utf8',
    );
    return output.trim().length > 0;
  } catch {
    return undefined;
  }
}

function printDiffSummary(cwd: string): string {
  try {
    return execFileSync('git', ['diff', '--stat'], { cwd, stdio: 'pipe' }).toString('utf8');
  } catch {
    return '';
  }
}
