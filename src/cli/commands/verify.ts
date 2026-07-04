import fs from 'node:fs';
import path from 'node:path';
import Docker from 'dockerode';
import { AdvisoryCache, DEFAULT_CACHE_DIR } from '../../adapters/cache/db.js';
import { detectLockfile } from '../../adapters/lockfile/detect.js';
import { OsvClient } from '../../adapters/osv/client.js';
import { OsvAdvisorySource } from '../../adapters/osv/index.js';
import { DockerRuntime } from '../../adapters/sandbox/docker.js';
import { DockerSandbox } from '../../adapters/sandbox/index.js';
import type { ScanOutput, ScannedVuln, VerificationResult } from '../../core/models/index.js';
import type { LockfileParser } from '../../core/ports.js';
import { runScan } from '../../services/scan.js';
import { verifyCandidate } from '../../services/verify.js';
import { loadConfig, type Config } from '../../shared/config.js';
import { AppError } from '../../shared/errors.js';
import { createLogger } from '../../shared/logger.js';
import { mapWithConcurrency } from '../../shared/pool.js';
import { errorExitCode } from '../exit-code.js';
import {
  createPaint,
  explainStep,
  getSymbols,
  resolveColor,
  resolveUiOptions,
  type Paint,
  type SymbolSet,
} from '../ui/index.js';

/**
 * Composition root for `veripatch verify` (blueprint §6). Ensures a fresh
 * scan, resolves the requested candidate(s), runs each through the Docker
 * sandbox with a live step ticker, and persists run artifacts. Exit code is
 * never 1 — a FAIL confidence verdict is a successful verification, not an
 * error (blueprint §2).
 */
export interface VerifyCommandFlags {
  cwd: string;
  configPath: string | undefined;
  verbose: boolean;
  color: boolean;
  vulnId: string | undefined;
  all: boolean;
  severity: Config['severityThreshold'] | undefined;
  /** --concurrency override for config.verifyConcurrency. */
  concurrency: number | undefined;
}

const LAST_SCAN_FILE_NAME = 'last-scan.json';
const LAST_SCAN_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const SEVERITY_ORDER: Record<ScannedVuln['severity']['label'], number> = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
  CRITICAL: 3,
};

export async function runVerifyCommand(flags: VerifyCommandFlags): Promise<number> {
  const ui = resolveUiOptions(resolveColor(flags.color));
  const paint = createPaint(ui.color);
  const sym = getSymbols(ui.unicode);
  const printError = (message: string): void => {
    process.stderr.write(`${paint(sym.fail, 'danger')} ${message}\n`);
  };

  const configResult = loadConfig({
    cwd: flags.cwd,
    ...(flags.configPath !== undefined ? { configPath: flags.configPath } : {}),
    env: process.env,
    cliFlags: {
      ...(flags.concurrency !== undefined ? { verifyConcurrency: flags.concurrency } : {}),
    },
  });
  if (!configResult.ok) {
    printError(configResult.error.message);
    return errorExitCode(configResult.error);
  }
  const { config } = configResult.value;

  if (!flags.all && flags.vulnId === undefined) {
    printError('Specify a vulnerability id or pass --all.');
    return 2;
  }

  const docker = new Docker();
  try {
    await docker.ping();
  } catch (cause) {
    const dockerError = AppError.world(
      'DOCKER_UNAVAILABLE',
      'Could not reach the Docker daemon',
      'Run `veripatch doctor` to diagnose, or start Docker Desktop / the docker service.',
      cause,
    );
    printError(dockerError.message);
    return errorExitCode(dockerError);
  }

  const cacheResult = AdvisoryCache.open(DEFAULT_CACHE_DIR);
  if (!cacheResult.ok) {
    printError(cacheResult.error.message);
    return errorExitCode(cacheResult.error);
  }
  const cache = cacheResult.value;

  try {
    const detected = detectLockfile(flags.cwd);
    if (detected.packageManager !== null && detected.packageManager !== 'npm') {
      const unsupported = AppError.user(
        'VERIFY_UNSUPPORTED_PACKAGE_MANAGER',
        `This project uses ${detected.packageManager} — the verify sandbox currently replays fixes with npm only.`,
        `\`veripatch scan\` fully supports ${detected.packageManager}; sandbox verification for it is on the roadmap.`,
      );
      printError(unsupported.message);
      return errorExitCode(unsupported);
    }
    const parser = detected.parser;
    const advisorySource = new OsvAdvisorySource({
      client: new OsvClient(),
      cache,
      cacheTtlHours: config.cacheTtlHours,
      logger: createLogger({ verbose: flags.verbose }),
    });

    const scanResult = await ensureFreshScan(flags.cwd, config, parser, advisorySource);
    if (!scanResult.ok) {
      printError(scanResult.error.message);
      return errorExitCode(scanResult.error);
    }
    const output = scanResult.value;

    if (output.scan.degraded) {
      const degradedError = AppError.user(
        'VERIFY_DISABLED_DEGRADED',
        'No lockfile was found — verification requires an exact resolved tree.',
        'Run `npm install` to generate package-lock.json, then re-run scan.',
      );
      printError(degradedError.message);
      return errorExitCode(degradedError);
    }

    const candidates = selectCandidates(output, flags);
    if (candidates.length === 0) {
      printError('No matching, feasible vulnerability found in the last scan.');
      return 2;
    }

    const sandbox = new DockerSandbox(new DockerRuntime({ docker }), parser, advisorySource);
    const reportDir = path.resolve(flags.cwd, config.reportDir);
    let overallExit = 0;

    // With concurrency 1 the per-step ticker streams live. Above that,
    // interleaved tickers would be unreadable, so each candidate's output is
    // buffered and flushed in input order as soon as its turn completes —
    // output stays deterministic regardless of which sandbox finishes first.
    const concurrency = Math.max(1, Math.min(config.verifyConcurrency, candidates.length));
    const live = concurrency === 1;
    const buffers = candidates.map(() => [] as string[]);
    const completed = candidates.map(() => false);
    let flushedUpTo = 0;
    const flushInOrder = (): void => {
      while (flushedUpTo < candidates.length && completed[flushedUpTo] === true) {
        process.stdout.write((buffers[flushedUpTo] ?? []).join(''));
        flushedUpTo++;
      }
    };

    await mapWithConcurrency(candidates, concurrency, async (vuln, index) => {
      const out = (line: string): void => {
        if (live) process.stdout.write(line);
        else buffers[index]?.push(line);
      };
      out(`\n${paint.bold(vuln.id)}  ${vuln.pkg} ${vuln.fix.from} ${sym.arrow} ${vuln.fix.to}\n`);
      const result = await verifyCandidate(
        sandbox,
        {
          projectDir: flags.cwd,
          candidate: vuln.fix,
          config: {
            testCommand: config.testCommand,
            buildCommand: config.buildCommand,
            verifyTimeoutMin: config.verifyTimeoutMin,
            sandboxImage: config.sandboxImage,
          },
        },
        (step) => {
          const icon =
            step.status === 'pass'
              ? paint(sym.pass, 'success')
              : step.status === 'skipped'
                ? paint.dim(sym.pending)
                : paint(sym.fail, 'danger');
          out(`  ${icon} ${step.step}\n`);
        },
      );

      if (!result.ok) {
        printError(result.error.message);
        overallExit = errorExitCode(result.error);
      } else {
        persistRunArtifacts(reportDir, result.value);
        out(renderVerdict(result.value, { paint, sym }));
      }
      completed[index] = true;
      if (!live) flushInOrder();
    });

    return overallExit;
  } finally {
    cache.close();
  }
}

async function ensureFreshScan(
  cwd: string,
  config: Config,
  parser: LockfileParser,
  advisorySource: OsvAdvisorySource,
) {
  const reportDir = path.resolve(cwd, config.reportDir);
  const lastScanPath = path.join(reportDir, LAST_SCAN_FILE_NAME);

  const isFresh =
    fs.existsSync(lastScanPath) &&
    Date.now() - fs.statSync(lastScanPath).mtimeMs <= LAST_SCAN_MAX_AGE_MS;

  if (isFresh) {
    try {
      return {
        ok: true as const,
        value: JSON.parse(fs.readFileSync(lastScanPath, 'utf8')) as ScanOutput,
      };
    } catch {
      // fall through to a fresh scan below
    }
  }

  return runScan(
    { parser, advisorySource },
    {
      projectDir: cwd,
      severityThreshold: config.severityThreshold,
      ignore: config.ignore,
      includeDevDeps: config.includeDevDeps,
    },
  );
}

function severityRankOf(threshold: Config['severityThreshold']): number {
  switch (threshold) {
    case 'low':
      return SEVERITY_ORDER.LOW;
    case 'medium':
      return SEVERITY_ORDER.MEDIUM;
    case 'high':
      return SEVERITY_ORDER.HIGH;
    case 'critical':
      return SEVERITY_ORDER.CRITICAL;
  }
}

function selectCandidates(output: ScanOutput, flags: VerifyCommandFlags): ScannedVuln[] {
  const feasible = output.vulns.filter((v) => v.fix.feasible);
  const vulnId = flags.vulnId;
  if (vulnId !== undefined) {
    return feasible.filter((v) => v.id === vulnId || v.aliases.includes(vulnId));
  }
  const thresholdRank =
    flags.severity !== undefined ? severityRankOf(flags.severity) : SEVERITY_ORDER.LOW;
  return feasible.filter((v) => SEVERITY_ORDER[v.severity.label] >= thresholdRank);
}

/**
 * Explains the verdict rather than just naming it — every word here comes
 * from this specific result's own steps, never a canned message. HIGH/MEDIUM
 * get the plain-language confirmations a reviewer actually wants ("upgrade
 * verified", "tests passed"); anything else names the real failing step so
 * "requires manual review" isn't a dead end.
 */
function renderVerdict(result: VerificationResult, deps: { paint: Paint; sym: SymbolSet }): string {
  const { paint, sym } = deps;
  const ok = result.confidence === 'HIGH' || result.confidence === 'MEDIUM';
  const badge = ok
    ? paint(`${sym.pass} verdict: ${result.confidence}`, 'success')
    : paint(`${sym.warn} verdict: ${result.confidence}`, 'warning');
  const lines = [`  ${badge}\n`];

  if (ok) {
    const explanations = result.steps
      .filter((s) => s.status === 'pass' && ['rescan', 'build', 'test'].includes(s.step))
      .map((s) => `${paint(sym.pass, 'success')} ${explainStep(s.step)}`);
    if (explanations.length > 0) lines.push(`    ${explanations.join('   ')}\n`);
  } else {
    const failing = result.steps.find((s) => s.status === 'fail' || s.status === 'timeout');
    const reason =
      failing !== undefined
        ? `${failing.step} step ${failing.status === 'timeout' ? 'timed out' : 'failed'}`
        : (result.residualRisks[0] ?? 'verification did not confirm the fix');
    lines.push(`    ${paint('⚠', 'warning')} Requires manual review — ${reason}\n`);
  }
  return lines.join('');
}

function persistRunArtifacts(reportDir: string, result: VerificationResult): void {
  const runDir = path.join(reportDir, 'runs', result.runId);
  fs.mkdirSync(runDir, { recursive: true });
  for (const step of result.steps) {
    fs.writeFileSync(path.join(runDir, `${step.step}.log`), step.logTail);
  }
  fs.writeFileSync(path.join(runDir, 'result.json'), JSON.stringify(result, null, 2));
}
