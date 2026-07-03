import { Command } from 'commander';
import {
  runBaselineAddCommand,
  runBaselineListCommand,
  runBaselinePruneCommand,
  runBaselineRemoveCommand,
} from './commands/baseline.js';
import { runCacheClearCommand, runCacheStatsCommand } from './commands/cache.js';
import { runDoctorCommand } from './commands/doctor.js';
import { runReportCommand } from './commands/report.js';
import { runScanCommand } from './commands/scan.js';
import { runUpdateCommand } from './commands/update.js';
import { runVerifyCommand } from './commands/verify.js';
import { loadConfig } from '../shared/config.js';
import { VERIPATCH_VERSION } from '../shared/version.js';

/**
 * VeriPatch CLI entry point.
 *
 * Layering rule (eslint-enforced): cli → services → core ← adapters.
 * This layer owns argument parsing, rendering, and exit codes only.
 */
export function buildProgram(): Command {
  const program = new Command();
  program
    .name('veripatch')
    .description('Verified remediation for npm vulnerabilities.')
    .version(VERIPATCH_VERSION)
    .option('--json', 'machine-readable output on stdout')
    .option('--verbose', 'debug-level logging')
    .option('--config <path>', 'path to a .veripatchrc file')
    .option('--no-color', 'disable colored output')
    .option('--cwd <dir>', 'project directory to operate in', process.cwd());

  program
    .command('scan')
    .description('Scan the project for known vulnerabilities.')
    .option(
      '--ci',
      'exit 1 only for vulnerabilities new relative to baseline.json (or any, if absent)',
    )
    .option('--dev', 'include devDependencies')
    .option('--no-dev', 'exclude devDependencies')
    .option('--severity <level>', 'minimum severity to report (low|medium|high|critical)')
    .option(
      '--write-baseline',
      'accept every vulnerability found in this scan as pre-existing debt (writes baseline.json)',
    )
    .action(async function (this: Command) {
      const globalOpts = this.parent?.opts<{
        json?: boolean;
        verbose?: boolean;
        config?: string;
        color: boolean;
        cwd: string;
      }>();
      const localOpts = this.opts<{
        ci?: boolean;
        severity?: string;
        writeBaseline?: boolean;
      }>();
      const devSource = this.getOptionValueSource('dev');

      const exitCode = await runScanCommand({
        cwd: globalOpts?.cwd ?? process.cwd(),
        configPath: globalOpts?.config,
        json: globalOpts?.json ?? false,
        verbose: globalOpts?.verbose ?? false,
        color: globalOpts?.color ?? true,
        ci: localOpts.ci ?? false,
        dev: devSource === 'cli' ? Boolean(this.opts<{ dev?: boolean }>().dev) : undefined,
        severity: isSeverityLevel(localOpts.severity) ? localOpts.severity : undefined,
        writeBaseline: localOpts.writeBaseline ?? false,
      });
      process.exitCode = exitCode;
    });

  program
    .command('verify [vulnId]')
    .description('Prove a fix is safe in a hardened Docker sandbox.')
    .option('--all', 'verify every feasible vulnerability from the last scan')
    .option(
      '--severity <level>',
      'minimum severity to verify with --all (low|medium|high|critical)',
    )
    .option(
      '--concurrency <n>',
      'sandbox verifications to run in parallel with --all (1-8)',
      (raw: string) => Number.parseInt(raw, 10),
    )
    .action(async function (this: Command, vulnId: string | undefined) {
      const globalOpts = this.parent?.opts<{
        verbose?: boolean;
        config?: string;
        color: boolean;
        cwd: string;
      }>();
      const localOpts = this.opts<{ all?: boolean; severity?: string; concurrency?: number }>();

      const exitCode = await runVerifyCommand({
        cwd: globalOpts?.cwd ?? process.cwd(),
        configPath: globalOpts?.config,
        verbose: globalOpts?.verbose ?? false,
        color: globalOpts?.color ?? true,
        vulnId,
        all: localOpts.all ?? false,
        severity: isSeverityLevel(localOpts.severity) ? localOpts.severity : undefined,
        concurrency: localOpts.concurrency,
      });
      process.exitCode = exitCode;
    });

  program
    .command('report [vulnId]')
    .description('Re-render an evidence report from stored run artifacts.')
    .option('--format <format>', 'md|json|pr-comment', 'md')
    .action(function (this: Command, vulnId: string | undefined) {
      const globalOpts = this.parent?.opts<{ config?: string; cwd: string }>();
      const localOpts = this.opts<{ format?: string }>();

      const exitCode = runReportCommand({
        cwd: globalOpts?.cwd ?? process.cwd(),
        configPath: globalOpts?.config,
        vulnId,
        format: isReportFormat(localOpts.format) ? localOpts.format : 'md',
      });
      process.exitCode = exitCode;
    });

  program
    .command('update <vulnId>')
    .description('Apply a verified fix to the working tree.')
    .option('--force', 'apply even without a HIGH/MEDIUM verification confidence')
    .option('--allow-dirty', 'apply even with uncommitted changes in the working tree')
    .action(function (this: Command, vulnId: string) {
      const globalOpts = this.parent?.opts<{ config?: string; cwd: string }>();
      const localOpts = this.opts<{ force?: boolean; allowDirty?: boolean }>();

      const exitCode = runUpdateCommand({
        cwd: globalOpts?.cwd ?? process.cwd(),
        configPath: globalOpts?.config,
        vulnId,
        force: localOpts.force ?? false,
        allowDirty: localOpts.allowDirty ?? false,
      });
      process.exitCode = exitCode;
    });

  program
    .command('doctor')
    .description('Diagnose the environment VeriPatch depends on.')
    .action(async function (this: Command) {
      const globalOpts = this.parent?.opts<{ config?: string; cwd: string }>();
      const cwd = globalOpts?.cwd ?? process.cwd();
      const configResult = loadConfig({
        cwd,
        ...(globalOpts?.config !== undefined ? { configPath: globalOpts.config } : {}),
        env: process.env,
      });
      const sandboxImage = configResult.ok
        ? configResult.value.config.sandboxImage
        : 'node:20-slim';

      const exitCode = await runDoctorCommand({
        cwd,
        configPath: globalOpts?.config,
        sandboxImage,
      });
      process.exitCode = exitCode;
    });

  const baselineCommand = program
    .command('baseline')
    .description('Manage accepted pre-existing debt (baseline.json).');
  const baselineGlobals = (cmd: Command) => {
    const globalOpts = cmd.parent?.parent?.opts<{ config?: string; cwd: string }>();
    return {
      cwd: globalOpts?.cwd ?? process.cwd(),
      configPath: globalOpts?.config,
    };
  };
  baselineCommand
    .command('list')
    .description('Show every baselined vuln with its reason, age, and expiry.')
    .action(function (this: Command) {
      process.exitCode = runBaselineListCommand(baselineGlobals(this));
    });
  baselineCommand
    .command('add <vulnId>')
    .description('Accept one finding from the last scan as debt.')
    .option('--reason <text>', 'why this debt is acceptable (stored in baseline.json)')
    .option(
      '--expires-days <n>',
      'days until the acceptance expires and the vuln counts as new again',
      (raw: string) => Number.parseInt(raw, 10),
    )
    .action(function (this: Command, vulnId: string) {
      const localOpts = this.opts<{ reason?: string; expiresDays?: number }>();
      process.exitCode = runBaselineAddCommand({
        ...baselineGlobals(this),
        vulnId,
        reason: localOpts.reason,
        expiresDays:
          localOpts.expiresDays !== undefined && Number.isFinite(localOpts.expiresDays)
            ? localOpts.expiresDays
            : undefined,
      });
    });
  baselineCommand
    .command('remove <vulnId>')
    .description('Stop accepting a vuln as debt.')
    .action(function (this: Command, vulnId: string) {
      process.exitCode = runBaselineRemoveCommand({ ...baselineGlobals(this), vulnId });
    });
  baselineCommand
    .command('prune')
    .description('Drop baseline entries whose vulns no longer appear in the last scan.')
    .action(function (this: Command) {
      process.exitCode = runBaselinePruneCommand(baselineGlobals(this));
    });

  const cacheCommand = program.command('cache').description('Manage the local advisory cache.');
  cacheCommand
    .command('clear')
    .description('Delete all cached advisory data.')
    .action(() => {
      process.exitCode = runCacheClearCommand();
    });
  cacheCommand
    .command('stats')
    .description('Show cache row counts, size, and staleness.')
    .action(() => {
      process.exitCode = runCacheStatsCommand();
    });

  return program;
}

function isReportFormat(value: string | undefined): value is 'md' | 'json' | 'pr-comment' {
  return value === 'md' || value === 'json' || value === 'pr-comment';
}

function isSeverityLevel(
  value: string | undefined,
): value is 'low' | 'medium' | 'high' | 'critical' {
  return value === 'low' || value === 'medium' || value === 'high' || value === 'critical';
}

export async function main(argv: string[] = process.argv): Promise<void> {
  await buildProgram().parseAsync(argv);
}

// This file is bundled to dist/cli.js and is exclusively the package's `bin`
// entrypoint (package.json) -- never imported as a library -- so it always
// runs main() unconditionally. An earlier "only run if this is the main
// module" guard compared import.meta.url (which resolves symlinks) against
// process.argv[1] (the invoked path); npm's global installs symlink the bin
// entry on Linux/macOS, so those two values diverge there and the guard
// silently skipped main() entirely -- the CLI would exit 0 having done
// nothing, on every Linux/macOS global install.
await main();
