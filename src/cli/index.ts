import { pathToFileURL } from 'node:url';
import { Command } from 'commander';
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
    .action(async function (this: Command, vulnId: string | undefined) {
      const globalOpts = this.parent?.opts<{
        verbose?: boolean;
        config?: string;
        color: boolean;
        cwd: string;
      }>();
      const localOpts = this.opts<{ all?: boolean; severity?: string }>();

      const exitCode = await runVerifyCommand({
        cwd: globalOpts?.cwd ?? process.cwd(),
        configPath: globalOpts?.config,
        verbose: globalOpts?.verbose ?? false,
        color: globalOpts?.color ?? true,
        vulnId,
        all: localOpts.all ?? false,
        severity: isSeverityLevel(localOpts.severity) ? localOpts.severity : undefined,
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

const isMainModule =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMainModule) {
  await main();
}
