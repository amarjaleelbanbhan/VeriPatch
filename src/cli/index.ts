import { pathToFileURL } from 'node:url';
import { Command } from 'commander';
import { runScanCommand } from './commands/scan.js';
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

  return program;
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
