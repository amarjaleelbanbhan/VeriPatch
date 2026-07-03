import Docker from 'dockerode';
import { AdvisoryCache, DEFAULT_CACHE_DIR } from '../../adapters/cache/db.js';
import { NpmLockfileParser } from '../../adapters/lockfile/index.js';
import { OsvClient } from '../../adapters/osv/client.js';
import { DockerRuntime } from '../../adapters/sandbox/docker.js';
import { loadConfig } from '../../shared/config.js';

/**
 * `veripatch doctor` (blueprint §6): diagnoses the environment VeriPatch
 * depends on. Each check is independent — one failure doesn't block the
 * rest from running, so the user sees every problem in one pass.
 */
export interface DoctorCheck {
  name: string;
  pass: boolean;
  hint?: string;
}

export interface DoctorCommandFlags {
  cwd: string;
  configPath: string | undefined;
  sandboxImage: string;
}

export async function runDoctorCommand(flags: DoctorCommandFlags): Promise<number> {
  const checks = await runAllChecks(flags);
  process.stdout.write(`${renderChecklist(checks)}\n`);
  return exitCodeFor(checks);
}

/** Pure aggregation, separated from the I/O above so it can be unit-tested with fake checks. */
export function exitCodeFor(checks: DoctorCheck[]): number {
  return checks.every((c) => c.pass) ? 0 : 1;
}

export function renderChecklist(checks: DoctorCheck[]): string {
  return checks
    .map((c) =>
      c.pass ? `✅ ${c.name}` : `❌ ${c.name}${c.hint !== undefined ? `\n   ${c.hint}` : ''}`,
    )
    .join('\n');
}

async function runAllChecks(flags: DoctorCommandFlags): Promise<DoctorCheck[]> {
  return [
    checkNodeVersion(),
    await checkDockerReachable(),
    await checkSandboxImagePullable(flags.sandboxImage),
    checkLockfile(flags.cwd),
    await checkOsvReachable(),
    checkCacheWritable(),
    checkConfigValid(flags),
  ];
}

const MIN_NODE_MAJOR = 20;

function checkNodeVersion(): DoctorCheck {
  const major = Number(process.versions.node.split('.')[0]);
  return {
    name: `Node.js >= ${String(MIN_NODE_MAJOR)} (found ${process.versions.node})`,
    pass: major >= MIN_NODE_MAJOR,
    hint: `Install Node ${String(MIN_NODE_MAJOR)} or newer.`,
  };
}

async function checkDockerReachable(): Promise<DoctorCheck> {
  try {
    await new Docker().ping();
    return { name: 'Docker daemon reachable', pass: true };
  } catch {
    return {
      name: 'Docker daemon reachable',
      pass: false,
      hint: 'Start Docker Desktop / the docker service. `verify` requires it; `scan` does not.',
    };
  }
}

async function checkSandboxImagePullable(image: string): Promise<DoctorCheck> {
  const result = await new DockerRuntime().pullImageIfMissing(image);
  return {
    name: `Sandbox image pullable (${image})`,
    pass: result.ok,
    ...(result.ok ? {} : { hint: result.error.message }),
  };
}

function checkLockfile(cwd: string): DoctorCheck {
  const result = new NpmLockfileParser().parse(cwd);
  if (!result.ok) {
    return { name: 'Lockfile present and parseable', pass: false, hint: result.error.message };
  }
  return {
    name: result.value.degraded
      ? 'Lockfile present (degraded: package.json only, verify disabled)'
      : `Lockfile present (${result.value.packageManager ?? 'unknown'} v${String(result.value.lockfileVersion)})`,
    pass: !result.value.degraded,
    ...(result.value.degraded ? { hint: 'Run `npm install` to generate package-lock.json.' } : {}),
  };
}

async function checkOsvReachable(): Promise<DoctorCheck> {
  const result = await new OsvClient({ timeoutMs: 5000 }).getVuln('GHSA-0000-0000-0000');
  // A real HTTP response (even 404 "not found") proves reachability; only
  // timeouts/connection failures mean OSV.dev itself is unreachable.
  const reachable =
    result.ok || (result.error.code !== 'OSV_TIMEOUT' && result.error.code !== 'OSV_UNREACHABLE');
  return {
    name: 'OSV.dev reachable',
    pass: reachable,
    ...(reachable
      ? {}
      : { hint: 'Check network connectivity; scan can still use cached advisories offline.' }),
  };
}

function checkCacheWritable(): DoctorCheck {
  const result = AdvisoryCache.open(DEFAULT_CACHE_DIR);
  if (result.ok) result.value.close();
  return {
    name: `Advisory cache writable (${DEFAULT_CACHE_DIR})`,
    pass: result.ok,
    ...(result.ok ? {} : { hint: result.error.message }),
  };
}

function checkConfigValid(flags: DoctorCommandFlags): DoctorCheck {
  const result = loadConfig({
    cwd: flags.cwd,
    ...(flags.configPath !== undefined ? { configPath: flags.configPath } : {}),
    env: process.env,
  });
  return {
    name: 'Configuration valid',
    pass: result.ok,
    ...(result.ok ? {} : { hint: result.error.message }),
  };
}
