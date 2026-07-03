import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DockerSandbox } from '../../../../src/adapters/sandbox/index.js';
import type {
  ContainerHandle,
  ExecOutcome,
  NetworkHandle,
  SandboxRuntime,
} from '../../../../src/adapters/sandbox/docker.js';
import type {
  DepGraph,
  DepNode,
  FixCandidate,
  StepName,
} from '../../../../src/core/models/index.js';
import type { AdvisorySource, LockfileParser } from '../../../../src/core/ports.js';
import { ok, type Result } from '../../../../src/shared/result.js';

/**
 * End-to-end DockerSandbox orchestration test with a fully in-memory
 * SandboxRuntime — proves the step sequence, network-phase transition, and
 * early-exit-on-failure behavior without a real Docker daemon. Structural
 * typing (SandboxRuntime/ContainerHandle/NetworkHandle) is what makes this
 * possible: the real DockerRuntime satisfies the same interfaces.
 */
function candidate(): FixCandidate {
  return {
    vulnId: 'GHSA-1',
    pkg: 'axios',
    from: '1.5.0',
    to: '1.6.0',
    bumpType: 'minor',
    strategy: 'direct',
    feasible: true,
  };
}

function node(name: string, version: string): DepNode {
  return { name, version, paths: [['root', name]], dev: false, direct: true };
}

function pass(output = ''): ExecOutcome {
  return { exitCode: 0, output, timedOut: false, durationMs: 1 };
}
function fail(): ExecOutcome {
  return { exitCode: 1, output: 'boom', timedOut: false, durationMs: 1 };
}

interface FakeRuntimeOptions {
  /** cmd[0] identity ('npm', 'sh') -> scripted outcome; defaults to pass(). */
  outcomes?: Record<string, ExecOutcome>;
  networkDisconnects?: string[];
}

function fakeRuntime(options: FakeRuntimeOptions = {}): {
  runtime: SandboxRuntime;
  calls: string[][];
} {
  const calls: string[][] = [];
  const disconnects = options.networkDisconnects ?? [];

  const container: ContainerHandle = {
    id: 'container-1',
    exec: (cmd) => {
      calls.push(cmd);
      const key = cmd.join(' ');
      return Promise.resolve(options.outcomes?.[key] ?? options.outcomes?.[cmd[0] ?? ''] ?? pass());
    },
    teardown: () => Promise.resolve(),
  };

  const network: NetworkHandle = {
    id: 'net-1',
    disconnect: (opts) => {
      disconnects.push(opts.Container);
      return Promise.resolve(undefined);
    },
    remove: () => Promise.resolve(undefined),
  };

  const runtime: SandboxRuntime = {
    pullImageIfMissing: () => Promise.resolve(ok(undefined)),
    createHardenedContainer: () => Promise.resolve(ok(container)),
    createIsolatedNetwork: () => Promise.resolve(ok(network)),
  };

  return { runtime, calls };
}

function passingParser(): LockfileParser {
  const graph: DepGraph = {
    nodes: [node('axios', '1.6.0')],
    lockfileVersion: 3,
    packageManager: 'npm',
    degraded: false,
  };
  return { parse: () => ok(graph) };
}

function fakeAdvisorySource(): AdvisorySource {
  return {
    getAdvisories: () =>
      Promise.resolve(
        ok({
          advisories: [
            {
              id: 'GHSA-1',
              aliases: [],
              summary: 's',
              severity: { cvss: 7.5, label: 'HIGH' as const },
              affected: [{ pkg: 'axios', ranges: ['<1.6.0'], fixed: '1.6.0' }],
              references: [],
              modified: '2026-01-01T00:00:00Z',
            },
          ],
          stale: false,
          dataErrors: 0,
        }),
      ),
  };
}

const config = {
  testCommand: 'npm test',
  buildCommand: 'npm run build',
  verifyTimeoutMin: 10,
  sandboxImage: 'node:20-slim',
};

let projectDir: string;

beforeEach(() => {
  projectDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veripatch-orchestration-'));
  fs.writeFileSync(path.join(projectDir, 'package.json'), '{"name":"fixture"}');
});

afterEach(() => {
  fs.rmSync(projectDir, { recursive: true, force: true });
});

describe('DockerSandbox — happy path', () => {
  it('runs every step in order and reaches a passing test', async () => {
    const { runtime } = fakeRuntime({
      outcomes: { 'sh -c npm test': pass('Tests  1 passed (1)') },
    });
    const sandbox = new DockerSandbox(runtime, passingParser(), fakeAdvisorySource());
    const seen: StepName[] = [];

    const result = await sandbox.run({ projectDir, candidate: candidate(), config }, (step) =>
      seen.push(step.step),
    );

    if (!result.ok) throw result.error;
    expect(seen).toEqual(['copy', 'apply', 'install', 'rescan', 'build', 'test']);
    expect(result.value.every((s) => s.status === 'pass')).toBe(true);
    const test = result.value.find((s) => s.step === 'test');
    expect(test?.testCounts).toEqual({ passed: 1, failed: 0, total: 1 });
  });

  it('isolates the container network between install and build', async () => {
    const disconnects: string[] = [];
    const { runtime } = fakeRuntime({ networkDisconnects: disconnects });
    const sandbox = new DockerSandbox(runtime, passingParser(), fakeAdvisorySource());

    const result = await sandbox.run({ projectDir, candidate: candidate(), config });
    if (!result.ok) throw result.error;
    expect(disconnects).toEqual(['container-1']);
  });

  it('reopens staged-file permissions from inside the container before teardown', async () => {
    const { runtime, calls } = fakeRuntime();
    const sandbox = new DockerSandbox(runtime, passingParser(), fakeAdvisorySource());

    const result = await sandbox.run({ projectDir, candidate: candidate(), config });
    if (!result.ok) throw result.error;
    // Anything npm creates inside the bind-mounted staging dir is owned by
    // the container's uid, which the host can't always delete afterward
    // (blueprint §9 non-root hardening + Docker's lack of uid remapping) --
    // this chmod is what makes host-side cleanup possible regardless.
    expect(calls.at(-1)).toEqual(['chmod', '-R', 'a+rwX', '/workspace']);
  });

  it('does not fail the run when the permission-reopen chmod itself fails', async () => {
    const container: ContainerHandle = {
      id: 'container-1',
      exec: (cmd) => {
        if (cmd[0] === 'chmod') return Promise.reject(new Error('container already gone'));
        return Promise.resolve(pass());
      },
      teardown: () => Promise.resolve(),
    };
    const runtime: SandboxRuntime = {
      pullImageIfMissing: () => Promise.resolve(ok(undefined)),
      createHardenedContainer: () => Promise.resolve(ok(container)),
      createIsolatedNetwork: () =>
        Promise.resolve(
          ok({
            id: 'net-1',
            disconnect: () => Promise.resolve(undefined),
            remove: () => Promise.resolve(undefined),
          }),
        ),
    };
    const sandbox = new DockerSandbox(runtime, passingParser(), fakeAdvisorySource());

    const result = await sandbox.run({ projectDir, candidate: candidate(), config });
    expect(result.ok).toBe(true);
  });
});

describe('DockerSandbox — early exit on gating failures', () => {
  it('stops after a failing apply and marks the rest skipped', async () => {
    const { runtime, calls } = fakeRuntime({ outcomes: { npm: fail() } });
    const sandbox = new DockerSandbox(runtime, passingParser(), fakeAdvisorySource());

    const result = await sandbox.run({ projectDir, candidate: candidate(), config });
    if (!result.ok) throw result.error;

    const byStep = Object.fromEntries(result.value.map((s) => [s.step, s.status])) as Record<
      StepName,
      string
    >;
    expect(byStep).toEqual({
      copy: 'pass',
      apply: 'fail',
      install: 'skipped',
      rescan: 'skipped',
      build: 'skipped',
      test: 'skipped',
    });
    // only apply and the final cleanup chmod ran — install/build/test never touched the container
    expect(calls).toEqual([
      ['npm', 'install', 'axios@1.6.0', '--package-lock-only'],
      ['chmod', '-R', 'a+rwX', '/workspace'],
    ]);
  });

  it('stops after a failing install and marks rescan/build/test skipped', async () => {
    const { runtime } = fakeRuntime({
      outcomes: {
        'npm install axios@1.6.0 --package-lock-only': pass(),
        'npm ci --ignore-scripts': fail(),
      },
    });
    const sandbox = new DockerSandbox(runtime, passingParser(), fakeAdvisorySource());

    const result = await sandbox.run({ projectDir, candidate: candidate(), config });
    if (!result.ok) throw result.error;
    const byStep = Object.fromEntries(result.value.map((s) => [s.step, s.status])) as Record<
      StepName,
      string
    >;
    expect(byStep.install).toBe('fail');
    expect(byStep.rescan).toBe('skipped');
    expect(byStep.build).toBe('skipped');
    expect(byStep.test).toBe('skipped');
  });

  it('stops after an ineffective rescan (vuln still present) and skips build/test', async () => {
    const stillVulnerableGraph: DepGraph = {
      nodes: [node('axios', '1.5.5')],
      lockfileVersion: 3,
      packageManager: 'npm',
      degraded: false,
    };
    const { runtime } = fakeRuntime();
    const sandbox = new DockerSandbox(
      runtime,
      { parse: () => ok(stillVulnerableGraph) },
      fakeAdvisorySource(),
    );

    const result = await sandbox.run({ projectDir, candidate: candidate(), config });
    if (!result.ok) throw result.error;
    const byStep = Object.fromEntries(result.value.map((s) => [s.step, s.status])) as Record<
      StepName,
      string
    >;
    expect(byStep.rescan).toBe('fail');
    expect(byStep.build).toBe('skipped');
    expect(byStep.test).toBe('skipped');
  });

  it('stops after a failing build and skips test', async () => {
    const { runtime } = fakeRuntime({ outcomes: { 'sh -c npm run build': fail() } });
    const sandbox = new DockerSandbox(runtime, passingParser(), fakeAdvisorySource());

    const result = await sandbox.run({ projectDir, candidate: candidate(), config });
    if (!result.ok) throw result.error;
    const byStep = Object.fromEntries(result.value.map((s) => [s.step, s.status])) as Record<
      StepName,
      string
    >;
    expect(byStep.build).toBe('fail');
    expect(byStep.test).toBe('skipped');
  });
});

describe('DockerSandbox — infrastructure failures', () => {
  it('propagates a container-creation failure as a Result error, not a throw', async () => {
    const runtime: SandboxRuntime = {
      pullImageIfMissing: () => Promise.resolve(ok(undefined)),
      createHardenedContainer: () =>
        Promise.resolve({
          ok: false,
          error: Object.assign(new Error('no docker'), {
            kind: 'WorldError',
            code: 'SANDBOX_CONTAINER_FAILED',
          }),
        } as Result<ContainerHandle>),
      createIsolatedNetwork: () =>
        Promise.resolve(
          ok({
            id: 'n',
            disconnect: () => Promise.resolve(undefined),
            remove: () => Promise.resolve(undefined),
          }),
        ),
    };
    const sandbox = new DockerSandbox(runtime, passingParser(), fakeAdvisorySource());
    const result = await sandbox.run({ projectDir, candidate: candidate(), config });
    expect(result.ok).toBe(false);
  });
});
