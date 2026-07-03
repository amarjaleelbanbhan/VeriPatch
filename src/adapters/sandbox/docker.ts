import { PassThrough } from 'node:stream';
import Docker from 'dockerode';
import { AppError } from '../../shared/errors.js';
import { err, ok, type Result } from '../../shared/result.js';

/**
 * Hardened container lifecycle (blueprint §9): non-root, all capabilities
 * dropped, no-new-privileges, pid/memory/cpu-limited, project copy bind-
 * mounted (never the original tree), auto-removed on teardown.
 */
const MEMORY_LIMIT_BYTES = 2 * 1024 * 1024 * 1024; // 2G
const CPU_LIMIT_NANOS = 2_000_000_000; // 2 CPUs
const PIDS_LIMIT = 512;
const CONTAINER_USER = '1000:1000'; // non-root
const WORKSPACE_DIR = '/workspace';

/**
 * Pure assembly of the hardened container-create options — extracted so the
 * hardening flags (blueprint §9) can be asserted directly in a unit test
 * without a running Docker daemon, and mirrored by the security e2e's live
 * `inspect()` assertions in CI.
 */
export function buildContainerCreateOptions(
  image: string,
  stagingDir: string,
  networkMode: string,
): Docker.ContainerCreateOptions {
  return {
    Image: image,
    Cmd: ['sleep', 'infinity'],
    User: CONTAINER_USER,
    WorkingDir: WORKSPACE_DIR,
    HostConfig: {
      Binds: [`${stagingDir}:${WORKSPACE_DIR}`],
      NetworkMode: networkMode,
      CapDrop: ['ALL'],
      SecurityOpt: ['no-new-privileges'],
      PidsLimit: PIDS_LIMIT,
      Memory: MEMORY_LIMIT_BYTES,
      NanoCpus: CPU_LIMIT_NANOS,
      AutoRemove: false,
    },
  };
}

export interface ExecOutcome {
  exitCode: number;
  output: string;
  timedOut: boolean;
  durationMs: number;
}

/** Structural container handle — lets orchestration/tests depend on this instead of dockerode directly. */
export interface ContainerHandle {
  readonly id: string;
  exec(cmd: string[], timeoutMs: number): Promise<ExecOutcome>;
  teardown(): Promise<void>;
}

/** Structural network handle, matching the slice of Docker.Network the orchestrator actually uses. */
export interface NetworkHandle {
  readonly id: string;
  disconnect(options: { Container: string; Force: boolean }): Promise<unknown>;
  remove(): Promise<unknown>;
}

/**
 * Everything DockerSandbox needs from a Docker connection. DockerRuntime
 * below satisfies this structurally — no explicit `implements` required —
 * which lets tests substitute an in-memory fake without touching dockerode.
 */
export interface SandboxRuntime {
  pullImageIfMissing(image: string): Promise<Result<void>>;
  createHardenedContainer(
    image: string,
    stagingDir: string,
    networkMode: string,
  ): Promise<Result<ContainerHandle>>;
  createIsolatedNetwork(name: string): Promise<Result<NetworkHandle>>;
}

export class HardenedContainer implements ContainerHandle {
  constructor(
    private readonly container: Docker.Container,
    private readonly docker: Docker,
  ) {}

  get id(): string {
    return this.container.id;
  }

  async exec(cmd: string[], timeoutMs: number): Promise<ExecOutcome> {
    const start = performance.now();
    const exec = await this.container.exec({
      Cmd: cmd,
      AttachStdout: true,
      AttachStderr: true,
      WorkingDir: WORKSPACE_DIR,
    });
    const stream = await exec.start({ hijack: true, stdin: false });

    const chunks: Buffer[] = [];
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
    stderr.on('data', (chunk: Buffer) => chunks.push(chunk));
    (
      this.docker.modem as { demuxStream: (s: unknown, o: unknown, e: unknown) => void }
    ).demuxStream(stream, stdout, stderr);

    const streamEnded = new Promise<void>((resolve) => {
      stream.on('end', resolve);
      stream.on('close', resolve);
    });
    const timedOut = await raceTimeout(streamEnded, timeoutMs);

    if (timedOut) {
      await this.container.kill().catch(() => undefined);
      return {
        exitCode: -1,
        output: Buffer.concat(chunks).toString('utf8'),
        timedOut: true,
        durationMs: performance.now() - start,
      };
    }

    const inspected = await exec.inspect();
    return {
      exitCode: inspected.ExitCode ?? -1,
      output: Buffer.concat(chunks).toString('utf8'),
      timedOut: false,
      durationMs: performance.now() - start,
    };
  }

  async teardown(): Promise<void> {
    await this.container.remove({ force: true }).catch(() => undefined);
  }
}

function raceTimeout(promise: Promise<void>, timeoutMs: number): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => {
      resolve(true);
    }, timeoutMs);
    void promise.then(() => {
      clearTimeout(timer);
      resolve(false);
    });
  });
}

export interface DockerRuntimeOptions {
  docker?: Docker;
}

export class DockerRuntime {
  private readonly docker: Docker;

  constructor(options: DockerRuntimeOptions = {}) {
    this.docker = options.docker ?? new Docker();
  }

  async pullImageIfMissing(image: string): Promise<Result<void>> {
    try {
      await this.docker.getImage(image).inspect();
      return ok(undefined);
    } catch {
      // not present locally — fall through and pull it
    }
    try {
      await new Promise<void>((resolve, reject) => {
        this.docker.pull(image, {}, (pullErr?: Error, stream?: NodeJS.ReadableStream) => {
          if (pullErr || stream === undefined) {
            reject(pullErr ?? new Error('docker pull returned no stream'));
            return;
          }
          this.docker.modem.followProgress(stream, (progressErr: Error | null) => {
            if (progressErr) reject(progressErr);
            else resolve();
          });
        });
      });
      return ok(undefined);
    } catch (cause) {
      return err(
        AppError.world(
          'SANDBOX_IMAGE_PULL_FAILED',
          `Could not pull sandbox image ${image}`,
          'Check network connectivity and that the image name is correct.',
          cause,
        ),
      );
    }
  }

  /** networkMode: a dedicated bridge network name (install phase) or "none". */
  async createHardenedContainer(
    image: string,
    stagingDir: string,
    networkMode: string,
  ): Promise<Result<HardenedContainer>> {
    try {
      const container = await this.docker.createContainer(
        buildContainerCreateOptions(image, stagingDir, networkMode),
      );
      await container.start();
      return ok(new HardenedContainer(container, this.docker));
    } catch (cause) {
      return err(
        AppError.world(
          'SANDBOX_CONTAINER_FAILED',
          'Could not start the verification sandbox container',
          'Run `veripatch doctor` to check Docker connectivity.',
          cause,
        ),
      );
    }
  }

  async createIsolatedNetwork(name: string): Promise<Result<Docker.Network>> {
    try {
      const network = await this.docker.createNetwork({ Name: name, Driver: 'bridge' });
      return ok(network);
    } catch (cause) {
      return err(
        AppError.world(
          'SANDBOX_NETWORK_FAILED',
          'Could not create the install-phase network',
          undefined,
          cause,
        ),
      );
    }
  }
}
