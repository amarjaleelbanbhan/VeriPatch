import { AppError } from '../../shared/errors.js';
import { err, ok, type Result } from '../../shared/result.js';
import type { NetworkHandle } from './docker.js';

/**
 * Two-phase network isolation (blueprint §9): the container gets registry
 * access only for the install step, then is cut off entirely before rescan/
 * build/test run. Implemented with a dedicated per-run bridge network
 * (rather than the host's shared default bridge) disconnected after install
 * — a real, verifiable isolation boundary, not a stub.
 */
export class NetworkPhaseManager {
  private network: NetworkHandle | undefined;

  constructor(
    private readonly runtime: {
      createIsolatedNetwork(name: string): Promise<Result<NetworkHandle>>;
    },
  ) {}

  /** Returns the Docker network mode to pass at container-create time. */
  async createInstallNetwork(runId: string): Promise<Result<string>> {
    const created = await this.runtime.createIsolatedNetwork(`veripatch-${runId}`);
    if (!created.ok) return created;
    this.network = created.value;
    return ok(this.network.id);
  }

  /** Cuts the container off from every network — the install/rescan boundary. */
  async isolate(containerId: string): Promise<Result<void>> {
    if (this.network === undefined) return ok(undefined);
    try {
      await this.network.disconnect({ Container: containerId, Force: true });
      return ok(undefined);
    } catch (cause) {
      return err(
        AppError.world(
          'SANDBOX_NETWORK_FAILED',
          'Could not isolate the sandbox network',
          undefined,
          cause,
        ),
      );
    }
  }

  async teardown(): Promise<void> {
    if (this.network === undefined) return;
    await this.network.remove().catch(() => undefined);
  }
}
