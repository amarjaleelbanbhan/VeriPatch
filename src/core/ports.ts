import type { Advisory, DepGraph, DepNode } from './models/index.js';
import type { Result } from '../shared/result.js';

/**
 * Ports (blueprint §5.3): core-defined interfaces that adapters implement.
 * Every implementation must pass the shared behavioral suite in tests/contract/.
 */

export interface LockfileParser {
  parse(projectDir: string): Result<DepGraph>;
}

export interface AdvisoryLookup {
  advisories: Advisory[];
  /** True when served from an expired cache because the network was unavailable. */
  stale: boolean;
  /** Advisories dropped due to schema validation failures (counted, never silently). */
  dataErrors: number;
}

export interface AdvisorySource {
  getAdvisories(nodes: DepNode[]): Promise<Result<AdvisoryLookup>>;
}

// Sandbox and Reporter ports land with M6/M7 alongside their domain types.
