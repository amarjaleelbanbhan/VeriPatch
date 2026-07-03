import type {
  Advisory,
  DepGraph,
  DepNode,
  FixCandidate,
  ScanOutput,
  StepResult,
  VerificationResult,
} from './models/index.js';
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

export interface SandboxConfig {
  testCommand: string;
  buildCommand: string;
  verifyTimeoutMin: number;
  sandboxImage: string;
}

export interface SandboxPlan {
  /** The real project directory — the Sandbox stages its own isolated copy. */
  projectDir: string;
  candidate: FixCandidate;
  config: SandboxConfig;
}

/**
 * Optional per-step callback, invoked as each pipeline step completes.
 * Additive over the blueprint's literal `run(plan): Promise<Result<StepResult[]>>`
 * signature — needed to drive the CLI's live step ticker without changing the
 * documented return shape.
 */
export type StepListener = (step: StepResult) => void;

export interface Sandbox {
  run(plan: SandboxPlan, onStep?: StepListener): Promise<Result<StepResult[]>>;
}

export interface ReportPaths {
  jsonPath: string;
  mdPath: string;
}

export interface Reporter {
  write(results: ScanOutput | VerificationResult, dir: string): Result<ReportPaths>;
}
