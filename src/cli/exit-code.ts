import type { AppError } from '../shared/errors.js';

/**
 * Single 0/1/2 exit-code mapping (blueprint §2/§6) — every command routes
 * through here rather than deciding its own exit codes ad hoc.
 *
 * scan:   0 clean, 1 vulns found, 2 tool/user error
 * verify: 0 verification completed (any verdict), 2 environment/tool error, never 1
 * others: 0 success, 2 error (doctor is the one exception: 1 = any check failed)
 */
export type ExitCode = 0 | 1 | 2;

export interface ScanExitInput {
  /** --ci mode counts only new-vs-baseline vulns; plain mode counts all ranked vulns. */
  ci: boolean;
  newVulnCount: number;
  totalVulnCount: number;
}

export function scanExitCode(input: ScanExitInput): ExitCode {
  const count = input.ci ? input.newVulnCount : input.totalVulnCount;
  return count > 0 ? 1 : 0;
}

/** Every AppError kind maps to 2 — UserError/WorldError/InternalError all halt the command. */
export function errorExitCode(error: AppError): ExitCode {
  switch (error.kind) {
    case 'UserError':
    case 'WorldError':
    case 'InternalError':
      return 2;
  }
}
