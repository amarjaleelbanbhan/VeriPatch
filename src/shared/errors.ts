/**
 * Unified error model (blueprint §2).
 *
 * - UserError:     caller did something fixable (bad config, missing lockfile) → exit 2 + hint.
 * - WorldError:    the environment failed us (network, Docker down) → degrade honestly or exit 2.
 * - InternalError: a VeriPatch bug — should never surface in a healthy build.
 *
 * A verification FAIL verdict is NOT an error; it is a first-class result.
 */
export type ErrorKind = 'UserError' | 'WorldError' | 'InternalError';

export class AppError extends Error {
  override readonly name = 'AppError';

  private constructor(
    readonly kind: ErrorKind,
    readonly code: string,
    message: string,
    readonly hint?: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
  }

  static user(code: string, message: string, hint?: string, cause?: unknown): AppError {
    return new AppError('UserError', code, message, hint, { cause });
  }

  static world(code: string, message: string, hint?: string, cause?: unknown): AppError {
    return new AppError('WorldError', code, message, hint, { cause });
  }

  static internal(code: string, message: string, cause?: unknown): AppError {
    return new AppError('InternalError', code, message, undefined, { cause });
  }
}
