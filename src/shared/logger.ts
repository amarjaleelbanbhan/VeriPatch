import os from 'node:os';
import { pino, type Logger, type DestinationStream } from 'pino';

/**
 * Structured logging (blueprint §2):
 * - all logs go to stderr — stdout is reserved for machine output (--json reports)
 * - --verbose lowers the level to debug
 * - never log env vars, tokens, or absolute home paths (home dir → "~")
 */
export type { Logger };

export interface LoggerOptions {
  /** debug level instead of info. */
  verbose?: boolean;
  /** Test seam: capture output instead of writing to stderr. */
  destination?: DestinationStream;
}

const SECRET_KEY_PATTERNS = [
  'token',
  'authorization',
  'password',
  'secret',
  'apiKey',
  'api_key',
  'env',
];

/** Replace the user's home directory with "~" wherever it appears in a string. */
export function redactHomeDir(text: string, homeDir: string = os.homedir()): string {
  if (homeDir.length === 0) return text;
  const variants = new Set([homeDir, homeDir.replaceAll('\\', '/'), homeDir.replaceAll('/', '\\')]);
  let out = text;
  for (const variant of variants) {
    out = out.replaceAll(variant, '~');
  }
  return out;
}

function redactValue(value: unknown): unknown {
  if (typeof value === 'string') return redactHomeDir(value);
  if (Array.isArray(value)) return value.map(redactValue);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = redactValue(v);
    }
    return out;
  }
  return value;
}

export function createLogger(options: LoggerOptions = {}): Logger {
  return pino(
    {
      level: options.verbose ? 'debug' : 'info',
      redact: {
        paths: SECRET_KEY_PATTERNS.flatMap((key) => [key, `*.${key}`]),
        censor: '[redacted]',
      },
      formatters: {
        log: (obj) => redactValue(obj) as Record<string, unknown>,
      },
      hooks: {
        logMethod(args, method) {
          const redacted = args.map((arg) =>
            typeof arg === 'string' ? redactHomeDir(arg) : arg,
          ) as typeof args;
          method.apply(this, redacted);
        },
      },
      base: null, // no pid/hostname noise
    },
    options.destination ?? process.stderr,
  );
}
