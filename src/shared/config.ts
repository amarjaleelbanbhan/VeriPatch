import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import { AppError } from './errors.js';
import { err, ok, type Result } from './result.js';

/**
 * Runtime configuration (blueprint §2).
 * Precedence: defaults < .veripatchrc < env VERIPATCH_* < CLI flags.
 */
export const ConfigSchema = z.object({
  severityThreshold: z.enum(['low', 'medium', 'high', 'critical']),
  ignore: z.array(z.string()),
  includeDevDeps: z.boolean(),
  testCommand: z.string().min(1),
  buildCommand: z.string().min(1),
  verifyTimeoutMin: z
    .number()
    .int()
    .positive()
    .max(24 * 60),
  sandboxImage: z.string().min(1),
  cacheTtlHours: z
    .number()
    .positive()
    .max(24 * 365),
  reportDir: z.string().min(1),
});
export type Config = z.infer<typeof ConfigSchema>;

export const DEFAULT_CONFIG: Config = {
  severityThreshold: 'low',
  ignore: [],
  includeDevDeps: true,
  testCommand: 'npm test',
  buildCommand: 'npm run build',
  verifyTimeoutMin: 10,
  sandboxImage: 'node:20-slim',
  cacheTtlHours: 24,
  reportDir: '.veripatch',
};

export const RC_FILE_NAME = '.veripatchrc';
const RC_FILE_MAX_BYTES = 1024 * 1024; // a config file has no business being >1MB

const CONFIG_KEYS = Object.keys(ConfigSchema.shape) as (keyof Config)[];

export interface LoadConfigInput {
  cwd: string;
  /** Explicit --config path; when set, a missing file is a UserError instead of a fallback. */
  configPath?: string;
  env?: NodeJS.ProcessEnv;
  cliFlags?: Partial<Config>;
}

export interface LoadedConfig {
  config: Config;
  /** Non-fatal issues (unknown rc keys) — caller decides how to surface them. */
  warnings: string[];
  /** Where the rc file was read from, if any. */
  rcPath?: string;
}

export function loadConfig(input: LoadConfigInput): Result<LoadedConfig> {
  const warnings: string[] = [];

  const rcResult = readRcFile(input, warnings);
  if (!rcResult.ok) return rcResult;
  const { values: rcValues, rcPath } = rcResult.value;

  const envResult = readEnvOverrides(input.env ?? {});
  if (!envResult.ok) return envResult;

  const merged = {
    ...DEFAULT_CONFIG,
    ...rcValues,
    ...envResult.value,
    ...stripUndefined(input.cliFlags ?? {}),
  };

  const parsed = ConfigSchema.safeParse(merged);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const key = issue?.path.join('.') ?? 'unknown';
    return err(
      AppError.user(
        'CONFIG_INVALID',
        `Invalid configuration value for "${key}": ${issue?.message ?? 'unknown error'}`,
        `Check "${key}" in ${rcPath ?? RC_FILE_NAME}, VERIPATCH_* environment variables, and CLI flags.`,
      ),
    );
  }

  return ok({ config: parsed.data, warnings, ...(rcPath !== undefined ? { rcPath } : {}) });
}

function readRcFile(
  input: LoadConfigInput,
  warnings: string[],
): Result<{ values: Partial<Config>; rcPath?: string }> {
  const rcPath = input.configPath ?? path.join(input.cwd, RC_FILE_NAME);
  const explicit = input.configPath !== undefined;

  if (!fs.existsSync(rcPath)) {
    if (explicit) {
      return err(
        AppError.user(
          'CONFIG_NOT_FOUND',
          `Config file not found: ${rcPath}`,
          'Check the --config path.',
        ),
      );
    }
    return ok({ values: {} });
  }

  let raw: string;
  try {
    const stat = fs.statSync(rcPath);
    if (stat.size > RC_FILE_MAX_BYTES) {
      return err(
        AppError.user(
          'CONFIG_TOO_LARGE',
          `Config file exceeds ${String(RC_FILE_MAX_BYTES)} bytes: ${rcPath}`,
        ),
      );
    }
    raw = fs.readFileSync(rcPath, 'utf8');
  } catch (cause) {
    return err(
      AppError.world(
        'CONFIG_UNREADABLE',
        `Could not read config file: ${rcPath}`,
        undefined,
        cause,
      ),
    );
  }

  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch (cause) {
    return err(
      AppError.user(
        'CONFIG_MALFORMED',
        `Config file is not valid JSON: ${rcPath}`,
        'Fix the JSON syntax (a trailing comma is the usual suspect).',
        cause,
      ),
    );
  }

  if (json === null || typeof json !== 'object' || Array.isArray(json)) {
    return err(
      AppError.user('CONFIG_MALFORMED', `Config file must contain a JSON object: ${rcPath}`),
    );
  }

  const values: Partial<Config> = {};
  for (const [key, value] of Object.entries(json)) {
    if ((CONFIG_KEYS as string[]).includes(key)) {
      (values as Record<string, unknown>)[key] = value;
    } else {
      warnings.push(`Unknown config key "${key}" in ${rcPath} — ignored.`);
    }
  }
  return ok({ values, rcPath });
}

/** VERIPATCH_SEVERITY_THRESHOLD=high → { severityThreshold: 'high' }, with type coercion. */
function readEnvOverrides(env: NodeJS.ProcessEnv): Result<Partial<Config>> {
  const overrides: Partial<Config> = {};
  for (const key of CONFIG_KEYS) {
    const envName = `VERIPATCH_${camelToScreamingSnake(key)}`;
    const rawValue = env[envName];
    if (rawValue === undefined) continue;

    const coerced = coerceEnvValue(key, rawValue);
    if (!coerced.ok) {
      return err(
        AppError.user(
          'CONFIG_INVALID',
          `Invalid value for environment variable ${envName}: ${coerced.error}`,
          `Expected ${expectedTypeOf(key)}.`,
        ),
      );
    }
    (overrides as Record<string, unknown>)[key] = coerced.value;
  }
  return ok(overrides);
}

function coerceEnvValue(
  key: keyof Config,
  raw: string,
): { ok: true; value: unknown } | { ok: false; error: string } {
  switch (expectedTypeOf(key)) {
    case 'boolean':
      if (raw === 'true' || raw === '1') return { ok: true, value: true };
      if (raw === 'false' || raw === '0') return { ok: true, value: false };
      return { ok: false, error: `"${raw}" is not a boolean` };
    case 'number': {
      const n = Number(raw);
      if (Number.isNaN(n)) return { ok: false, error: `"${raw}" is not a number` };
      return { ok: true, value: n };
    }
    case 'string[]':
      return {
        ok: true,
        value: raw
          .split(',')
          .map((s) => s.trim())
          .filter((s) => s.length > 0),
      };
    case 'string':
      return { ok: true, value: raw };
  }
}

function expectedTypeOf(key: keyof Config): 'boolean' | 'number' | 'string' | 'string[]' {
  switch (key) {
    case 'includeDevDeps':
      return 'boolean';
    case 'verifyTimeoutMin':
    case 'cacheTtlHours':
      return 'number';
    case 'ignore':
      return 'string[]';
    case 'severityThreshold':
    case 'testCommand':
    case 'buildCommand':
    case 'sandboxImage':
    case 'reportDir':
      return 'string';
  }
}

function camelToScreamingSnake(name: string): string {
  return name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase();
}

function stripUndefined<T extends object>(obj: T): Partial<T> {
  return Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined)) as Partial<T>;
}
