import fs from 'node:fs';
import { AppError } from '../../shared/errors.js';
import { err, ok, type Result } from '../../shared/result.js';

/**
 * Hardened JSON file reader (blueprint §9): the scanned project is
 * attacker-controlled input. Size-capped before read, JSON.parse only
 * (never eval/require), and "__proto__" keys stripped so no later copy
 * operation can pollute prototypes.
 */
export const MAX_JSON_BYTES = 50 * 1024 * 1024; // 50MB

export function readJsonFile(filePath: string, maxBytes = MAX_JSON_BYTES): Result<unknown> {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(filePath);
  } catch {
    return err(AppError.user('FILE_NOT_FOUND', `File not found: ${filePath}`));
  }

  if (!stat.isFile()) {
    return err(AppError.user('NOT_A_FILE', `Not a regular file: ${filePath}`));
  }
  if (stat.size > maxBytes) {
    return err(
      AppError.user(
        'FILE_TOO_LARGE',
        `${filePath} is ${String(stat.size)} bytes; limit is ${String(maxBytes)}`,
        'This does not look like an honest lockfile. If it is, raise the limit deliberately.',
      ),
    );
  }

  let raw: string;
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch (cause) {
    return err(AppError.world('FILE_UNREADABLE', `Could not read ${filePath}`, undefined, cause));
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (cause) {
    return err(AppError.user('JSON_MALFORMED', `${filePath} is not valid JSON`, undefined, cause));
  }

  return ok(stripDangerousKeys(parsed));
}

/**
 * Removes "__proto__" own-properties recursively. JSON.parse creates them as
 * harmless own properties, but any later {...spread} or Object.assign copy
 * would write them into a live prototype chain.
 */
export function stripDangerousKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripDangerousKeys);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value)) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
      out[key] = stripDangerousKeys((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}
