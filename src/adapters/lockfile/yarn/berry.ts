import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import { AppError } from '../../../shared/errors.js';
import { err, ok, type Result } from '../../../shared/result.js';
import { stripDangerousKeys } from '../safe-read.js';
import {
  hasForeignProtocol,
  splitDescriptor,
  stripNpmProtocol,
  type YarnEntries,
  type YarnEntry,
} from './entries.js';

/**
 * Parser for yarn berry (v2+) lockfiles — real YAML with a `__metadata` block.
 * Only `npm:`-protocol descriptors become graph entries; workspace/patch/git
 * resolutions are skipped (they are not registry packages VeriPatch can match
 * advisories against or bump).
 */

const RawBerryEntrySchema = z
  .object({
    version: z.union([z.string(), z.number()]).optional(),
    checksum: z.string().optional(),
    dependencies: z.record(z.string(), z.union([z.string(), z.number()])).optional(),
    optionalDependencies: z.record(z.string(), z.union([z.string(), z.number()])).optional(),
  })
  .loose();

const RawBerryLockSchema = z.record(z.string(), z.unknown());

export interface BerryLockfile {
  metadataVersion: number;
  entries: YarnEntries;
}

export function parseBerryLockfile(raw: string): Result<BerryLockfile> {
  let doc: unknown;
  try {
    doc = parseYaml(raw);
  } catch (cause) {
    return err(
      AppError.user(
        'LOCKFILE_INVALID',
        'yarn.lock is not valid YAML',
        'Regenerate the lockfile with yarn install.',
        cause,
      ),
    );
  }

  const parsed = RawBerryLockSchema.safeParse(stripDangerousKeys(doc));
  if (!parsed.success) {
    return err(AppError.user('LOCKFILE_INVALID', 'yarn.lock has an unexpected shape'));
  }
  const lock = parsed.data;

  const metadata = z
    .object({ version: z.coerce.number().int() })
    .loose()
    .safeParse(lock['__metadata']);
  if (!metadata.success) {
    return err(
      AppError.user(
        'LOCKFILE_INVALID',
        'yarn.lock has no readable __metadata.version',
        'Regenerate the lockfile with yarn install.',
      ),
    );
  }

  const entries: YarnEntries = new Map();
  for (const [key, value] of Object.entries(lock)) {
    if (key === '__metadata') continue;
    const entryParsed = RawBerryEntrySchema.safeParse(value);
    if (!entryParsed.success) {
      return err(
        AppError.user('LOCKFILE_INVALID', `yarn.lock entry "${key}" has an unexpected shape`),
      );
    }
    const rawEntry = entryParsed.data;
    if (rawEntry.version === undefined) continue; // unresolvable

    for (const part of key.split(',')) {
      const descriptor = part.trim();
      const split = splitDescriptor(descriptor);
      if (split === undefined) {
        return err(AppError.user('LOCKFILE_INVALID', `unparseable descriptor "${descriptor}"`));
      }
      if (hasForeignProtocol(split.range)) continue; // workspace:, patch:, git..., file:

      const entry: YarnEntry = {
        name: split.name,
        version: String(rawEntry.version),
        ...(rawEntry.checksum !== undefined ? { integrity: rawEntry.checksum } : {}),
        dependencies: normalizeDeps(rawEntry.dependencies),
        optionalDependencies: normalizeDeps(rawEntry.optionalDependencies),
      };
      entries.set(`${split.name}@${split.range}`, entry);
    }
  }

  return ok({ metadataVersion: metadata.data.version, entries });
}

function normalizeDeps(deps: Record<string, string | number> | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, range] of Object.entries(deps ?? {})) {
    const rangeText = String(range);
    if (hasForeignProtocol(rangeText)) continue;
    out[name] = stripNpmProtocol(rangeText);
  }
  return out;
}
