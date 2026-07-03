import {
  BASELINE_SCHEMA_VERSION,
  type Baseline,
  type BaselineEntry,
  type ScannedVuln,
} from '../core/models/index.js';

/**
 * Baseline diffing and management (blueprint §6 `--ci` mode): a vuln's
 * identity for baseline purposes is its advisory id plus the affected package
 * — not the installed version, so a partial/ineffective bump doesn't
 * spuriously look "new".
 */
export function baselineKeyOf(vuln: ScannedVuln): string {
  return `${vuln.id}::${vuln.pkg}`;
}

export function createBaseline(vulns: ScannedVuln[], now = new Date()): Baseline {
  const keys = [...new Set(vulns.map(baselineKeyOf))].sort();
  return {
    schemaVersion: BASELINE_SCHEMA_VERSION,
    vulnKeys: keys,
    entries: keys.map((key) => ({ key, addedAt: now.toISOString() })),
  };
}

/** Keys currently accepted as debt — expired entries no longer count. */
export function activeBaselineKeys(baseline: Baseline, now = new Date()): Set<string> {
  const expired = new Set(
    (baseline.entries ?? [])
      .filter((e) => e.expiresAt !== undefined && new Date(e.expiresAt) <= now)
      .map((e) => e.key),
  );
  return new Set(baseline.vulnKeys.filter((key) => !expired.has(key)));
}

export interface BaselineDiff {
  newVulns: ScannedVuln[];
  existingVulns: ScannedVuln[];
}

/** No baseline at all means every vuln counts as new (blueprint: "else any"). */
export function diffAgainstBaseline(
  vulns: ScannedVuln[],
  baseline: Baseline | undefined,
  now = new Date(),
): BaselineDiff {
  if (baseline === undefined) {
    return { newVulns: vulns, existingVulns: [] };
  }
  const known = activeBaselineKeys(baseline, now);
  const newVulns: ScannedVuln[] = [];
  const existingVulns: ScannedVuln[] = [];
  for (const vuln of vulns) {
    (known.has(baselineKeyOf(vuln)) ? existingVulns : newVulns).push(vuln);
  }
  return { newVulns, existingVulns };
}

export interface BaselineMutation {
  baseline: Baseline;
  /** Keys the operation actually added/removed (empty = nothing to do). */
  changedKeys: string[];
}

export interface AddOptions {
  reason?: string | undefined;
  expiresAt?: string | undefined;
  now?: Date;
}

/** Accepts every given vuln as debt; existing keys keep their metadata. */
export function addToBaseline(
  baseline: Baseline | undefined,
  vulns: ScannedVuln[],
  options: AddOptions = {},
): BaselineMutation {
  const base: Baseline = baseline ?? { schemaVersion: BASELINE_SCHEMA_VERSION, vulnKeys: [] };
  const existing = new Set(base.vulnKeys);
  const changedKeys = [...new Set(vulns.map(baselineKeyOf))]
    .filter((key) => !existing.has(key))
    .sort();

  const newEntries: BaselineEntry[] = changedKeys.map((key) => ({
    key,
    addedAt: (options.now ?? new Date()).toISOString(),
    ...(options.reason !== undefined ? { reason: options.reason } : {}),
    ...(options.expiresAt !== undefined ? { expiresAt: options.expiresAt } : {}),
  }));

  return {
    baseline: {
      ...base,
      vulnKeys: [...base.vulnKeys, ...changedKeys].sort(),
      entries: [...(base.entries ?? []), ...newEntries],
    },
    changedKeys,
  };
}

/** Removes every key belonging to the given advisory id (`id::*`). */
export function removeFromBaseline(baseline: Baseline, vulnId: string): BaselineMutation {
  const prefix = `${vulnId}::`;
  const changedKeys = baseline.vulnKeys.filter((key) => key.startsWith(prefix));
  return {
    baseline: dropKeys(baseline, new Set(changedKeys)),
    changedKeys,
  };
}

/** Drops keys that no longer match any currently-found vuln — debt paid off. */
export function pruneBaseline(baseline: Baseline, currentVulns: ScannedVuln[]): BaselineMutation {
  const current = new Set(currentVulns.map(baselineKeyOf));
  const changedKeys = baseline.vulnKeys.filter((key) => !current.has(key));
  return {
    baseline: dropKeys(baseline, new Set(changedKeys)),
    changedKeys,
  };
}

function dropKeys(baseline: Baseline, keys: ReadonlySet<string>): Baseline {
  return {
    ...baseline,
    vulnKeys: baseline.vulnKeys.filter((key) => !keys.has(key)),
    ...(baseline.entries !== undefined
      ? { entries: baseline.entries.filter((e) => !keys.has(e.key)) }
      : {}),
  };
}
