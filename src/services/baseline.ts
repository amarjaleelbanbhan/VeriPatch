import { BASELINE_SCHEMA_VERSION, type Baseline, type ScannedVuln } from '../core/models/index.js';

/**
 * Baseline diffing (blueprint §6 `--ci` mode): a vuln's identity for baseline
 * purposes is its advisory id plus the affected package — not the installed
 * version, so a partial/ineffective bump doesn't spuriously look "new".
 */
export function baselineKeyOf(vuln: ScannedVuln): string {
  return `${vuln.id}::${vuln.pkg}`;
}

export function createBaseline(vulns: ScannedVuln[]): Baseline {
  return {
    schemaVersion: BASELINE_SCHEMA_VERSION,
    vulnKeys: [...new Set(vulns.map(baselineKeyOf))].sort(),
  };
}

export interface BaselineDiff {
  newVulns: ScannedVuln[];
  existingVulns: ScannedVuln[];
}

/** No baseline at all means every vuln counts as new (blueprint: "else any"). */
export function diffAgainstBaseline(
  vulns: ScannedVuln[],
  baseline: Baseline | undefined,
): BaselineDiff {
  if (baseline === undefined) {
    return { newVulns: vulns, existingVulns: [] };
  }
  const known = new Set(baseline.vulnKeys);
  const newVulns: ScannedVuln[] = [];
  const existingVulns: ScannedVuln[] = [];
  for (const vuln of vulns) {
    (known.has(baselineKeyOf(vuln)) ? existingVulns : newVulns).push(vuln);
  }
  return { newVulns, existingVulns };
}
