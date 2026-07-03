import type { SeverityLabel, Vuln } from '../models/index.js';

/**
 * Severity ranking and filtering (blueprint §6 scan flags: --severity,
 * --dev/--no-dev, and .veripatchrc's ignore list).
 */

const SEVERITY_ORDER: Record<SeverityLabel, number> = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
  CRITICAL: 3,
};

export interface SeverityFilterOptions {
  /** Minimum severity to keep, inclusive. */
  severityThreshold: 'low' | 'medium' | 'high' | 'critical';
  /** Advisory ids or aliases the user has explicitly accepted the risk of. */
  ignore: string[];
  /** Whether devDependencies-only vulns should be kept. */
  includeDevDeps: boolean;
}

/** Filters by threshold/ignore/dev, then sorts severity desc, cvss desc, id asc. */
export function rankVulnerabilities(vulns: Vuln[], options: SeverityFilterOptions): Vuln[] {
  const thresholdRank = SEVERITY_ORDER[options.severityThreshold.toUpperCase() as SeverityLabel];
  const ignoreSet = new Set(options.ignore);

  return vulns
    .filter((v) => SEVERITY_ORDER[v.advisory.severity.label] >= thresholdRank)
    .filter((v) => !isIgnored(v, ignoreSet))
    .filter((v) => options.includeDevDeps || !v.node.dev)
    .sort(compareVulns);
}

function isIgnored(vuln: Vuln, ignoreSet: ReadonlySet<string>): boolean {
  if (ignoreSet.has(vuln.advisory.id)) return true;
  return vuln.advisory.aliases.some((alias) => ignoreSet.has(alias));
}

function compareVulns(a: Vuln, b: Vuln): number {
  const severityDiff =
    SEVERITY_ORDER[b.advisory.severity.label] - SEVERITY_ORDER[a.advisory.severity.label];
  if (severityDiff !== 0) return severityDiff;
  const cvssDiff = b.advisory.severity.cvss - a.advisory.severity.cvss;
  if (cvssDiff !== 0) return cvssDiff;
  return a.advisory.id.localeCompare(b.advisory.id);
}
