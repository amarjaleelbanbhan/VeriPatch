import semver from 'semver';
import type { Advisory, DepNode, Vuln } from '../models/index.js';

/**
 * Version matching (blueprint §3): never hand-roll semver — the `semver`
 * package is the sole source of truth for range logic. This wrapper only
 * decides how OSV's two range flavors map onto it:
 *
 * - a comparator-shaped range ("<1.6.0", ">=0.8.1 <1.6.0", "*") is checked
 *   with semver.satisfies
 * - a bare version string (from OSV's explicit `versions` enumeration) is
 *   checked with exact equality — it is not a range at all
 *
 * includePrerelease stays on: a 1.2.3-beta.0 install must not silently
 * dodge an advisory that covers it.
 */

const RANGE_OPERATOR_CHARS = /[<>=^~|*x]/i;

export function versionInRange(version: string, range: string): boolean {
  if (range === '*') return true;
  if (!RANGE_OPERATOR_CHARS.test(range)) {
    // Bare version string — exact match only, never a "starts with" prefix match.
    return semver.valid(version) !== null && semver.valid(range) !== null
      ? semver.eq(version, range)
      : version === range;
  }
  if (!semver.validRange(range)) return false;
  return semver.satisfies(version, range, { includePrerelease: true });
}

/**
 * Cross a DepGraph against a set of advisories, producing one Vuln per
 * (node, matching range) pair. An advisory with multiple affected ranges for
 * the same package (e.g. two disjoint vulnerable windows) can match a node
 * at most once — the first matching range wins, recorded in matchedRange.
 */
export function matchVulnerabilities(nodes: DepNode[], advisories: Advisory[]): Vuln[] {
  const vulns: Vuln[] = [];
  for (const node of nodes) {
    for (const advisory of advisories) {
      const matchedRange = firstMatchingRange(node, advisory);
      if (matchedRange !== undefined) {
        vulns.push({ advisory, node, matchedRange });
      }
    }
  }
  return vulns;
}

function firstMatchingRange(node: DepNode, advisory: Advisory): string | undefined {
  for (const entry of advisory.affected) {
    if (entry.pkg !== node.name) continue;
    for (const range of entry.ranges) {
      if (versionInRange(node.version, range)) return range;
    }
  }
  return undefined;
}
