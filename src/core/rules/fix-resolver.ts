import semver from 'semver';
import type { BumpType, FixCandidate, FixStrategy, Vuln } from '../models/index.js';

/**
 * Deterministic fix resolution (blueprint §2/§9).
 *
 * Invariant enforced structurally, not just by convention: FixCandidate.pkg
 * always equals the vulnerable node's own name. A "fix" is a version-only
 * change to the same package — never a swap to a different one.
 *
 * Strategy is a pure function of `node.direct` because the rule engine has
 * no access to the live dependency tree at this layer:
 * - direct dependency  -> 'direct'   (bump the root's own package.json range)
 * - transitive         -> 'override' (npm `overrides` field forces resolution)
 * parent-bump is a verify-time fallback when an override alone would violate
 * the parent's own engines/peer constraints — decided during verification,
 * not here.
 */
export function resolveFix(vuln: Vuln): FixCandidate {
  const { node, advisory } = vuln;
  const fixedVersions = collectFixedVersions(vuln);

  if (fixedVersions.length === 0) {
    return {
      vulnId: advisory.id,
      pkg: node.name,
      from: node.version,
      to: node.version,
      bumpType: 'patch',
      strategy: strategyFor(vuln),
      feasible: false,
      reason: 'No fixed version has been published for this advisory.',
    };
  }

  // First-fixed: the lowest published version that actually resolves this
  // vulnerability and is newer than what's installed.
  const to = fixedVersions.sort(semver.compare).find((v) => semver.gt(v, node.version));

  if (to === undefined) {
    return {
      vulnId: advisory.id,
      pkg: node.name,
      from: node.version,
      to: node.version,
      bumpType: 'patch',
      strategy: strategyFor(vuln),
      feasible: false,
      reason: 'Installed version is already at or above every known fixed version.',
    };
  }

  return {
    vulnId: advisory.id,
    pkg: node.name,
    from: node.version,
    to,
    bumpType: bumpTypeOf(node.version, to),
    strategy: strategyFor(vuln),
    feasible: true,
  };
}

function collectFixedVersions(vuln: Vuln): string[] {
  const versions: string[] = [];
  for (const entry of vuln.advisory.affected) {
    if (entry.pkg !== vuln.node.name) continue;
    if (entry.fixed !== undefined && semver.valid(entry.fixed) !== null) {
      versions.push(entry.fixed);
    }
  }
  return versions;
}

function strategyFor(vuln: Vuln): FixStrategy {
  return vuln.node.direct ? 'direct' : 'override';
}

function bumpTypeOf(from: string, to: string): BumpType {
  const diff = semver.diff(from, to);
  switch (diff) {
    case 'major':
    case 'premajor':
      return 'major';
    case 'minor':
    case 'preminor':
      return 'minor';
    case 'patch':
    case 'prepatch':
    case 'prerelease':
    case 'release':
    case null:
      return 'patch';
  }
}
