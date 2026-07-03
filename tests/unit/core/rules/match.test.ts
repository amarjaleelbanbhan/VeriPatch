import { describe, expect, it } from 'vitest';
import { matchVulnerabilities, versionInRange } from '../../../../src/core/rules/match.js';
import type { Advisory, DepNode } from '../../../../src/core/models/index.js';

describe('versionInRange — exhaustive semver edge-case table', () => {
  // [version, range, expected] — every row exercises a documented edge case
  // (blueprint §8: 0.x, prerelease, ||, *).
  const table: [string, string, boolean][] = [
    // Standard comparator ranges
    ['1.5.0', '<1.6.0', true],
    ['1.6.0', '<1.6.0', false],
    ['1.6.0', '>=0.8.1 <1.6.0', false],
    ['0.8.0', '>=0.8.1 <1.6.0', false],
    ['1.0.0', '>=0.8.1 <1.6.0', true],

    // 0.x versions — no implicit "0.x is all one major" special-casing beyond semver's own rules
    ['0.1.0', '<0.2.0', true],
    ['0.2.0', '<0.2.0', false],
    ['0.9.9', '>=0.1.0 <1.0.0', true],

    // Prerelease versions: excluded by default semver rules unless the range
    // itself has a matching prerelease tag — we force includePrerelease so an
    // advisory range still catches prerelease installs.
    ['1.6.0-beta.1', '<1.6.0', true],
    ['1.6.0-beta.1', '<1.6.0-beta.5', true],
    ['1.6.0-beta.9', '<1.6.0-beta.5', false],
    ['2.0.0-alpha', '>=1.0.0', true],

    // OR'd ranges
    ['1.0.0', '<0.5.0 || >=0.9.0 <1.1.0', true],
    ['0.7.0', '<0.5.0 || >=0.9.0 <1.1.0', false],

    // Wildcards / "everything" ranges
    ['999.0.0', '*', true],
    ['0.0.1', '*', true],
    ['1.2.3', '>=1.0.0', true],

    // Bare version strings from OSV `versions` enumeration — exact match only
    ['1.2.3', '1.2.3', true],
    ['1.2.30', '1.2.3', false], // no accidental prefix match
    ['1.2.3', '1.2.4', false],

    // Malformed range never throws, just doesn't match
    ['1.0.0', 'not-a-range!!!', false],
  ];

  it.each(table)('%s in %s -> %s', (version, range, expected) => {
    expect(versionInRange(version, range)).toBe(expected);
  });
});

function node(name: string, version: string, overrides: Partial<DepNode> = {}): DepNode {
  return { name, version, paths: [['root', name]], dev: false, direct: true, ...overrides };
}

function advisory(id: string, pkg: string, ranges: string[], fixed?: string): Advisory {
  return {
    id,
    aliases: [],
    summary: 's',
    severity: { cvss: 7.5, label: 'HIGH' },
    affected: [{ pkg, ranges, ...(fixed !== undefined ? { fixed } : {}) }],
    references: [],
    modified: '2026-01-01T00:00:00Z',
  };
}

describe('matchVulnerabilities', () => {
  it('matches a node against an advisory covering it', () => {
    const nodes = [node('axios', '1.5.0')];
    const advisories = [advisory('GHSA-1', 'axios', ['<1.6.0'], '1.6.0')];
    const vulns = matchVulnerabilities(nodes, advisories);
    expect(vulns).toHaveLength(1);
    expect(vulns[0]).toMatchObject({ matchedRange: '<1.6.0' });
  });

  it('never matches a different package name (same-package invariant, upstream)', () => {
    const nodes = [node('axios', '1.5.0')];
    const advisories = [advisory('GHSA-1', 'lodash', ['<5.0.0'])];
    expect(matchVulnerabilities(nodes, advisories)).toHaveLength(0);
  });

  it('does not match a version outside every range', () => {
    const nodes = [node('axios', '2.0.0')];
    const advisories = [advisory('GHSA-1', 'axios', ['<1.6.0'])];
    expect(matchVulnerabilities(nodes, advisories)).toHaveLength(0);
  });

  it('produces one Vuln per matching (node, advisory) pair, not per range', () => {
    const nodes = [node('axios', '1.5.0')];
    const advisories = [advisory('GHSA-1', 'axios', ['<1.0.0', '>=1.0.0 <1.6.0'])];
    const vulns = matchVulnerabilities(nodes, advisories);
    expect(vulns).toHaveLength(1);
    expect(vulns[0]?.matchedRange).toBe('>=1.0.0 <1.6.0');
  });

  it('matches every affected node across multiple duplicate versions', () => {
    const nodes = [node('b', '1.0.0'), node('b', '2.0.0', { direct: false })];
    const advisories = [advisory('GHSA-1', 'b', ['<1.5.0'])];
    const vulns = matchVulnerabilities(nodes, advisories);
    expect(vulns.map((v) => v.node.version)).toEqual(['1.0.0']);
  });
});
