import { describe, expect, it } from 'vitest';
import { resolveFix } from '../../../../src/core/rules/fix-resolver.js';
import type { Advisory, DepNode, Vuln } from '../../../../src/core/models/index.js';

function node(version: string, overrides: Partial<DepNode> = {}): DepNode {
  return {
    name: 'axios',
    version,
    paths: [['root', 'axios']],
    dev: false,
    direct: true,
    ...overrides,
  };
}

function vuln(
  installed: string,
  affected: Advisory['affected'],
  overrides: Partial<DepNode> = {},
): Vuln {
  return {
    node: node(installed, overrides),
    matchedRange: affected[0]?.ranges[0] ?? '*',
    advisory: {
      id: 'GHSA-1',
      aliases: [],
      summary: 's',
      severity: { cvss: 7.5, label: 'HIGH' },
      affected,
      references: [],
      modified: '2026-01-01T00:00:00Z',
    },
  };
}

describe('resolveFix — direct strategy', () => {
  it('resolves a patch bump', () => {
    const v = vuln('1.5.0', [{ pkg: 'axios', ranges: ['<1.5.1'], fixed: '1.5.1' }]);
    expect(resolveFix(v)).toEqual({
      vulnId: 'GHSA-1',
      pkg: 'axios',
      from: '1.5.0',
      to: '1.5.1',
      bumpType: 'patch',
      strategy: 'direct',
      feasible: true,
    });
  });

  it('resolves a minor bump', () => {
    const v = vuln('1.5.0', [{ pkg: 'axios', ranges: ['<1.6.0'], fixed: '1.6.0' }]);
    expect(resolveFix(v).bumpType).toBe('minor');
  });

  it('resolves a major bump', () => {
    const v = vuln('1.5.0', [{ pkg: 'axios', ranges: ['<2.0.0'], fixed: '2.0.0' }]);
    expect(resolveFix(v).bumpType).toBe('major');
  });

  it('picks the first-fixed (lowest) version across multiple disjoint ranges', () => {
    const v = vuln('1.0.0', [
      { pkg: 'axios', ranges: ['>=1.0.0 <1.2.0'], fixed: '1.2.0' },
      { pkg: 'axios', ranges: ['>=0.5.0 <1.0.0'], fixed: '1.1.0' },
    ]);
    // both fixed versions are > installed; the lower one wins
    expect(resolveFix(v).to).toBe('1.1.0');
  });
});

describe('resolveFix — strategy by directness', () => {
  it('transitive dependency resolves to override strategy', () => {
    const v = vuln('1.5.0', [{ pkg: 'axios', ranges: ['<1.6.0'], fixed: '1.6.0' }], {
      direct: false,
    });
    expect(resolveFix(v).strategy).toBe('override');
  });
});

describe('resolveFix — infeasible cases', () => {
  it('no fixed version published', () => {
    const v = vuln('1.5.0', [{ pkg: 'axios', ranges: ['<9.9.9'] }]);
    const fix = resolveFix(v);
    expect(fix.feasible).toBe(false);
    expect(fix.to).toBe(fix.from);
    expect(fix.reason).toMatch(/no fixed version/i);
  });

  it('installed version already at or above every fixed version', () => {
    const v = vuln('2.0.0', [{ pkg: 'axios', ranges: ['*'], fixed: '1.6.0' }]);
    const fix = resolveFix(v);
    expect(fix.feasible).toBe(false);
    expect(fix.reason).toMatch(/already at or above/i);
  });

  it('ignores an invalid fixed-version string rather than crashing', () => {
    const v = vuln('1.0.0', [{ pkg: 'axios', ranges: ['<2.0.0'], fixed: 'not-a-version' }]);
    expect(resolveFix(v).feasible).toBe(false);
  });
});

describe('resolveFix — same-package invariant', () => {
  it('the candidate package always matches the vulnerable node', () => {
    const v = vuln('1.5.0', [{ pkg: 'axios', ranges: ['<1.6.0'], fixed: '1.6.0' }]);
    expect(resolveFix(v).pkg).toBe(v.node.name);
  });
});
