import { describe, expect, it } from 'vitest';
import {
  baselineKeyOf,
  createBaseline,
  diffAgainstBaseline,
} from '../../../src/services/baseline.js';
import type { ScannedVuln } from '../../../src/core/models/index.js';

function vuln(id: string, pkg: string, installed = '1.0.0'): ScannedVuln {
  return {
    id,
    aliases: [],
    pkg,
    installed,
    severity: { cvss: 7.5, label: 'HIGH' },
    dev: false,
    paths: [['root', pkg]],
    fix: {
      vulnId: id,
      pkg,
      from: installed,
      to: '2.0.0',
      bumpType: 'major',
      strategy: 'direct',
      feasible: true,
    },
    verification: null,
  };
}

describe('baselineKeyOf', () => {
  it('is stable across installed-version changes', () => {
    expect(baselineKeyOf(vuln('GHSA-1', 'axios', '1.0.0'))).toBe(
      baselineKeyOf(vuln('GHSA-1', 'axios', '1.5.0')),
    );
  });

  it('differs across packages or advisory ids', () => {
    expect(baselineKeyOf(vuln('GHSA-1', 'axios'))).not.toBe(baselineKeyOf(vuln('GHSA-2', 'axios')));
    expect(baselineKeyOf(vuln('GHSA-1', 'axios'))).not.toBe(
      baselineKeyOf(vuln('GHSA-1', 'lodash')),
    );
  });
});

describe('createBaseline', () => {
  it('captures a deduplicated, sorted key set', () => {
    const baseline = createBaseline([
      vuln('GHSA-2', 'b'),
      vuln('GHSA-1', 'a'),
      vuln('GHSA-2', 'b', '9.9.9'),
    ]);
    expect(baseline).toEqual({ schemaVersion: 1, vulnKeys: ['GHSA-1::a', 'GHSA-2::b'] });
  });
});

describe('diffAgainstBaseline', () => {
  it('everything counts as new when there is no baseline', () => {
    const vulns = [vuln('GHSA-1', 'a'), vuln('GHSA-2', 'b')];
    const diff = diffAgainstBaseline(vulns, undefined);
    expect(diff.newVulns).toEqual(vulns);
    expect(diff.existingVulns).toEqual([]);
  });

  it('splits vulns into new vs already-known', () => {
    const baseline = createBaseline([vuln('GHSA-1', 'a')]);
    const vulns = [vuln('GHSA-1', 'a', '1.5.0'), vuln('GHSA-2', 'b')];
    const diff = diffAgainstBaseline(vulns, baseline);
    expect(diff.existingVulns.map((v) => v.id)).toEqual(['GHSA-1']);
    expect(diff.newVulns.map((v) => v.id)).toEqual(['GHSA-2']);
  });
});
