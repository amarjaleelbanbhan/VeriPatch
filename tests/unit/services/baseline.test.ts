import { describe, expect, it } from 'vitest';
import {
  activeBaselineKeys,
  addToBaseline,
  baselineKeyOf,
  createBaseline,
  diffAgainstBaseline,
  pruneBaseline,
  removeFromBaseline,
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
  it('captures a deduplicated, sorted key set with addedAt metadata', () => {
    const now = new Date('2026-07-04T00:00:00.000Z');
    const baseline = createBaseline(
      [vuln('GHSA-2', 'b'), vuln('GHSA-1', 'a'), vuln('GHSA-2', 'b', '9.9.9')],
      now,
    );
    expect(baseline.vulnKeys).toEqual(['GHSA-1::a', 'GHSA-2::b']);
    expect(baseline.entries).toEqual([
      { key: 'GHSA-1::a', addedAt: now.toISOString() },
      { key: 'GHSA-2::b', addedAt: now.toISOString() },
    ]);
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

  it('an expired acceptance counts as new again', () => {
    const { baseline } = addToBaseline(undefined, [vuln('GHSA-1', 'a')], {
      expiresAt: '2026-01-01T00:00:00.000Z',
    });
    const afterExpiry = diffAgainstBaseline(
      [vuln('GHSA-1', 'a')],
      baseline,
      new Date('2026-06-01T00:00:00.000Z'),
    );
    expect(afterExpiry.newVulns.map((v) => v.id)).toEqual(['GHSA-1']);

    const beforeExpiry = diffAgainstBaseline(
      [vuln('GHSA-1', 'a')],
      baseline,
      new Date('2025-06-01T00:00:00.000Z'),
    );
    expect(beforeExpiry.existingVulns.map((v) => v.id)).toEqual(['GHSA-1']);
  });
});

describe('baseline mutations', () => {
  it('addToBaseline stores reason and expiry, and is idempotent', () => {
    const now = new Date('2026-07-04T00:00:00.000Z');
    const first = addToBaseline(undefined, [vuln('GHSA-1', 'a')], {
      reason: 'not reachable in our code path',
      now,
    });
    expect(first.changedKeys).toEqual(['GHSA-1::a']);
    expect(first.baseline.entries).toEqual([
      { key: 'GHSA-1::a', addedAt: now.toISOString(), reason: 'not reachable in our code path' },
    ]);

    const second = addToBaseline(first.baseline, [vuln('GHSA-1', 'a')], { now });
    expect(second.changedKeys).toEqual([]);
    expect(second.baseline).toEqual(first.baseline);
  });

  it('removeFromBaseline drops every key of the advisory, with metadata', () => {
    const { baseline } = addToBaseline(undefined, [vuln('GHSA-1', 'a'), vuln('GHSA-1', 'b')], {});
    const removed = removeFromBaseline(baseline, 'GHSA-1');
    expect(removed.changedKeys).toEqual(['GHSA-1::a', 'GHSA-1::b']);
    expect(removed.baseline.vulnKeys).toEqual([]);
    expect(removed.baseline.entries).toEqual([]);
  });

  it('pruneBaseline drops keys whose vulns are gone', () => {
    const { baseline } = addToBaseline(undefined, [vuln('GHSA-1', 'a'), vuln('GHSA-2', 'b')], {});
    const pruned = pruneBaseline(baseline, [vuln('GHSA-2', 'b')]);
    expect(pruned.changedKeys).toEqual(['GHSA-1::a']);
    expect(pruned.baseline.vulnKeys).toEqual(['GHSA-2::b']);
  });

  it('activeBaselineKeys keeps keys without metadata forever', () => {
    const baseline = { schemaVersion: 1 as const, vulnKeys: ['GHSA-1::a'] };
    expect([...activeBaselineKeys(baseline, new Date('2099-01-01'))]).toEqual(['GHSA-1::a']);
  });
});
