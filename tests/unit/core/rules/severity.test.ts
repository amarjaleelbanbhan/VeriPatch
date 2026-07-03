import { describe, expect, it } from 'vitest';
import { rankVulnerabilities } from '../../../../src/core/rules/severity.js';
import type { Advisory, DepNode, Vuln } from '../../../../src/core/models/index.js';

function makeVuln(
  id: string,
  label: Advisory['severity']['label'],
  cvss: number,
  overrides: { dev?: boolean; aliases?: string[] } = {},
): Vuln {
  const node: DepNode = {
    name: 'pkg',
    version: '1.0.0',
    paths: [['root', 'pkg']],
    dev: overrides.dev ?? false,
    direct: true,
  };
  return {
    node,
    matchedRange: '*',
    advisory: {
      id,
      aliases: overrides.aliases ?? [],
      summary: 's',
      severity: { cvss, label },
      affected: [{ pkg: 'pkg', ranges: ['*'] }],
      references: [],
      modified: '2026-01-01T00:00:00Z',
    },
  };
}

describe('rankVulnerabilities — threshold filtering', () => {
  const vulns = [
    makeVuln('LOW-1', 'LOW', 2.0),
    makeVuln('MED-1', 'MEDIUM', 5.5),
    makeVuln('HIGH-1', 'HIGH', 7.5),
    makeVuln('CRIT-1', 'CRITICAL', 9.8),
  ];

  it('low threshold keeps everything', () => {
    const r = rankVulnerabilities(vulns, {
      severityThreshold: 'low',
      ignore: [],
      includeDevDeps: true,
    });
    expect(r).toHaveLength(4);
  });

  it('high threshold keeps only high and critical', () => {
    const r = rankVulnerabilities(vulns, {
      severityThreshold: 'high',
      ignore: [],
      includeDevDeps: true,
    });
    expect(r.map((v) => v.advisory.id)).toEqual(['CRIT-1', 'HIGH-1']);
  });

  it('critical threshold keeps only critical', () => {
    const r = rankVulnerabilities(vulns, {
      severityThreshold: 'critical',
      ignore: [],
      includeDevDeps: true,
    });
    expect(r.map((v) => v.advisory.id)).toEqual(['CRIT-1']);
  });
});

describe('rankVulnerabilities — sorting', () => {
  it('sorts severity desc, then cvss desc, then id asc as a final tiebreak', () => {
    const vulns = [
      makeVuln('B', 'HIGH', 7.0),
      makeVuln('A', 'HIGH', 7.0),
      makeVuln('X', 'CRITICAL', 9.0),
      makeVuln('Y', 'HIGH', 8.9),
    ];
    const r = rankVulnerabilities(vulns, {
      severityThreshold: 'low',
      ignore: [],
      includeDevDeps: true,
    });
    expect(r.map((v) => v.advisory.id)).toEqual(['X', 'Y', 'A', 'B']);
  });
});

describe('rankVulnerabilities — ignore list', () => {
  it('drops vulns by id', () => {
    const vulns = [makeVuln('CVE-1', 'HIGH', 7.5), makeVuln('CVE-2', 'HIGH', 7.5)];
    const r = rankVulnerabilities(vulns, {
      severityThreshold: 'low',
      ignore: ['CVE-1'],
      includeDevDeps: true,
    });
    expect(r.map((v) => v.advisory.id)).toEqual(['CVE-2']);
  });

  it('drops vulns by alias', () => {
    const vulns = [makeVuln('GHSA-1', 'HIGH', 7.5, { aliases: ['CVE-2026-1'] })];
    const r = rankVulnerabilities(vulns, {
      severityThreshold: 'low',
      ignore: ['CVE-2026-1'],
      includeDevDeps: true,
    });
    expect(r).toHaveLength(0);
  });
});

describe('rankVulnerabilities — dev filter', () => {
  it('excludes dev-only vulns when includeDevDeps is false', () => {
    const vulns = [makeVuln('DEV-1', 'HIGH', 7.5, { dev: true }), makeVuln('PROD-1', 'HIGH', 7.5)];
    const r = rankVulnerabilities(vulns, {
      severityThreshold: 'low',
      ignore: [],
      includeDevDeps: false,
    });
    expect(r.map((v) => v.advisory.id)).toEqual(['PROD-1']);
  });

  it('includes dev vulns when includeDevDeps is true', () => {
    const vulns = [makeVuln('DEV-1', 'HIGH', 7.5, { dev: true })];
    const r = rankVulnerabilities(vulns, {
      severityThreshold: 'low',
      ignore: [],
      includeDevDeps: true,
    });
    expect(r).toHaveLength(1);
  });
});
