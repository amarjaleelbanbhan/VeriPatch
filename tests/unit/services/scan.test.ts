import { describe, expect, it } from 'vitest';
import { runScan, type ScanServiceDeps } from '../../../src/services/scan.js';
import type { DepGraph, DepNode } from '../../../src/core/models/index.js';
import type { AdvisoryLookup, AdvisorySource, LockfileParser } from '../../../src/core/ports.js';
import { AppError } from '../../../src/shared/errors.js';
import { err, ok, type Result } from '../../../src/shared/result.js';

function node(name: string, version: string, overrides: Partial<DepNode> = {}): DepNode {
  return { name, version, paths: [['root', name]], dev: false, direct: true, ...overrides };
}

function fakeParser(graph: DepGraph | AppError): LockfileParser {
  return { parse: () => (graph instanceof AppError ? err(graph) : ok(graph)) };
}

function fakeAdvisorySource(result: Result<AdvisoryLookup>): AdvisorySource {
  return { getAdvisories: () => Promise.resolve(result) };
}

const baseRequest = {
  projectDir: '/project',
  severityThreshold: 'low' as const,
  ignore: [],
  includeDevDeps: true,
};

describe('runScan', () => {
  it('propagates a lockfile parse error', async () => {
    const deps: ScanServiceDeps = {
      parser: fakeParser(AppError.user('NO_MANIFEST', 'no project')),
      advisorySource: fakeAdvisorySource(ok({ advisories: [], stale: false, dataErrors: 0 })),
    };
    const r = await runScan(deps, baseRequest);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('NO_MANIFEST');
  });

  it('propagates an advisory source error', async () => {
    const deps: ScanServiceDeps = {
      parser: fakeParser({ nodes: [], lockfileVersion: 3, degraded: false }),
      advisorySource: fakeAdvisorySource(err(AppError.world('ADVISORIES_UNAVAILABLE', 'offline'))),
    };
    const r = await runScan(deps, baseRequest);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('ADVISORIES_UNAVAILABLE');
  });

  it('produces a schema-shaped ScanOutput with ranked, fix-resolved vulns', async () => {
    const nodes = [node('axios', '1.5.0'), node('lodash', '4.17.21')];
    const deps: ScanServiceDeps = {
      parser: fakeParser({ nodes, lockfileVersion: 3, degraded: false }),
      advisorySource: fakeAdvisorySource(
        ok({
          advisories: [
            {
              id: 'GHSA-1',
              aliases: ['CVE-2026-1'],
              summary: 's',
              severity: { cvss: 7.5, label: 'HIGH' },
              affected: [{ pkg: 'axios', ranges: ['<1.6.0'], fixed: '1.6.0' }],
              references: [],
              modified: '2026-01-01T00:00:00Z',
            },
          ],
          stale: false,
          dataErrors: 0,
        }),
      ),
    };

    const r = await runScan(deps, baseRequest);
    if (!r.ok) throw r.error;
    const output = r.value;

    expect(output.schemaVersion).toBe(1);
    expect(output.scan).toMatchObject({ totalDeps: 2, degraded: false, lockfileVersion: 3 });
    expect(output.vulns).toHaveLength(1);
    expect(output.vulns[0]).toMatchObject({
      id: 'GHSA-1',
      pkg: 'axios',
      installed: '1.5.0',
      fix: { to: '1.6.0', feasible: true, bumpType: 'minor', strategy: 'direct' },
      verification: null,
    });
    expect(output.summary).toEqual({ critical: 0, high: 1, medium: 0, low: 0, verified: 0 });
  });

  it('applies severity/ignore/dev filters before building the output', async () => {
    const nodes = [node('a', '1.0.0'), node('b', '1.0.0', { dev: true })];
    const advisories = [
      {
        id: 'GHSA-a',
        aliases: [],
        summary: 's',
        severity: { cvss: 3.0, label: 'LOW' as const },
        affected: [{ pkg: 'a', ranges: ['*'], fixed: '2.0.0' }],
        references: [],
        modified: '2026-01-01T00:00:00Z',
      },
      {
        id: 'GHSA-b',
        aliases: [],
        summary: 's',
        severity: { cvss: 7.0, label: 'HIGH' as const },
        affected: [{ pkg: 'b', ranges: ['*'], fixed: '2.0.0' }],
        references: [],
        modified: '2026-01-01T00:00:00Z',
      },
    ];
    const deps: ScanServiceDeps = {
      parser: fakeParser({ nodes, lockfileVersion: 3, degraded: false }),
      advisorySource: fakeAdvisorySource(ok({ advisories, stale: false, dataErrors: 0 })),
    };

    const r = await runScan(deps, {
      ...baseRequest,
      severityThreshold: 'medium',
      includeDevDeps: false,
    });
    if (!r.ok) throw r.error;
    // GHSA-a filtered by severity threshold; GHSA-b filtered by dev exclusion.
    expect(r.value.vulns).toHaveLength(0);
  });

  it('propagates degraded and stale flags from the graph and advisory lookup', async () => {
    const deps: ScanServiceDeps = {
      parser: fakeParser({ nodes: [], lockfileVersion: null, degraded: true }),
      advisorySource: fakeAdvisorySource(ok({ advisories: [], stale: true, dataErrors: 2 })),
    };
    const r = await runScan(deps, baseRequest);
    if (!r.ok) throw r.error;
    expect(r.value.scan).toMatchObject({
      degraded: true,
      lockfileVersion: null,
      stale: true,
      dataErrors: 2,
    });
  });
});
