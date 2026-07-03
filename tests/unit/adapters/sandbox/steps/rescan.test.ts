import { describe, expect, it } from 'vitest';
import { runRescanStep } from '../../../../../src/adapters/sandbox/steps/rescan.js';
import type { DepGraph, DepNode, FixCandidate } from '../../../../../src/core/models/index.js';
import type { AdvisorySource, LockfileParser } from '../../../../../src/core/ports.js';
import { AppError } from '../../../../../src/shared/errors.js';
import { err, ok } from '../../../../../src/shared/result.js';

function node(name: string, version: string): DepNode {
  return { name, version, paths: [['root', name]], dev: false, direct: true };
}

const candidate: FixCandidate = {
  vulnId: 'GHSA-1',
  pkg: 'axios',
  from: '1.5.0',
  to: '1.6.0',
  bumpType: 'minor',
  strategy: 'direct',
  feasible: true,
};

function fakeParser(graph: DepGraph): LockfileParser {
  return { parse: () => ok(graph) };
}

const advisory = {
  id: 'GHSA-1',
  aliases: [],
  summary: 's',
  severity: { cvss: 7.5, label: 'HIGH' as const },
  affected: [{ pkg: 'axios', ranges: ['<1.6.0'], fixed: '1.6.0' }],
  references: [],
  modified: '2026-01-01T00:00:00Z',
};

function fakeAdvisorySource(advisories: (typeof advisory)[]): AdvisorySource {
  return { getAdvisories: () => Promise.resolve(ok({ advisories, stale: false, dataErrors: 0 })) };
}

describe('runRescanStep', () => {
  it('passes when the vuln no longer matches the bumped version', async () => {
    const graph: DepGraph = {
      nodes: [node('axios', '1.6.0')],
      lockfileVersion: 3,
      degraded: false,
    };
    const step = await runRescanStep(
      fakeParser(graph),
      fakeAdvisorySource([advisory]),
      '/staging',
      candidate,
    );
    expect(step).toMatchObject({ step: 'rescan', status: 'pass' });
  });

  it('fails when the vuln is still present after the bump (ineffective fix)', async () => {
    const graph: DepGraph = {
      nodes: [node('axios', '1.5.5')],
      lockfileVersion: 3,
      degraded: false,
    };
    const step = await runRescanStep(
      fakeParser(graph),
      fakeAdvisorySource([advisory]),
      '/staging',
      candidate,
    );
    expect(step).toMatchObject({ step: 'rescan', status: 'fail' });
    expect(step.logTail).toContain('still present');
  });

  it('fails safely when the sandbox lockfile cannot be parsed', async () => {
    const parser: LockfileParser = {
      parse: () => err(AppError.user('LOCKFILE_INVALID', 'bad lockfile')),
    };
    const step = await runRescanStep(parser, fakeAdvisorySource([advisory]), '/staging', candidate);
    expect(step.status).toBe('fail');
    expect(step.logTail).toContain('bad lockfile');
  });

  it('fails safely when advisory lookup errors', async () => {
    const graph: DepGraph = {
      nodes: [node('axios', '1.5.5')],
      lockfileVersion: 3,
      degraded: false,
    };
    const advisorySource: AdvisorySource = {
      getAdvisories: () =>
        Promise.resolve(err(AppError.world('ADVISORIES_UNAVAILABLE', 'offline'))),
    };
    const step = await runRescanStep(fakeParser(graph), advisorySource, '/staging', candidate);
    expect(step.status).toBe('fail');
  });
});
