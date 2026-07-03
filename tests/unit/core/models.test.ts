import { describe, expect, it } from 'vitest';
import {
  AdvisorySchema,
  ConfidenceSchema,
  DepGraphSchema,
  DepNodeSchema,
  FixCandidateSchema,
  StepResultSchema,
  VerificationResultSchema,
  VulnSchema,
} from '../../../src/core/models/index.js';

const depNode = {
  name: 'axios',
  version: '1.5.0',
  paths: [['root', 'axios']],
  dev: false,
  direct: true,
  integrity: 'sha512-abc',
};

const advisory = {
  id: 'GHSA-xxxx-yyyy-zzzz',
  aliases: ['CVE-2026-1111'],
  summary: 'SSRF in axios',
  severity: { cvss: 7.5, label: 'HIGH' },
  affected: [{ pkg: 'axios', ranges: ['<1.6.2'], fixed: '1.6.2' }],
  references: ['https://example.com/advisory'],
  modified: '2026-01-01T00:00:00Z',
};

const fixCandidate = {
  vulnId: 'CVE-2026-1111',
  pkg: 'axios',
  from: '1.5.0',
  to: '1.6.2',
  bumpType: 'minor',
  strategy: 'direct',
  feasible: true,
};

describe('domain schemas round-trip', () => {
  it('DepNode / DepGraph', () => {
    expect(DepNodeSchema.parse(depNode)).toEqual(depNode);
    const graph = { nodes: [depNode], lockfileVersion: 3, packageManager: 'npm', degraded: false };
    expect(DepGraphSchema.parse(graph)).toEqual(graph);
  });

  it('Advisory', () => {
    expect(AdvisorySchema.parse(advisory)).toEqual(advisory);
  });

  it('Vuln', () => {
    const vuln = { advisory, node: depNode, matchedRange: '<1.6.2' };
    expect(VulnSchema.parse(vuln)).toEqual(vuln);
  });

  it('FixCandidate', () => {
    expect(FixCandidateSchema.parse(fixCandidate)).toEqual(fixCandidate);
    const infeasible = {
      ...fixCandidate,
      feasible: false,
      reason: 'no fixed version published',
    };
    expect(FixCandidateSchema.parse(infeasible)).toEqual(infeasible);
  });

  it('StepResult / VerificationResult', () => {
    const step = {
      step: 'install',
      status: 'pass',
      exitCode: 0,
      durationMs: 92_000,
      logTail: 'added 1243 packages',
    };
    expect(StepResultSchema.parse(step)).toEqual(step);

    const verification = {
      candidate: fixCandidate,
      steps: [step],
      confidence: 'HIGH',
      residualRisks: [],
      runId: 'b7f9d3f2-0000-4000-8000-000000000000',
      startedAt: '2026-07-03T12:00:00.000Z',
    };
    expect(VerificationResultSchema.parse(verification)).toEqual(verification);
  });
});

describe('domain schemas reject invalid input', () => {
  it('rejects hostile package names', () => {
    for (const name of [
      '../../../etc/passwd',
      'pkg;rm -rf /',
      'PKG_UPPER',
      '.hidden',
      'name with spaces',
      '',
    ]) {
      expect(DepNodeSchema.safeParse({ ...depNode, name }).success, name).toBe(false);
    }
  });

  it('accepts scoped names', () => {
    expect(DepNodeSchema.safeParse({ ...depNode, name: '@scope/pkg-name' }).success).toBe(true);
  });

  it('rejects out-of-range cvss and unknown labels', () => {
    expect(
      AdvisorySchema.safeParse({ ...advisory, severity: { cvss: 11, label: 'HIGH' } }).success,
    ).toBe(false);
    expect(
      AdvisorySchema.safeParse({ ...advisory, severity: { cvss: 5, label: 'SEVERE' } }).success,
    ).toBe(false);
  });

  it('rejects non-integer lockfile versions and unknown package managers', () => {
    expect(
      DepGraphSchema.safeParse({
        nodes: [],
        lockfileVersion: 2.5,
        packageManager: 'npm',
        degraded: false,
      }).success,
    ).toBe(false);
    expect(
      DepGraphSchema.safeParse({
        nodes: [],
        lockfileVersion: 3,
        packageManager: 'bower',
        degraded: false,
      }).success,
    ).toBe(false);
  });

  it('rejects unknown confidence and step values', () => {
    expect(ConfidenceSchema.safeParse('MAYBE').success).toBe(false);
    expect(
      StepResultSchema.safeParse({ step: 'deploy', status: 'pass', durationMs: 1, logTail: '' })
        .success,
    ).toBe(false);
  });

  it('rejects non-ISO startedAt', () => {
    expect(
      VerificationResultSchema.safeParse({
        candidate: fixCandidate,
        steps: [],
        confidence: 'MEDIUM',
        residualRisks: [],
        runId: 'r1',
        startedAt: 'yesterday',
      }).success,
    ).toBe(false);
  });
});
