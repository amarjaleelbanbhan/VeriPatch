import { describe, expect, it } from 'vitest';
import { mergeVerification } from '../../../src/services/report.js';
import type { ScanOutput, VerificationResult } from '../../../src/core/models/index.js';

function baseScan(overrides: Partial<ScanOutput> = {}): ScanOutput {
  return {
    schemaVersion: 1,
    tool: { name: 'VeriPatch', version: '0.0.0' },
    generatedAt: '2026-01-01T00:00:00.000Z',
    scan: { lockfileVersion: 3, degraded: false, totalDeps: 1, dataErrors: 0, stale: false },
    vulns: [
      {
        id: 'GHSA-1',
        aliases: [],
        pkg: 'axios',
        installed: '1.5.0',
        severity: { cvss: 7.5, label: 'HIGH' },
        dev: false,
        paths: [['root', 'axios']],
        fix: {
          vulnId: 'GHSA-1',
          pkg: 'axios',
          from: '1.5.0',
          to: '1.6.0',
          bumpType: 'minor',
          strategy: 'direct',
          feasible: true,
        },
        verification: null,
      },
    ],
    summary: { critical: 0, high: 1, medium: 0, low: 0, verified: 0 },
    ...overrides,
  };
}

function verification(overrides: Partial<VerificationResult> = {}): VerificationResult {
  return {
    candidate: {
      vulnId: 'GHSA-1',
      pkg: 'axios',
      from: '1.5.0',
      to: '1.6.0',
      bumpType: 'minor',
      strategy: 'direct',
      feasible: true,
    },
    steps: [],
    confidence: 'HIGH',
    residualRisks: [],
    runId: 'r1',
    startedAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

describe('mergeVerification', () => {
  it('attaches the verification to the matching vuln by id+pkg', () => {
    const merged = mergeVerification(baseScan(), verification());
    expect(merged.vulns[0]?.verification).toEqual(verification());
  });

  it('recomputes the verified count in the summary', () => {
    const merged = mergeVerification(baseScan(), verification());
    expect(merged.summary.verified).toBe(1);
    expect(merged.summary.high).toBe(1); // severity counts untouched
  });

  it('leaves non-matching vulns and their verification untouched', () => {
    const scan = baseScan({
      vulns: [
        ...baseScan().vulns,
        {
          id: 'GHSA-2',
          aliases: [],
          pkg: 'lodash',
          installed: '4.17.0',
          severity: { cvss: 5.0, label: 'MEDIUM' },
          dev: false,
          paths: [['root', 'lodash']],
          fix: {
            vulnId: 'GHSA-2',
            pkg: 'lodash',
            from: '4.17.0',
            to: '4.17.21',
            bumpType: 'patch',
            strategy: 'direct',
            feasible: true,
          },
          verification: null,
        },
      ],
      summary: { critical: 0, high: 1, medium: 1, low: 0, verified: 0 },
    });
    const merged = mergeVerification(scan, verification());
    expect(merged.vulns[1]?.verification).toBeNull();
    expect(merged.summary.verified).toBe(1);
  });

  it('does not merge into a vuln with a different package name', () => {
    const scan = baseScan();
    const wrongPkg = verification({
      candidate: { ...verification().candidate, pkg: 'not-axios' },
    });
    const merged = mergeVerification(scan, wrongPkg);
    expect(merged.vulns[0]?.verification).toBeNull();
  });
});
