import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadMergedScan } from '../../../../src/cli/commands/shared.js';
import type { ScanOutput, VerificationResult } from '../../../../src/core/models/index.js';

let reportDir: string;

beforeEach(() => {
  reportDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veripatch-shared-'));
});

afterEach(() => {
  fs.rmSync(reportDir, { recursive: true, force: true });
});

function writeScan(overrides: Partial<ScanOutput> = {}): void {
  const scan: ScanOutput = {
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
  fs.writeFileSync(path.join(reportDir, 'last-scan.json'), JSON.stringify(scan));
}

function writeRun(
  runId: string,
  startedAt: string,
  confidence: VerificationResult['confidence'],
): void {
  const result: VerificationResult = {
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
    confidence,
    residualRisks: [],
    runId,
    startedAt,
  };
  const runDir = path.join(reportDir, 'runs', runId);
  fs.mkdirSync(runDir, { recursive: true });
  fs.writeFileSync(path.join(runDir, 'result.json'), JSON.stringify(result));
}

describe('loadMergedScan', () => {
  it('errors when no last-scan.json exists', () => {
    const r = loadMergedScan(reportDir);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('NO_SCAN_FOUND');
  });

  it('returns the scan unmodified when no runs exist', () => {
    writeScan();
    const r = loadMergedScan(reportDir);
    if (!r.ok) throw r.error;
    expect(r.value.vulns[0]?.verification).toBeNull();
  });

  it('merges a single run into the matching vuln', () => {
    writeScan();
    writeRun('run-1', '2026-01-02T00:00:00.000Z', 'HIGH');
    const r = loadMergedScan(reportDir);
    if (!r.ok) throw r.error;
    expect(r.value.vulns[0]?.verification?.confidence).toBe('HIGH');
    expect(r.value.summary.verified).toBe(1);
  });

  it('keeps only the most recent run when a vuln was verified more than once', () => {
    writeScan();
    writeRun('run-1', '2026-01-01T00:00:00.000Z', 'MEDIUM');
    writeRun('run-2', '2026-01-03T00:00:00.000Z', 'HIGH');
    const r = loadMergedScan(reportDir);
    if (!r.ok) throw r.error;
    expect(r.value.vulns[0]?.verification?.runId).toBe('run-2');
    expect(r.value.vulns[0]?.verification?.confidence).toBe('HIGH');
  });

  it('skips a corrupted run artifact rather than failing the whole load', () => {
    writeScan();
    const runDir = path.join(reportDir, 'runs', 'bad-run');
    fs.mkdirSync(runDir, { recursive: true });
    fs.writeFileSync(path.join(runDir, 'result.json'), 'not json');
    const r = loadMergedScan(reportDir);
    if (!r.ok) throw r.error;
    expect(r.value.vulns[0]?.verification).toBeNull();
  });

  it('errors on a malformed last-scan.json', () => {
    fs.writeFileSync(path.join(reportDir, 'last-scan.json'), 'not json');
    const r = loadMergedScan(reportDir);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('SCAN_FILE_MALFORMED');
  });
});
