import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { FileReporter } from '../../../../src/adapters/report/index.js';
import type { ScanOutput, VerificationResult } from '../../../../src/core/models/index.js';

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veripatch-reporter-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function scan(): ScanOutput {
  return {
    schemaVersion: 1,
    tool: { name: 'VeriPatch', version: '0.0.0' },
    generatedAt: '2026-01-01T00:00:00.000Z',
    scan: { lockfileVersion: 3, degraded: false, totalDeps: 1, dataErrors: 0, stale: false },
    vulns: [],
    summary: { critical: 0, high: 0, medium: 0, low: 0, verified: 0 },
  };
}

describe('FileReporter', () => {
  it('writes both report.json and report.md', () => {
    const reporter = new FileReporter();
    const r = reporter.write(scan(), tmpDir);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(fs.existsSync(r.value.jsonPath)).toBe(true);
    expect(fs.existsSync(r.value.mdPath)).toBe(true);
  });

  it('honors a custom base file name', () => {
    const reporter = new FileReporter();
    const r = reporter.write(scan(), tmpDir, 'report-GHSA-1');
    if (!r.ok) throw r.error;
    expect(path.basename(r.value.jsonPath)).toBe('report-GHSA-1.json');
    expect(path.basename(r.value.mdPath)).toBe('report-GHSA-1.md');
  });

  it('rejects a standalone VerificationResult with no severity/package context', () => {
    const reporter = new FileReporter();
    const verification: VerificationResult = {
      candidate: {
        vulnId: 'GHSA-1',
        pkg: 'axios',
        from: '1.0.0',
        to: '1.0.1',
        bumpType: 'patch',
        strategy: 'direct',
        feasible: true,
      },
      steps: [],
      confidence: 'HIGH',
      residualRisks: [],
      runId: 'r1',
      startedAt: '2026-01-01T00:00:00.000Z',
    };
    const r = reporter.write(verification, tmpDir);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('REPORT_UNSUPPORTED_INPUT');
  });
});
