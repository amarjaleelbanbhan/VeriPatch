import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { writeJsonReport } from '../../../../src/adapters/report/json.js';
import { ScanOutputSchema, type ScanOutput } from '../../../../src/core/models/index.js';

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veripatch-report-json-'));
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

describe('writeJsonReport', () => {
  it('writes schema-valid, pretty-printed JSON', () => {
    const filePath = path.join(tmpDir, 'report.json');
    const r = writeJsonReport(scan(), filePath);
    expect(r.ok).toBe(true);

    const written = JSON.parse(fs.readFileSync(filePath, 'utf8')) as unknown;
    expect(() => ScanOutputSchema.parse(written)).not.toThrow();
    expect(fs.readFileSync(filePath, 'utf8')).toContain('\n  ');
  });

  it('refuses to write data that fails its own schema (self-test)', () => {
    const filePath = path.join(tmpDir, 'report.json');
    const invalid = { ...scan(), schemaVersion: 2 } as unknown as ScanOutput;
    const r = writeJsonReport(invalid, filePath);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('REPORT_SCHEMA_INVALID');
    expect(fs.existsSync(filePath)).toBe(false);
  });

  it('surfaces an unwritable directory as a WorldError', () => {
    const r = writeJsonReport(scan(), path.join(tmpDir, 'does', 'not', 'exist', 'report.json'));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.kind).toBe('WorldError');
  });
});
