import { execSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { runUpdateCommand } from '../../../../src/cli/commands/update.js';
import type { ScanOutput } from '../../../../src/core/models/index.js';

let cwd: string;

function writeScan(overrides: Partial<ScanOutput['vulns'][number]> = {}): void {
  const scan: ScanOutput = {
    schemaVersion: 1,
    tool: { name: 'VeriPatch', version: '0.0.0' },
    generatedAt: '2026-01-01T00:00:00.000Z',
    scan: {
      lockfileVersion: 3,
      packageManager: 'npm',
      degraded: false,
      totalDeps: 1,
      dataErrors: 0,
      stale: false,
    },
    vulns: [
      {
        id: 'GHSA-1',
        aliases: [],
        pkg: 'left-pad',
        installed: '1.0.0',
        severity: { cvss: 7.5, label: 'HIGH' },
        dev: false,
        paths: [['root', 'left-pad']],
        fix: {
          vulnId: 'GHSA-1',
          pkg: 'left-pad',
          from: '1.0.0',
          to: '1.3.0',
          bumpType: 'minor',
          strategy: 'direct',
          feasible: true,
        },
        verification: null,
        ...overrides,
      },
    ],
    summary: { critical: 0, high: 1, medium: 0, low: 0, verified: 0 },
  };
  fs.mkdirSync(path.join(cwd, '.veripatch'), { recursive: true });
  fs.writeFileSync(path.join(cwd, '.veripatch', 'last-scan.json'), JSON.stringify(scan));
}

beforeEach(() => {
  cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'veripatch-update-'));
  fs.writeFileSync(
    path.join(cwd, 'package.json'),
    JSON.stringify({ name: 'fixture', version: '1.0.0', dependencies: { 'left-pad': '1.0.0' } }),
  );
});

afterEach(() => {
  fs.rmSync(cwd, { recursive: true, force: true });
});

function baseFlags(): {
  configPath: undefined;
  vulnId: string;
  force: boolean;
  allowDirty: boolean;
} {
  return { configPath: undefined, vulnId: 'GHSA-1', force: false, allowDirty: false };
}

describe('runUpdateCommand — refusal rules', () => {
  it('refuses when the vulnerability id is not in the last scan', () => {
    writeScan();
    const code = runUpdateCommand({ ...baseFlags(), cwd, vulnId: 'GHSA-nope' });
    expect(code).toBe(2);
  });

  it('refuses when the fix is not feasible', () => {
    writeScan({ fix: { ...writeScanDefaultFix(), feasible: false, reason: 'no fix' } });
    const code = runUpdateCommand({ ...baseFlags(), cwd });
    expect(code).toBe(2);
  });

  it('refuses an unverified vuln without --force', () => {
    writeScan();
    const code = runUpdateCommand({ ...baseFlags(), cwd });
    expect(code).toBe(2);
  });

  it('refuses a FAIL-confidence vuln without --force', () => {
    writeScan({ verification: makeVerification('FAIL') });
    const code = runUpdateCommand({ ...baseFlags(), cwd });
    expect(code).toBe(2);
  });

  it('accepts an unverified vuln when --force is passed, but still enforces the dirty-tree check', () => {
    writeScan();
    execSync('git init', { cwd, stdio: 'pipe' });
    fs.writeFileSync(path.join(cwd, 'untracked.txt'), 'x');
    const code = runUpdateCommand({ ...baseFlags(), cwd, force: true });
    expect(code).toBe(2); // still refused: dirty tree, no --allow-dirty
  });

  it('applies the fix when verified HIGH and the tree is clean', () => {
    writeScan({ verification: makeVerification('HIGH') });
    execSync('git init', { cwd, stdio: 'pipe' });
    execSync('git add -A', { cwd, stdio: 'pipe' });
    execSync('git -c user.email=t@t.com -c user.name=t commit -m init', { cwd, stdio: 'pipe' });

    const code = runUpdateCommand({ ...baseFlags(), cwd });
    expect(code).toBe(0);
    const pkg = JSON.parse(fs.readFileSync(path.join(cwd, 'package.json'), 'utf8')) as {
      dependencies: Record<string, string>;
    };
    expect(pkg.dependencies['left-pad']).toContain('1.3.0');
  }, 30_000);

  it('applies with --allow-dirty even when the tree has uncommitted changes', () => {
    writeScan({ verification: makeVerification('MEDIUM') });
    execSync('git init', { cwd, stdio: 'pipe' });
    fs.writeFileSync(path.join(cwd, 'untracked.txt'), 'x');

    const code = runUpdateCommand({ ...baseFlags(), cwd, allowDirty: true });
    expect(code).toBe(0);
  }, 30_000);

  it('override strategy writes an overrides entry instead of a root dependency', () => {
    // a transitive vuln: left-pad is NOT a direct dependency here
    fs.writeFileSync(
      path.join(cwd, 'package.json'),
      JSON.stringify({ name: 'fixture', version: '1.0.0' }),
    );
    writeScan({
      fix: { ...writeScanDefaultFix(), strategy: 'override' },
      verification: makeVerification('HIGH'),
    });

    const code = runUpdateCommand({ ...baseFlags(), cwd, allowDirty: true });
    expect(code).toBe(0);
    const pkg = JSON.parse(fs.readFileSync(path.join(cwd, 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
      overrides?: Record<string, string>;
    };
    expect(pkg.overrides).toEqual({ 'left-pad': '1.3.0' });
    expect(pkg.dependencies?.['left-pad']).toBeUndefined();
  }, 30_000);
});

function writeScanDefaultFix() {
  return {
    vulnId: 'GHSA-1',
    pkg: 'left-pad',
    from: '1.0.0',
    to: '1.3.0',
    bumpType: 'minor' as const,
    strategy: 'direct' as const,
    feasible: true,
  };
}

function makeVerification(confidence: 'HIGH' | 'MEDIUM' | 'FAIL' | 'INCONCLUSIVE') {
  return {
    candidate: writeScanDefaultFix(),
    steps: [],
    confidence,
    residualRisks: [],
    runId: 'r1',
    startedAt: '2026-01-01T00:00:00.000Z',
  };
}
