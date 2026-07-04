import { describe, expect, it } from 'vitest';
import { renderScan } from '../../../src/cli/render.js';
import type { RenderOptions } from '../../../src/cli/render.js';
import type {
  ScanOutput,
  ScannedVuln,
  VerificationResult,
} from '../../../src/core/models/index.js';

const ESC = String.fromCharCode(27);
const NL = String.fromCharCode(10);

function baseOutput(overrides: Partial<ScanOutput> = {}): ScanOutput {
  return {
    schemaVersion: 1,
    tool: { name: 'VeriPatch', version: '0.0.0' },
    generatedAt: '2026-01-01T00:00:00.000Z',
    scan: {
      lockfileVersion: 3,
      packageManager: 'npm',
      degraded: false,
      totalDeps: 10,
      dataErrors: 0,
      stale: false,
    },
    vulns: [],
    summary: { critical: 0, high: 0, medium: 0, low: 0, verified: 0 },
    ...overrides,
  };
}

function ui(overrides: Partial<RenderOptions> = {}): RenderOptions {
  return { color: false, unicode: true, width: 76, ...overrides };
}

const noColor = ui();

function vuln(overrides: Partial<ScannedVuln> = {}): ScannedVuln {
  return {
    id: 'GHSA-1',
    aliases: ['CVE-2026-1'],
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
    ...overrides,
  };
}

function verificationResult(overrides: Partial<VerificationResult> = {}): VerificationResult {
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
    steps: [
      { step: 'copy', status: 'pass', durationMs: 10, logTail: '' },
      { step: 'apply', status: 'pass', durationMs: 10, logTail: '' },
      { step: 'install', status: 'pass', durationMs: 10, logTail: '' },
      { step: 'rescan', status: 'pass', durationMs: 10, logTail: '' },
      { step: 'build', status: 'pass', durationMs: 10, logTail: '' },
      { step: 'test', status: 'pass', durationMs: 10, logTail: '' },
    ],
    confidence: 'HIGH',
    residualRisks: [],
    runId: 'run-1',
    startedAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

describe('renderScan — brand header', () => {
  it('always shows the wordmark and tagline', () => {
    const out = renderScan(baseOutput(), noColor);
    expect(out).toContain('VeriPatch');
    expect(out).toContain('prove the fix is safe');
  });
});

describe('renderScan — no vulnerabilities', () => {
  it('prints a clean success card with the scanned package count', () => {
    const out = renderScan(baseOutput(), noColor);
    expect(out).toContain('No known vulnerabilities found');
    expect(out).toContain('10 packages scanned');
    expect(out).toContain('npm');
  });
});

describe('renderScan — with unverified vulnerabilities', () => {
  const output = baseOutput({
    scan: {
      lockfileVersion: 3,
      packageManager: 'npm',
      degraded: false,
      totalDeps: 10,
      dataErrors: 0,
      stale: false,
    },
    vulns: [vuln()],
    summary: { critical: 0, high: 1, medium: 0, low: 0, verified: 0 },
  });

  it('renders the project summary card with real counts', () => {
    const out = renderScan(output, noColor);
    expect(out).toContain('Project Summary');
    expect(out).toContain('Package manager');
    expect(out).toContain('Packages scanned');
    expect(out).toContain('10');
    expect(out).toContain('Vulnerabilities');
  });

  it('renders the top-vulnerabilities table with package, severity, versions', () => {
    const out = renderScan(output, noColor);
    expect(out).toContain('Top Vulnerabilities');
    expect(out).toContain('axios');
    expect(out).toContain('HIGH');
    expect(out).toContain('1.5.0');
    expect(out).toContain('1.6.0');
    expect(out).toContain('not verified');
  });

  it('never fabricates a verification section for a vuln that was never verified', () => {
    const out = renderScan(output, noColor);
    expect(out).not.toContain('Verification');
    expect(out).not.toContain('Upgrade verified');
  });

  it('recommends `veripatch verify` when nothing is verified yet', () => {
    const out = renderScan(output, noColor);
    expect(out).toContain('veripatch verify GHSA-1');
  });

  it('shows a dash instead of a bump for infeasible fixes, with the real reason', () => {
    const infeasible = baseOutput({
      vulns: [
        vuln({
          fix: {
            vulnId: 'GHSA-1',
            pkg: 'axios',
            from: '1.5.0',
            to: '1.5.0',
            bumpType: 'patch',
            strategy: 'direct',
            feasible: false,
            reason: 'No fixed version has been published for this advisory.',
          },
        }),
      ],
    });
    const out = renderScan(infeasible, noColor);
    expect(out).toContain('axios');
    expect(out).not.toContain('1.5.0→1.5.0');
  });
});

describe('renderScan — with a real verified fix', () => {
  const output = baseOutput({
    vulns: [vuln({ verification: verificationResult() })],
    summary: { critical: 0, high: 1, medium: 0, low: 0, verified: 1 },
  });

  it('shows verified status in the table', () => {
    const out = renderScan(output, noColor);
    expect(out).toContain('verified');
  });

  it('explains the verdict using only real step outcomes', () => {
    const out = renderScan(output, noColor);
    expect(out).toContain('Verification');
    expect(out).toContain('Upgrade verified');
    expect(out).toContain('Build succeeded');
    expect(out).toContain('Tests passed');
  });

  it('final summary recommends `veripatch update` with a real risk-reduction sentence', () => {
    const out = renderScan(output, noColor);
    expect(out).toContain('verified fix');
    expect(out).toContain('Removes');
    expect(out).toContain('1 high');
    expect(out).toContain('veripatch update GHSA-1');
  });
});

describe('renderScan — a verification that failed', () => {
  const output = baseOutput({
    vulns: [
      vuln({
        verification: verificationResult({
          confidence: 'FAIL',
          steps: [
            { step: 'copy', status: 'pass', durationMs: 10, logTail: '' },
            { step: 'apply', status: 'pass', durationMs: 10, logTail: '' },
            { step: 'install', status: 'pass', durationMs: 10, logTail: '' },
            { step: 'rescan', status: 'fail', durationMs: 10, logTail: '' },
            { step: 'build', status: 'skipped', durationMs: 0, logTail: '' },
            { step: 'test', status: 'skipped', durationMs: 0, logTail: '' },
          ],
        }),
      }),
    ],
  });

  it('says manual review is required, with the real failing step named', () => {
    const out = renderScan(output, noColor);
    expect(out).toContain('Requires manual review');
    expect(out).toContain('rescan step failed');
    expect(out).not.toContain('Tests passed');
  });
});

describe('renderScan — banners', () => {
  it('shows a degraded banner', () => {
    const out = renderScan(
      baseOutput({
        scan: {
          lockfileVersion: null,
          packageManager: null,
          degraded: true,
          totalDeps: 3,
          dataErrors: 0,
          stale: false,
        },
      }),
      noColor,
    );
    expect(out).toContain('degraded');
    expect(out).toContain('verify disabled');
  });

  it('shows a stale-cache banner', () => {
    const out = renderScan(
      baseOutput({
        scan: {
          lockfileVersion: 3,
          packageManager: 'npm',
          degraded: false,
          totalDeps: 3,
          dataErrors: 0,
          stale: true,
        },
      }),
      noColor,
    );
    expect(out).toContain('offline');
  });

  it('shows a data-errors banner', () => {
    const out = renderScan(
      baseOutput({
        scan: {
          lockfileVersion: 3,
          packageManager: 'npm',
          degraded: false,
          totalDeps: 3,
          dataErrors: 2,
          stale: false,
        },
      }),
      noColor,
    );
    expect(out).toContain('2 advisories dropped');
  });
});

describe('renderScan — color handling', () => {
  const output = baseOutput({ vulns: [vuln()] });

  it('contains no raw ANSI codes when color is disabled', () => {
    const out = renderScan(output, ui({ color: false }));
    expect(out.includes(ESC)).toBe(false);
  });

  it('emits ANSI codes when color is enabled', () => {
    const out = renderScan(output, ui({ color: true }));
    expect(out.includes(ESC)).toBe(true);
  });

  it('keeps table columns aligned even when a cell is colored (visible-width padding)', () => {
    const twoRows = baseOutput({
      vulns: [vuln(), vuln({ id: 'GHSA-2', pkg: 'lodash', severity: { cvss: 3, label: 'LOW' } })],
    });
    const out = renderScan(twoRows, ui({ color: true }));
    const lines = out.split(NL).filter((l) => l.includes('axios') || l.includes('lodash'));
    const ansiPattern = new RegExp(ESC + '\\[[0-9;]*m', 'g');
    const visibleLengths = lines.map((l) => l.replace(ansiPattern, '').length);
    expect(new Set(visibleLengths).size).toBe(1);
  });

  it('regression: a severity badge that fits its column keeps its color — every cell passes through truncateVisible on every render, and the common (non-truncating) case must not silently strip it', () => {
    const out = renderScan(output, ui({ color: true }));
    const severityLine = out.split(NL).find((l) => l.includes('HIGH'));
    expect(severityLine).toContain(ESC);
  });

  it('regression: the final summary box keeps its color (boxes share the same cell-rendering path as tables)', () => {
    const verified = baseOutput({ vulns: [vuln({ verification: verificationResult() })] });
    const out = renderScan(verified, ui({ color: true }));
    const summaryLine = out.split(NL).find((l) => l.includes('verified fix'));
    expect(summaryLine).toContain(ESC);
  });
});

describe('renderScan — ASCII fallback', () => {
  it('never emits unicode symbols when unicode is unsupported', () => {
    const out = renderScan(baseOutput({ vulns: [vuln()] }), ui({ unicode: false }));
    expect(out).not.toMatch(/[✓✗⚠◆›╭╮╰╯│─]/u);
  });
});
