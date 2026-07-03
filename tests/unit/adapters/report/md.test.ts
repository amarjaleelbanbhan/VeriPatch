import { describe, expect, it } from 'vitest';
import { renderPrComment, renderScanReportMarkdown } from '../../../../src/adapters/report/md.js';
import type { ScanOutput } from '../../../../src/core/models/index.js';

function baseScan(overrides: Partial<ScanOutput> = {}): ScanOutput {
  return {
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
    vulns: [],
    summary: { critical: 0, high: 0, medium: 0, low: 0, verified: 0 },
    ...overrides,
  };
}

describe('renderScanReportMarkdown', () => {
  it('reports a clean scan plainly', () => {
    const md = renderScanReportMarkdown(baseScan());
    expect(md).toContain('No vulnerabilities found');
  });

  it('renders a table row per vulnerability', () => {
    const md = renderScanReportMarkdown(
      baseScan({
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
      }),
    );
    expect(md).toContain('| GHSA\\-1 | HIGH | axios 1\\.5\\.0 |');
    expect(md).toContain('_not verified_');
  });

  it('escapes markdown metacharacters in externally sourced strings', () => {
    const md = renderScanReportMarkdown(
      baseScan({
        vulns: [
          {
            id: '*bold-id*',
            aliases: [],
            pkg: '[pkg](evil)',
            installed: '1.0.0',
            severity: { cvss: 3, label: 'LOW' },
            dev: false,
            paths: [['root', 'pkg']],
            fix: {
              vulnId: '*bold-id*',
              pkg: '[pkg](evil)',
              from: '1.0.0',
              to: '1.0.0',
              bumpType: 'patch',
              strategy: 'direct',
              feasible: false,
              reason: 'no fix',
            },
            verification: null,
          },
        ],
      }),
    );
    expect(md).not.toContain('*bold-id*');
    expect(md).toContain('\\*bold\\-id\\*');
    expect(md).not.toContain('[pkg](evil)');
  });

  it('renders a verification section with escaped step log tails in <details>', () => {
    const md = renderScanReportMarkdown(
      baseScan({
        vulns: [
          {
            id: 'GHSA-2',
            aliases: [],
            pkg: 'axios',
            installed: '1.5.0',
            severity: { cvss: 7.5, label: 'HIGH' },
            dev: false,
            paths: [['root', 'axios']],
            fix: {
              vulnId: 'GHSA-2',
              pkg: 'axios',
              from: '1.5.0',
              to: '1.6.0',
              bumpType: 'minor',
              strategy: 'direct',
              feasible: true,
            },
            verification: {
              candidate: {
                vulnId: 'GHSA-2',
                pkg: 'axios',
                from: '1.5.0',
                to: '1.6.0',
                bumpType: 'minor',
                strategy: 'direct',
                feasible: true,
              },
              steps: [
                {
                  step: 'install',
                  status: 'pass',
                  exitCode: 0,
                  durationMs: 100,
                  logTail: 'added 1 package',
                },
                {
                  step: 'test',
                  status: 'pass',
                  exitCode: 0,
                  durationMs: 200,
                  logTail: 'ok',
                  testCounts: { passed: 3, failed: 0, total: 3 },
                },
              ],
              confidence: 'HIGH',
              residualRisks: ["Confidence reflects the project's own checks."],
              runId: 'r-1',
              startedAt: '2026-01-01T00:00:00.000Z',
            },
          },
        ],
        summary: { critical: 0, high: 1, medium: 0, low: 0, verified: 1 },
      }),
    );
    expect(md).toContain('## GHSA\\-2 — HIGH');
    expect(md).toContain('<details>');
    expect(md).toContain('added 1 package');
    expect(md).toContain('3/3 passed');
    expect(md).toContain('Residual risks');
  });
});

describe('renderPrComment', () => {
  it('wraps the report body with a sticky-comment marker', () => {
    const comment = renderPrComment(baseScan());
    expect(comment).toContain('<!-- veripatch-report -->');
    expect(comment).toContain('No vulnerabilities found');
  });
});
