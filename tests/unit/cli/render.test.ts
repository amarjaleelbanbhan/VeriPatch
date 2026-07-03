import { describe, expect, it } from 'vitest';
import { renderScan } from '../../../src/cli/render.js';
import type { ScanOutput } from '../../../src/core/models/index.js';

function baseOutput(overrides: Partial<ScanOutput> = {}): ScanOutput {
  return {
    schemaVersion: 1,
    tool: { name: 'VeriPatch', version: '0.0.0' },
    generatedAt: '2026-01-01T00:00:00.000Z',
    scan: { lockfileVersion: 3, degraded: false, totalDeps: 10, dataErrors: 0, stale: false },
    vulns: [],
    summary: { critical: 0, high: 0, medium: 0, low: 0, verified: 0 },
    ...overrides,
  };
}

const noColor = { color: false };

describe('renderScan — no vulnerabilities', () => {
  it('prints a clean success message', () => {
    const out = renderScan(baseOutput(), noColor);
    expect(out).toContain('No vulnerabilities found');
  });
});

describe('renderScan — with vulnerabilities', () => {
  const output = baseOutput({
    vulns: [
      {
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
      },
    ],
    summary: { critical: 0, high: 1, medium: 0, low: 0, verified: 0 },
  });

  it('renders a table with id, severity, package bump, and a verify hint', () => {
    const out = renderScan(output, noColor);
    expect(out).toContain('GHSA-1');
    expect(out).toContain('HIGH');
    expect(out).toContain('axios 1.5.0→1.6.0');
    expect(out).toContain('minor');
    expect(out).toContain('direct');
    expect(out).toContain('veripatch verify <id>');
    expect(out).toContain('1 vulnerability found');
  });

  it('renders infeasible fixes with their reason instead of a bump', () => {
    const infeasible = baseOutput({
      vulns: [
        {
          ...output.vulns[0]!,
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
        },
      ],
    });
    const out = renderScan(infeasible, noColor);
    expect(out).toContain('No fixed version has been published');
    expect(out).not.toContain('→');
  });

  it('contains no raw ANSI codes when color is disabled', () => {
    const out = renderScan(output, noColor);
    // eslint-disable-next-line no-control-regex -- intentionally probing for the ESC byte
    expect(out).not.toMatch(/\u001B\[/);
  });

  it('emits ANSI codes when color is enabled', () => {
    const out = renderScan(output, { color: true });
    // eslint-disable-next-line no-control-regex -- intentionally probing for the ESC byte
    expect(out).toMatch(/\u001B\[/);
  });
});

describe('renderScan — banners', () => {
  it('shows a degraded banner', () => {
    const out = renderScan(
      baseOutput({
        scan: { lockfileVersion: null, degraded: true, totalDeps: 3, dataErrors: 0, stale: false },
      }),
      noColor,
    );
    expect(out).toContain('degraded');
    expect(out).toContain('verify disabled');
  });

  it('shows a stale-cache banner', () => {
    const out = renderScan(
      baseOutput({
        scan: { lockfileVersion: 3, degraded: false, totalDeps: 3, dataErrors: 0, stale: true },
      }),
      noColor,
    );
    expect(out).toContain('offline');
  });

  it('shows a data-errors banner', () => {
    const out = renderScan(
      baseOutput({
        scan: { lockfileVersion: 3, degraded: false, totalDeps: 3, dataErrors: 2, stale: false },
      }),
      noColor,
    );
    expect(out).toContain('2 advisories dropped');
  });
});
