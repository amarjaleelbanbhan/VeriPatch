import { describe, expect, it } from 'vitest';
import { matchVulnerabilities } from '../../src/core/rules/match.js';
import { resolveFix } from '../../src/core/rules/fix-resolver.js';
import { rankVulnerabilities } from '../../src/core/rules/severity.js';
import type { Advisory, DepNode } from '../../src/core/models/index.js';

/**
 * Perf budget for the pure rule-engine pipeline (blueprint M5/T5.6, metric
 * M1: scan <15s warm on a 1,500-dep project). This isolates match + rank +
 * fix resolution — parsing and network I/O are covered elsewhere — so the
 * budget here is a small slice of the full 15s NFR, not the whole thing.
 */
const DEP_COUNT = 1500;
const BUDGET_MS = 2000;

function buildFixture(): { nodes: DepNode[]; advisories: Advisory[] } {
  const nodes: DepNode[] = [];
  const advisories: Advisory[] = [];
  for (let i = 0; i < DEP_COUNT; i++) {
    const name = `pkg-${String(i)}`;
    nodes.push({
      name,
      version: '1.0.0',
      paths: [['root', name]],
      dev: i % 5 === 0,
      direct: i % 3 === 0,
    });
    // Roughly a fifth of packages have a real, fixable vulnerability.
    if (i % 5 === 0) {
      advisories.push({
        id: `GHSA-bench-${String(i)}`,
        aliases: [],
        summary: 'bench fixture',
        severity: { cvss: 7.5, label: 'HIGH' },
        affected: [{ pkg: name, ranges: ['<2.0.0'], fixed: '2.0.0' }],
        references: [],
        modified: '2026-01-01T00:00:00Z',
      });
    }
  }
  return { nodes, advisories };
}

describe('rule engine perf budget', () => {
  it(`matches, ranks, and resolves fixes for ${String(DEP_COUNT)} deps under ${String(BUDGET_MS)}ms`, () => {
    const { nodes, advisories } = buildFixture();

    const start = performance.now();
    const vulns = matchVulnerabilities(nodes, advisories);
    const ranked = rankVulnerabilities(vulns, {
      severityThreshold: 'low',
      ignore: [],
      includeDevDeps: true,
    });
    for (const vuln of ranked) resolveFix(vuln);
    const elapsed = performance.now() - start;

    expect(ranked.length).toBe(DEP_COUNT / 5);
    expect(elapsed).toBeLessThan(BUDGET_MS);
  });
});
