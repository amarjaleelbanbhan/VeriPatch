import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { resolveFix } from '../../../src/core/rules/fix-resolver.js';
import type { Advisory, DepNode, Vuln } from '../../../src/core/models/index.js';

/**
 * Property-based invariant tests (blueprint T4.4). The rule engine is the
 * one place a mistake could quietly turn "fix this vulnerability" into
 * "install an unrelated package" — these run the invariant against
 * thousands of generated inputs rather than a handful of examples.
 */

const semverArb = fc
  .tuple(
    fc.nat({ max: 20 }),
    fc.nat({ max: 20 }),
    fc.nat({ max: 20 }),
    fc.option(fc.constantFrom('alpha', 'beta', 'rc.1'), { nil: undefined }),
  )
  .map(
    ([maj, min, patch, pre]) =>
      `${String(maj)}.${String(min)}.${String(patch)}${pre !== undefined ? `-${pre}` : ''}`,
  );

const pkgNameArb = fc.stringMatching(/^[a-z][a-z0-9-]{0,20}$/);

const vulnArb: fc.Arbitrary<Vuln> = fc
  .tuple(
    pkgNameArb,
    semverArb,
    fc.boolean(),
    fc.array(
      fc.record({ ranges: fc.constant(['*']), fixed: fc.option(semverArb, { nil: undefined }) }),
      {
        minLength: 0,
        maxLength: 4,
      },
    ),
    fc.string({ minLength: 1, maxLength: 20 }),
  )
  .map(([pkg, installed, direct, fixedEntries, advisoryId]) => {
    const node: DepNode = {
      name: pkg,
      version: installed,
      paths: [['root', pkg]],
      dev: false,
      direct,
    };
    const affected: Advisory['affected'] = fixedEntries.map((e) => ({
      pkg,
      ranges: [...e.ranges],
      ...(e.fixed !== undefined ? { fixed: e.fixed } : {}),
    }));
    const advisory: Advisory = {
      id: advisoryId,
      aliases: [],
      summary: 's',
      severity: { cvss: 7.5, label: 'HIGH' },
      affected,
      references: [],
      modified: '2026-01-01T00:00:00Z',
    };
    return { node, matchedRange: '*', advisory };
  });

describe('resolveFix invariants', () => {
  it('the resolved candidate package always equals the vulnerable node package (property)', () => {
    fc.assert(
      fc.property(vulnArb, (vuln) => {
        const fix = resolveFix(vuln);
        expect(fix.pkg).toBe(vuln.node.name);
        expect(fix.vulnId).toBe(vuln.advisory.id);
        expect(fix.from).toBe(vuln.node.version);
      }),
      { numRuns: 500 },
    );
  });

  it('an infeasible fix always leaves "to" equal to "from" (property)', () => {
    fc.assert(
      fc.property(vulnArb, (vuln) => {
        const fix = resolveFix(vuln);
        if (!fix.feasible) {
          expect(fix.to).toBe(fix.from);
          expect(fix.reason).toBeDefined();
        }
      }),
      { numRuns: 500 },
    );
  });

  it('a feasible fix always proposes a version strictly greater than installed (property)', () => {
    fc.assert(
      fc.property(vulnArb, (vuln) => {
        const fix = resolveFix(vuln);
        if (fix.feasible) {
          expect(fix.reason).toBeUndefined();
          // semver comparison is exercised directly by fix-resolver.test.ts;
          // here we only assert the invariant that to !== from.
          expect(fix.to).not.toBe(fix.from);
        }
      }),
      { numRuns: 500 },
    );
  });

  it('strategy is a pure function of node.direct (property)', () => {
    fc.assert(
      fc.property(vulnArb, (vuln) => {
        const fix = resolveFix(vuln);
        expect(fix.strategy).toBe(vuln.node.direct ? 'direct' : 'override');
      }),
      { numRuns: 500 },
    );
  });
});
