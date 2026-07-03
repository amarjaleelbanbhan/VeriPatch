import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { normalizeOsvAdvisory } from '../../../../src/adapters/osv/schema.js';

const FIXTURES = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  '..',
  'fixtures',
  'osv',
);

function loadFixture(name: string): unknown {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES, name), 'utf8'));
}

describe('normalizeOsvAdvisory', () => {
  it('normalizes a real GHSA advisory', () => {
    const advisory = normalizeOsvAdvisory(loadFixture('GHSA-wf5p-g6vw-rhxx.json'));
    expect(advisory).toBeDefined();
    expect(advisory).toMatchObject({
      id: 'GHSA-wf5p-g6vw-rhxx',
      aliases: ['CVE-2023-45857'],
      modified: '2024-04-17T18:47:41Z',
    });
    // CVSS vector beats the MODERATE database label
    expect(advisory!.severity).toEqual({ cvss: 6.5, label: 'MEDIUM' });
    // introduced 0.8.1 / fixed 1.6.0 → semver window with fixed captured
    expect(advisory!.affected).toEqual([
      { pkg: 'axios', ranges: ['>=0.8.1 <1.6.0'], fixed: '1.6.0' },
    ]);
    expect(advisory!.references).toContain('https://github.com/axios/axios/issues/6006');
  });

  it('converts introduced-0 and open-ended event windows', () => {
    const advisory = normalizeOsvAdvisory({
      id: 'OSV-TEST-1',
      modified: '2026-01-01T00:00:00Z',
      affected: [
        {
          package: { ecosystem: 'npm', name: 'pkg-a' },
          ranges: [
            { type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] },
            { type: 'SEMVER', events: [{ introduced: '3.0.0' }] },
            { type: 'SEMVER', events: [{ introduced: '1.0.0' }, { last_affected: '1.9.9' }] },
          ],
        },
      ],
    });
    expect(advisory!.affected.map((a) => a.ranges[0])).toEqual([
      '<2.0.0',
      '>=3.0.0',
      '>=1.0.0 <=1.9.9',
    ]);
    expect(advisory!.affected[0]!.fixed).toBe('2.0.0');
    expect(advisory!.affected[1]!.fixed).toBeUndefined();
  });

  it('ignores non-npm ecosystems and GIT ranges', () => {
    const advisory = normalizeOsvAdvisory({
      id: 'OSV-TEST-2',
      modified: '2026-01-01T00:00:00Z',
      affected: [
        {
          package: { ecosystem: 'PyPI', name: 'requests' },
          ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }] }],
        },
        {
          package: { ecosystem: 'npm', name: 'lib' },
          ranges: [{ type: 'GIT', events: [{ introduced: 'abc123' }] }],
          versions: ['1.0.0', '1.0.1'],
        },
      ],
    });
    // PyPI entry dropped entirely; GIT range dropped but explicit versions kept.
    expect(advisory!.affected).toEqual([{ pkg: 'lib', ranges: ['1.0.0', '1.0.1'] }]);
  });

  it('sanitizes ANSI injection smuggled through advisory text', () => {
    const advisory = normalizeOsvAdvisory({
      id: `OSV-TEST-3`,
      modified: '2026-01-01T00:00:00Z',
      summary: `bad\u001B[8m hidden\u001B[0m text`,
      affected: [],
    });
    expect(advisory!.summary).toBe('bad hidden text');
  });

  it('returns undefined for garbage and counts stay with the caller', () => {
    expect(normalizeOsvAdvisory(null)).toBeUndefined();
    expect(normalizeOsvAdvisory({ nope: true })).toBeUndefined();
    expect(normalizeOsvAdvisory({ id: '', modified: 'x' })).toBeUndefined();
  });
});
