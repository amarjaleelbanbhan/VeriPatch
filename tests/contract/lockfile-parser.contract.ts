import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { DepGraphSchema } from '../../src/core/models/index.js';
import type { LockfileParser } from '../../src/core/ports.js';

const FIXTURES = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'fixtures',
  'lockfiles',
);

/**
 * Behavioral contract every LockfileParser implementation must satisfy
 * (blueprint §5.3). Run it from a *.test.ts per implementation.
 */
export function runLockfileParserContract(name: string, makeParser: () => LockfileParser): void {
  describe(`LockfileParser contract: ${name}`, () => {
    it('returns a schema-valid DepGraph for a valid project', () => {
      const r = makeParser().parse(path.join(FIXTURES, 'v3-nested'));
      expect(r.ok).toBe(true);
      if (r.ok) expect(() => DepGraphSchema.parse(r.value)).not.toThrow();
    });

    it('never throws on hostile input — returns err instead', () => {
      const parser = makeParser();
      for (const fixture of ['corrupt', 'hostile-name', 'v1-legacy', 'does-not-exist']) {
        const r = parser.parse(path.join(FIXTURES, fixture));
        expect(r.ok, fixture).toBe(false);
        if (!r.ok) {
          expect(r.error.kind, fixture).toBe('UserError');
          expect(r.error.code.length, fixture).toBeGreaterThan(0);
        }
      }
    });

    it('flags degraded output and disables nothing silently', () => {
      const r = makeParser().parse(path.join(FIXTURES, 'degraded-project'));
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.value.degraded).toBe(true);
        expect(r.value.lockfileVersion).toBeNull();
      }
    });

    it('is deterministic — two parses agree', () => {
      const parser = makeParser();
      const a = parser.parse(path.join(FIXTURES, 'v3-nested'));
      const b = parser.parse(path.join(FIXTURES, 'v3-nested'));
      expect(a).toEqual(b);
    });
  });
}
