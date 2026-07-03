import { describe, expect, it } from 'vitest';
import { AdvisorySchema, type DepNode } from '../../src/core/models/index.js';
import type { AdvisorySource } from '../../src/core/ports.js';

/**
 * Behavioral contract every AdvisorySource implementation must satisfy
 * (blueprint §5.3). The factory receives nodes known to have at least one
 * advisory in the implementation's data source.
 */
export function runAdvisorySourceContract(
  name: string,
  setup: () => Promise<{ source: AdvisorySource; vulnerableNode: DepNode }>,
): void {
  describe(`AdvisorySource contract: ${name}`, () => {
    it('returns schema-valid advisories with stale/dataErrors bookkeeping', async () => {
      const { source, vulnerableNode } = await setup();
      const r = await source.getAdvisories([vulnerableNode]);
      expect(r.ok).toBe(true);
      if (!r.ok) return;

      expect(typeof r.value.stale).toBe('boolean');
      expect(r.value.dataErrors).toBeGreaterThanOrEqual(0);
      expect(r.value.advisories.length).toBeGreaterThan(0);
      for (const advisory of r.value.advisories) {
        expect(() => AdvisorySchema.parse(advisory)).not.toThrow();
      }
    });

    it('handles an empty node list without touching the world', async () => {
      const { source } = await setup();
      const r = await source.getAdvisories([]);
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.value.advisories).toEqual([]);
        expect(r.value.dataErrors).toBe(0);
      }
    });
  });
}
