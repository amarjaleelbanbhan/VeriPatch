import { describe, expect, it } from 'vitest';
import { renderCacheStats } from '../../../../src/cli/commands/cache.js';
import type { CacheStats } from '../../../../src/adapters/cache/db.js';

describe('renderCacheStats', () => {
  it('renders row counts and size', () => {
    const stats: CacheStats = {
      pkgRows: 12,
      advisoryRows: 40,
      dbBytes: 20_480,
      oldestFetchedAt: null,
      newestFetchedAt: null,
    };
    const out = renderCacheStats(stats);
    expect(out).toContain('Packages cached: 12');
    expect(out).toContain('Advisories cached: 40');
    expect(out).toContain('Cache size: 20 KB');
    expect(out).not.toContain('Oldest entry');
  });

  it('renders a staleness histogram when timestamps are present', () => {
    const now = Math.floor(Date.now() / 1000);
    const stats: CacheStats = {
      pkgRows: 1,
      advisoryRows: 1,
      dbBytes: 100,
      oldestFetchedAt: now - 48 * 3600,
      newestFetchedAt: now - 3600,
    };
    const out = renderCacheStats(stats);
    expect(out).toContain('Oldest entry: 48h old');
    expect(out).toMatch(/Newest entry: (0h|<1h|1h) old/);
  });
});
