import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AdvisoryCache, CACHE_FILE_NAME } from '../../../../src/adapters/cache/db.js';

let tmpDir: string;
let cache: AdvisoryCache;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veripatch-cache-'));
  const opened = AdvisoryCache.open(tmpDir);
  if (!opened.ok) throw opened.error;
  cache = opened.value;
});

afterEach(() => {
  cache.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('AdvisoryCache', () => {
  it('roundtrips package advisory ids', () => {
    cache.setPkgAdvisoryIds('axios@1.5.0', ['GHSA-1', 'GHSA-2'], 1000);
    expect(cache.getPkgAdvisoryIds('axios@1.5.0')).toEqual({
      ids: ['GHSA-1', 'GHSA-2'],
      fetchedAt: 1000,
    });
    expect(cache.getPkgAdvisoryIds('missing@1.0.0')).toBeUndefined();
  });

  it('upserts on conflict', () => {
    cache.setPkgAdvisoryIds('a@1.0.0', ['GHSA-1'], 1000);
    cache.setPkgAdvisoryIds('a@1.0.0', ['GHSA-9'], 2000);
    expect(cache.getPkgAdvisoryIds('a@1.0.0')).toEqual({ ids: ['GHSA-9'], fetchedAt: 2000 });
  });

  it('roundtrips advisories', () => {
    cache.setAdvisory('GHSA-1', '{"id":"GHSA-1"}', '2026-01-01T00:00:00Z', 1234);
    expect(cache.getAdvisory('GHSA-1')).toEqual({
      json: '{"id":"GHSA-1"}',
      modified: '2026-01-01T00:00:00Z',
      fetchedAt: 1234,
    });
  });

  it('migrations are idempotent — reopening the same file works', () => {
    cache.setPkgAdvisoryIds('a@1.0.0', ['GHSA-1'], 1000);
    cache.close();

    const reopened = AdvisoryCache.open(tmpDir);
    if (!reopened.ok) throw reopened.error;
    cache = reopened.value;
    expect(cache.getPkgAdvisoryIds('a@1.0.0')).toEqual({ ids: ['GHSA-1'], fetchedAt: 1000 });
  });

  it('stats and clear', () => {
    cache.setPkgAdvisoryIds('a@1.0.0', ['GHSA-1'], 1000);
    cache.setAdvisory('GHSA-1', '{}', 'm', 500);
    cache.setAdvisory('GHSA-2', '{}', 'm', 900);

    const stats = cache.stats();
    expect(stats.pkgRows).toBe(1);
    expect(stats.advisoryRows).toBe(2);
    expect(stats.oldestFetchedAt).toBe(500);
    expect(stats.newestFetchedAt).toBe(900);
    expect(stats.dbBytes).toBeGreaterThan(0);

    cache.clear();
    expect(cache.stats().pkgRows).toBe(0);
    expect(cache.stats().advisoryRows).toBe(0);
  });

  it('sets 0600 permissions on POSIX systems', () => {
    if (process.platform === 'win32') return; // POSIX modes are advisory on Windows
    const mode = fs.statSync(path.join(tmpDir, CACHE_FILE_NAME)).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it('open failure yields WorldError, not a throw', () => {
    const filePath = path.join(tmpDir, 'blocking-file');
    fs.writeFileSync(filePath, 'not a directory');
    const r = AdvisoryCache.open(path.join(filePath, 'nested'));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.kind).toBe('WorldError');
  });
});
