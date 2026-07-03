import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AdvisoryCache } from '../../src/adapters/cache/db.js';
import { OsvClient } from '../../src/adapters/osv/client.js';
import { OsvAdvisorySource } from '../../src/adapters/osv/index.js';
import type { DepNode } from '../../src/core/models/index.js';

const BASE = 'https://osv.test/v1';
const server = setupServer();

const FIXTURE = JSON.parse(
  fs.readFileSync(
    path.join(
      path.dirname(fileURLToPath(import.meta.url)),
      '..',
      'fixtures',
      'osv',
      'GHSA-wf5p-g6vw-rhxx.json',
    ),
    'utf8',
  ),
) as Record<string, unknown>;

beforeAll(() => {
  server.listen({ onUnhandledRequest: 'error' });
});
afterEach(() => {
  server.resetHandlers();
});
afterAll(() => {
  server.close();
});

let tmpDir: string;
let cache: AdvisoryCache;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veripatch-source-'));
  const opened = AdvisoryCache.open(tmpDir);
  if (!opened.ok) throw opened.error;
  cache = opened.value;
});

afterEach(() => {
  cache.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function node(name: string, version: string): DepNode {
  return { name, version, paths: [['root', name]], dev: false, direct: true };
}

function makeSource(now: number): OsvAdvisorySource {
  return new OsvAdvisorySource({
    client: new OsvClient({ baseUrl: BASE, sleepFn: () => Promise.resolve() }),
    cache,
    cacheTtlHours: 24,
    now: () => now,
  });
}

function happyHandlers(counters: { batch: number; detail: number }): void {
  server.use(
    http.post(`${BASE}/querybatch`, () => {
      counters.batch += 1;
      return HttpResponse.json({
        results: [{ vulns: [{ id: 'GHSA-wf5p-g6vw-rhxx', modified: 'm' }] }],
      });
    }),
    http.get(`${BASE}/vulns/GHSA-wf5p-g6vw-rhxx`, () => {
      counters.detail += 1;
      return HttpResponse.json(FIXTURE);
    }),
  );
}

describe('OsvAdvisorySource', () => {
  it('fetches, validates, and returns advisories on a cold cache', async () => {
    const counters = { batch: 0, detail: 0 };
    happyHandlers(counters);

    const r = await makeSource(1_000_000).getAdvisories([node('axios', '1.5.0')]);
    if (!r.ok) throw r.error;
    expect(r.value.stale).toBe(false);
    expect(r.value.dataErrors).toBe(0);
    expect(r.value.advisories).toHaveLength(1);
    expect(r.value.advisories[0]!.id).toBe('GHSA-wf5p-g6vw-rhxx');
    expect(counters).toEqual({ batch: 1, detail: 1 });
  });

  it('serves a warm cache without touching the network', async () => {
    const counters = { batch: 0, detail: 0 };
    happyHandlers(counters);
    const source = makeSource(1_000_000);
    await source.getAdvisories([node('axios', '1.5.0')]);

    // Second call: same TTL window, zero additional requests.
    const r = await source.getAdvisories([node('axios', '1.5.0')]);
    if (!r.ok) throw r.error;
    expect(r.value.advisories).toHaveLength(1);
    expect(counters).toEqual({ batch: 1, detail: 1 });
  });

  it('refreshes expired entries when online', async () => {
    const counters = { batch: 0, detail: 0 };
    happyHandlers(counters);
    await makeSource(1_000_000).getAdvisories([node('axios', '1.5.0')]);

    // 25h later: TTL (24h) exceeded → both endpoints hit again.
    const r = await makeSource(1_000_000 + 25 * 3600).getAdvisories([node('axios', '1.5.0')]);
    if (!r.ok) throw r.error;
    expect(r.value.stale).toBe(false);
    expect(counters).toEqual({ batch: 2, detail: 2 });
  });

  it('serves stale data flagged stale:true when offline', async () => {
    const counters = { batch: 0, detail: 0 };
    happyHandlers(counters);
    await makeSource(1_000_000).getAdvisories([node('axios', '1.5.0')]);

    server.resetHandlers(
      http.post(`${BASE}/querybatch`, () => HttpResponse.error()),
      http.get(`${BASE}/vulns/:id`, () => HttpResponse.error()),
    );

    const r = await makeSource(1_000_000 + 25 * 3600).getAdvisories([node('axios', '1.5.0')]);
    if (!r.ok) throw r.error;
    expect(r.value.stale).toBe(true);
    expect(r.value.advisories).toHaveLength(1);
  });

  it('refuses to fake "no vulns" for never-cached packages while offline', async () => {
    server.use(
      http.post(`${BASE}/querybatch`, () => HttpResponse.error()),
      http.get(`${BASE}/vulns/:id`, () => HttpResponse.error()),
    );
    const r = await makeSource(1_000_000).getAdvisories([node('never-seen', '1.0.0')]);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe('ADVISORIES_UNAVAILABLE');
      expect(r.error.kind).toBe('WorldError');
    }
  });

  it('drops invalid advisories and counts them as dataErrors', async () => {
    server.use(
      http.post(`${BASE}/querybatch`, () =>
        HttpResponse.json({
          results: [{ vulns: [{ id: 'GHSA-broken' }, { id: 'GHSA-wf5p-g6vw-rhxx' }] }],
        }),
      ),
      // one endpoint returns garbage, the other a valid advisory
      http.get(`${BASE}/vulns/GHSA-broken`, () => HttpResponse.json({ totally: 'wrong' })),
      http.get(`${BASE}/vulns/GHSA-wf5p-g6vw-rhxx`, () => HttpResponse.json(FIXTURE)),
    );

    const r = await makeSource(1_000_000).getAdvisories([node('axios', '1.5.0')]);
    if (!r.ok) throw r.error;
    expect(r.value.dataErrors).toBe(1);
    expect(r.value.advisories.map((a) => a.id)).toEqual(['GHSA-wf5p-g6vw-rhxx']);
  });
});
