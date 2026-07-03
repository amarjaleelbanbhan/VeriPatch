import { http, HttpResponse, delay } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { BATCH_LIMIT, OsvClient } from '../../src/adapters/osv/client.js';

const BASE = 'https://osv.test/v1';
const server = setupServer();

beforeAll(() => {
  server.listen({ onUnhandledRequest: 'error' });
});
afterEach(() => {
  server.resetHandlers();
});
afterAll(() => {
  server.close();
});

const noSleep = (): Promise<void> => Promise.resolve();

function makeClient(timeoutMs = 5000): OsvClient {
  return new OsvClient({ baseUrl: BASE, timeoutMs, sleepFn: noSleep });
}

interface BatchBody {
  queries: { package: { name: string; ecosystem: string }; version: string }[];
}

describe('OsvClient.queryBatch', () => {
  it('chunks requests at the 1000-query API limit', async () => {
    const received: number[] = [];
    server.use(
      http.post(`${BASE}/querybatch`, async ({ request }) => {
        const body = (await request.json()) as BatchBody;
        received.push(body.queries.length);
        return HttpResponse.json({
          results: body.queries.map(() => ({ vulns: [{ id: 'GHSA-x', modified: 'm' }] })),
        });
      }),
    );

    const queries = Array.from({ length: BATCH_LIMIT + 5 }, (_, i) => ({
      name: `pkg${String(i)}`,
      version: '1.0.0',
    }));
    const r = await makeClient().queryBatch(queries);
    if (!r.ok) throw r.error;
    expect(received).toEqual([BATCH_LIMIT, 5]);
    expect(r.value).toHaveLength(BATCH_LIMIT + 5);
    expect(r.value[0]).toEqual([{ id: 'GHSA-x', modified: 'm' }]);
  });

  it('maps empty results to empty arrays, preserving order', async () => {
    server.use(
      http.post(`${BASE}/querybatch`, () =>
        HttpResponse.json({ results: [{}, { vulns: [{ id: 'GHSA-a' }] }] }),
      ),
    );
    const r = await makeClient().queryBatch([
      { name: 'clean', version: '1.0.0' },
      { name: 'vuln', version: '2.0.0' },
    ]);
    if (!r.ok) throw r.error;
    expect(r.value).toEqual([[], [{ id: 'GHSA-a' }]]);
  });

  it('retries 429 with backoff then succeeds', async () => {
    let calls = 0;
    server.use(
      http.post(`${BASE}/querybatch`, () => {
        calls += 1;
        if (calls <= 2) return new HttpResponse(null, { status: 429 });
        return HttpResponse.json({ results: [{}] });
      }),
    );
    const r = await makeClient().queryBatch([{ name: 'a', version: '1.0.0' }]);
    expect(r.ok).toBe(true);
    expect(calls).toBe(3);
  });

  it('gives up after persistent 429s', async () => {
    server.use(http.post(`${BASE}/querybatch`, () => new HttpResponse(null, { status: 429 })));
    const r = await makeClient().queryBatch([{ name: 'a', version: '1.0.0' }]);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('OSV_RATE_LIMITED');
  });

  it('retries 5xx twice then reports WorldError', async () => {
    let calls = 0;
    server.use(
      http.post(`${BASE}/querybatch`, () => {
        calls += 1;
        return new HttpResponse(null, { status: 503 });
      }),
    );
    const r = await makeClient().queryBatch([{ name: 'a', version: '1.0.0' }]);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe('OSV_SERVER_ERROR');
      expect(r.error.kind).toBe('WorldError');
    }
    expect(calls).toBe(3); // initial + 2 retries
  });

  it('times out slow responses', async () => {
    server.use(
      http.post(`${BASE}/querybatch`, async () => {
        await delay(2_000);
        return HttpResponse.json({ results: [{}] });
      }),
    );
    const r = await makeClient(100).queryBatch([{ name: 'a', version: '1.0.0' }]);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('OSV_TIMEOUT');
  });

  it('rejects result-count mismatches instead of misattributing vulns', async () => {
    server.use(http.post(`${BASE}/querybatch`, () => HttpResponse.json({ results: [] })));
    const r = await makeClient().queryBatch([{ name: 'a', version: '1.0.0' }]);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('OSV_BAD_RESPONSE');
  });
});

describe('OsvClient.getVuln', () => {
  it('fetches advisory JSON by id', async () => {
    server.use(http.get(`${BASE}/vulns/GHSA-abc`, () => HttpResponse.json({ id: 'GHSA-abc' })));
    const r = await makeClient().getVuln('GHSA-abc');
    if (!r.ok) throw r.error;
    expect(r.value).toEqual({ id: 'GHSA-abc' });
  });

  it('URL-encodes hostile ids', async () => {
    let requestedPath = '';
    server.use(
      http.get(`${BASE}/vulns/*`, ({ request }) => {
        requestedPath = new URL(request.url).pathname;
        return HttpResponse.json({ id: 'x' });
      }),
    );
    await makeClient().getVuln('../evil?x=1');
    expect(requestedPath).not.toContain('../');
    expect(requestedPath).toContain('..%2Fevil');
  });
});
