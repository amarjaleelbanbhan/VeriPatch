import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, beforeAll } from 'vitest';
import { AdvisoryCache } from '../../src/adapters/cache/db.js';
import { OsvClient } from '../../src/adapters/osv/client.js';
import { OsvAdvisorySource } from '../../src/adapters/osv/index.js';
import { runAdvisorySourceContract } from './advisory-source.contract.js';

const BASE = 'https://osv-contract.test/v1';

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

const server = setupServer(
  http.post(`${BASE}/querybatch`, () =>
    HttpResponse.json({ results: [{ vulns: [{ id: 'GHSA-wf5p-g6vw-rhxx' }] }] }),
  ),
  http.get(`${BASE}/vulns/GHSA-wf5p-g6vw-rhxx`, () => HttpResponse.json(FIXTURE)),
);

const cleanups: (() => void)[] = [];

beforeAll(() => {
  server.listen({ onUnhandledRequest: 'error' });
});
afterAll(() => {
  server.close();
  for (const cleanup of cleanups) cleanup();
});

runAdvisorySourceContract('OsvAdvisorySource', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veripatch-contract-'));
  const opened = AdvisoryCache.open(tmpDir);
  if (!opened.ok) throw opened.error;
  const cache = opened.value;
  cleanups.push(() => {
    cache.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  return Promise.resolve({
    source: new OsvAdvisorySource({
      client: new OsvClient({ baseUrl: BASE }),
      cache,
      cacheTtlHours: 24,
    }),
    vulnerableNode: {
      name: 'axios',
      version: '1.5.0',
      paths: [['root', 'axios']],
      dev: false,
      direct: true,
    },
  });
});
