import { AppError } from '../../shared/errors.js';
import { err, ok, type Result } from '../../shared/result.js';
import { OsvQueryBatchResponseSchema } from './schema.js';

/**
 * Thin OSV.dev HTTP client (blueprint §5.1):
 * - querybatch chunked at 1000 queries per call
 * - 10s timeout per call
 * - 429 → exponential backoff with jitter, max 3 retries
 * - 5xx → retry ×2, then WorldError
 */

export const OSV_BASE_URL = 'https://api.osv.dev/v1';
export const BATCH_LIMIT = 1000;
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_429_RETRIES = 3;
const MAX_5XX_RETRIES = 2;

export interface OsvClientOptions {
  baseUrl?: string;
  timeoutMs?: number;
  fetchFn?: typeof fetch;
  /** Test seam — replaces real backoff sleeps. */
  sleepFn?: (ms: number) => Promise<void>;
}

export interface PackageQuery {
  name: string;
  version: string;
}

export interface VulnRef {
  id: string;
  modified?: string;
}

const defaultSleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

export class OsvClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchFn: typeof fetch;
  private readonly sleepFn: (ms: number) => Promise<void>;

  constructor(options: OsvClientOptions = {}) {
    this.baseUrl = options.baseUrl ?? OSV_BASE_URL;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchFn = options.fetchFn ?? fetch;
    this.sleepFn = options.sleepFn ?? defaultSleep;
  }

  /** Vulnerability id refs per query, aligned with the input order. */
  async queryBatch(queries: PackageQuery[]): Promise<Result<VulnRef[][]>> {
    const results: VulnRef[][] = [];
    for (let offset = 0; offset < queries.length; offset += BATCH_LIMIT) {
      const chunk = queries.slice(offset, offset + BATCH_LIMIT);
      const body = {
        queries: chunk.map((q) => ({
          package: { name: q.name, ecosystem: 'npm' },
          version: q.version,
        })),
      };
      const response = await this.request('/querybatch', {
        method: 'POST',
        body: JSON.stringify(body),
      });
      if (!response.ok) return response;

      const parsed = OsvQueryBatchResponseSchema.safeParse(response.value);
      if (!parsed.success) {
        return err(AppError.world('OSV_BAD_RESPONSE', 'OSV querybatch response failed validation'));
      }
      if (parsed.data.results.length !== chunk.length) {
        return err(AppError.world('OSV_BAD_RESPONSE', 'OSV querybatch result count mismatch'));
      }
      for (const result of parsed.data.results) {
        results.push(
          (result.vulns ?? []).map((v) => ({
            id: v.id,
            ...(v.modified !== undefined ? { modified: v.modified } : {}),
          })),
        );
      }
    }
    return ok(results);
  }

  /** Full advisory JSON by id (validated later by the normalizer). */
  async getVuln(id: string): Promise<Result<unknown>> {
    return this.request(`/vulns/${encodeURIComponent(id)}`, { method: 'GET' });
  }

  private async request(
    path: string,
    init: { method: string; body?: string },
  ): Promise<Result<unknown>> {
    const url = `${this.baseUrl}${path}`;
    let attempts429 = 0;
    let attempts5xx = 0;

    for (;;) {
      let response: Response;
      try {
        response = await this.fetchFn(url, {
          method: init.method,
          headers: { 'content-type': 'application/json' },
          ...(init.body !== undefined ? { body: init.body } : {}),
          signal: AbortSignal.timeout(this.timeoutMs),
        });
      } catch (cause) {
        const timedOut = cause instanceof DOMException && cause.name === 'TimeoutError';
        return err(
          AppError.world(
            timedOut ? 'OSV_TIMEOUT' : 'OSV_UNREACHABLE',
            timedOut
              ? `OSV request timed out after ${String(this.timeoutMs)}ms`
              : 'Could not reach OSV.dev',
            'Check network connectivity; scan can serve cached data offline.',
            cause,
          ),
        );
      }

      if (response.status === 429) {
        attempts429 += 1;
        if (attempts429 > MAX_429_RETRIES) {
          return err(AppError.world('OSV_RATE_LIMITED', 'OSV.dev rate limit persisted'));
        }
        const backoff = 2 ** attempts429 * 500 + Math.random() * 250;
        await this.sleepFn(backoff);
        continue;
      }

      if (response.status >= 500) {
        attempts5xx += 1;
        if (attempts5xx > MAX_5XX_RETRIES) {
          return err(
            AppError.world('OSV_SERVER_ERROR', `OSV.dev returned ${String(response.status)}`),
          );
        }
        await this.sleepFn(250 * attempts5xx);
        continue;
      }

      if (!response.ok) {
        return err(
          AppError.world(
            'OSV_HTTP_ERROR',
            `OSV.dev returned ${String(response.status)} for ${path}`,
          ),
        );
      }

      try {
        return ok(await response.json());
      } catch (cause) {
        return err(
          AppError.world('OSV_BAD_RESPONSE', 'OSV returned non-JSON body', undefined, cause),
        );
      }
    }
  }
}
