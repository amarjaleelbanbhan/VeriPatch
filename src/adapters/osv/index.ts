import { AdvisorySchema, type Advisory, type DepNode } from '../../core/models/index.js';
import type { AdvisoryLookup, AdvisorySource } from '../../core/ports.js';
import { AppError } from '../../shared/errors.js';
import type { Logger } from '../../shared/logger.js';
import { err, ok, type Result } from '../../shared/result.js';
import type { AdvisoryCache } from '../cache/db.js';
import type { OsvClient, PackageQuery } from './client.js';
import { normalizeOsvAdvisory } from './schema.js';

/**
 * Cache-first advisory source (blueprint §5.1/§4):
 *
 * 1. name@version → advisory-id lists come from the cache when fresh (TTL),
 *    otherwise from one chunked querybatch call.
 * 2. advisory ids → full advisories, again cache-first, hydrated via detail
 *    fetches, validated + sanitized before entering core.
 * 3. offline: expired cache entries are still served, flagged `stale: true`
 *    so the renderer can banner them. Packages with no cache at all make the
 *    degradation dishonest → WorldError instead.
 * 4. advisories that fail validation are dropped and counted (`dataErrors`).
 */

export interface OsvAdvisorySourceOptions {
  client: OsvClient;
  cache: AdvisoryCache;
  cacheTtlHours: number;
  logger?: Logger;
  /** Test seam: epoch-seconds clock. */
  now?: () => number;
}

export class OsvAdvisorySource implements AdvisorySource {
  private readonly client: OsvClient;
  private readonly cache: AdvisoryCache;
  private readonly ttlSeconds: number;
  private readonly logger: Logger | undefined;
  private readonly now: () => number;

  constructor(options: OsvAdvisorySourceOptions) {
    this.client = options.client;
    this.cache = options.cache;
    this.ttlSeconds = options.cacheTtlHours * 3600;
    this.logger = options.logger;
    this.now = options.now ?? ((): number => Math.floor(Date.now() / 1000));
  }

  async getAdvisories(nodes: DepNode[]): Promise<Result<AdvisoryLookup>> {
    const idsResult = await this.resolveAdvisoryIds(nodes);
    if (!idsResult.ok) return idsResult;
    const { idSet, stale: idsStale } = idsResult.value;

    const hydrated = await this.hydrateAdvisories(idSet);
    if (!hydrated.ok) return hydrated;

    return ok({
      advisories: hydrated.value.advisories,
      stale: idsStale || hydrated.value.stale,
      dataErrors: hydrated.value.dataErrors,
    });
  }

  /** Step 1: which advisory ids affect each name@version. */
  private async resolveAdvisoryIds(
    nodes: DepNode[],
  ): Promise<Result<{ idSet: Set<string>; stale: boolean }>> {
    const now = this.now();
    const idSet = new Set<string>();
    let stale = false;

    const missing: { node: DepNode; hasStaleCache: boolean }[] = [];
    for (const node of nodes) {
      const cached = this.cache.getPkgAdvisoryIds(pkgKey(node));
      if (cached !== undefined && now - cached.fetchedAt <= this.ttlSeconds) {
        for (const id of cached.ids) idSet.add(id);
      } else {
        missing.push({ node, hasStaleCache: cached !== undefined });
      }
    }
    if (missing.length === 0) return ok({ idSet, stale });

    const queries: PackageQuery[] = missing.map(({ node }) => ({
      name: node.name,
      version: node.version,
    }));
    const batch = await this.client.queryBatch(queries);

    if (batch.ok) {
      batch.value.forEach((refs, i) => {
        const node = missing[i]?.node;
        if (node === undefined) return;
        const ids = refs.map((r) => r.id);
        this.cache.setPkgAdvisoryIds(pkgKey(node), ids, now);
        for (const id of ids) idSet.add(id);
      });
      return ok({ idSet, stale });
    }

    // Network failed. Serving expired entries is honest degradation; missing
    // entries would silently report "no vulns" — that is a lie, so refuse.
    const uncachable = missing.filter((m) => !m.hasStaleCache);
    if (uncachable.length > 0) {
      return err(
        AppError.world(
          'ADVISORIES_UNAVAILABLE',
          `OSV.dev is unreachable and ${String(uncachable.length)} package(s) have no cached advisories`,
          'Reconnect and retry; cached packages can be scanned offline.',
          batch.error,
        ),
      );
    }
    this.logger?.warn('OSV unreachable — serving stale advisory ids from cache');
    stale = true;
    for (const { node } of missing) {
      const cached = this.cache.getPkgAdvisoryIds(pkgKey(node));
      for (const id of cached?.ids ?? []) idSet.add(id);
    }
    return ok({ idSet, stale });
  }

  /** Step 2: ids → validated Advisory objects, cache-first with stale fallback. */
  private async hydrateAdvisories(
    idSet: Set<string>,
  ): Promise<Result<{ advisories: Advisory[]; stale: boolean; dataErrors: number }>> {
    const now = this.now();
    const advisories: Advisory[] = [];
    let stale = false;
    let dataErrors = 0;

    for (const id of idSet) {
      const cached = this.cache.getAdvisory(id);
      if (cached !== undefined && now - cached.fetchedAt <= this.ttlSeconds) {
        const revived = reviveCachedAdvisory(cached.json);
        if (revived !== undefined) {
          advisories.push(revived);
          continue;
        }
        // Corrupted cache row: fall through to refetch.
      }

      const fetched = await this.client.getVuln(id);
      if (fetched.ok) {
        const advisory = normalizeOsvAdvisory(fetched.value);
        if (advisory === undefined) {
          dataErrors += 1;
          this.logger?.warn({ advisoryId: id }, 'dropped advisory failing schema validation');
          continue;
        }
        this.cache.setAdvisory(id, JSON.stringify(advisory), advisory.modified, now);
        advisories.push(advisory);
        continue;
      }

      // Fetch failed → expired cache copy is still better than nothing.
      if (cached !== undefined) {
        const revived = reviveCachedAdvisory(cached.json);
        if (revived !== undefined) {
          stale = true;
          advisories.push(revived);
          continue;
        }
      }
      return err(
        AppError.world(
          'ADVISORY_FETCH_FAILED',
          `Could not fetch advisory ${id} and no cached copy exists`,
          undefined,
          fetched.error,
        ),
      );
    }

    return ok({ advisories, stale, dataErrors });
  }
}

function pkgKey(node: DepNode): string {
  return `${node.name}@${node.version}`;
}

/** Cached rows were validated on write, but never trust storage blindly. */
function reviveCachedAdvisory(json: string): Advisory | undefined {
  try {
    const parsed = AdvisorySchema.safeParse(JSON.parse(json));
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}
