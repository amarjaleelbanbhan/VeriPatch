import { AdvisoryCache, DEFAULT_CACHE_DIR, type CacheStats } from '../../adapters/cache/db.js';
import { createLogger } from '../../shared/logger.js';
import { errorExitCode } from '../exit-code.js';

/** `veripatch cache clear|stats` (blueprint §6): utility over the local advisory cache. */
export function runCacheClearCommand(): number {
  const logger = createLogger({});
  const opened = AdvisoryCache.open(DEFAULT_CACHE_DIR);
  if (!opened.ok) {
    logger.error({ code: opened.error.code }, opened.error.message);
    return errorExitCode(opened.error);
  }
  opened.value.clear();
  opened.value.close();
  process.stdout.write('Advisory cache cleared.\n');
  return 0;
}

export function runCacheStatsCommand(): number {
  const logger = createLogger({});
  const opened = AdvisoryCache.open(DEFAULT_CACHE_DIR);
  if (!opened.ok) {
    logger.error({ code: opened.error.code }, opened.error.message);
    return errorExitCode(opened.error);
  }
  const stats = opened.value.stats();
  opened.value.close();
  process.stdout.write(`${renderCacheStats(stats)}\n`);
  return 0;
}

export function renderCacheStats(stats: CacheStats): string {
  const now = Math.floor(Date.now() / 1000);
  const ageOf = (fetchedAt: number): string => {
    const hours = Math.floor((now - fetchedAt) / 3600);
    return hours < 1 ? '<1h' : `${String(hours)}h`;
  };
  const lines = [
    `Packages cached: ${String(stats.pkgRows)}`,
    `Advisories cached: ${String(stats.advisoryRows)}`,
    `Cache size: ${String(Math.round(stats.dbBytes / 1024))} KB`,
  ];
  if (stats.oldestFetchedAt !== null && stats.newestFetchedAt !== null) {
    lines.push(
      `Oldest entry: ${ageOf(stats.oldestFetchedAt)} old`,
      `Newest entry: ${ageOf(stats.newestFetchedAt)} old`,
    );
  }
  return lines.join('\n');
}
