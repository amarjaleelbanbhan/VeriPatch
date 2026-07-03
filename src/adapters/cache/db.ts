import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import { AppError } from '../../shared/errors.js';
import { err, ok, type Result } from '../../shared/result.js';
import { MIGRATIONS } from './migrations/index.js';

/**
 * SQLite advisory cache (blueprint §4): single file under ~/.veripatch,
 * 0600 perms, migrations applied idempotently at open. Callers never see
 * better-sqlite3 types — only this narrow API.
 */

export const DEFAULT_CACHE_DIR = path.join(os.homedir(), '.veripatch');
export const CACHE_FILE_NAME = 'cache.db';

export interface CachedPkgIds {
  ids: string[];
  fetchedAt: number;
}

export interface CachedAdvisory {
  json: string;
  modified: string;
  fetchedAt: number;
}

export interface CacheStats {
  pkgRows: number;
  advisoryRows: number;
  dbBytes: number;
  oldestFetchedAt: number | null;
  newestFetchedAt: number | null;
}

export class AdvisoryCache {
  private constructor(
    private readonly db: Database.Database,
    readonly dbPath: string,
  ) {}

  static open(cacheDir: string = DEFAULT_CACHE_DIR): Result<AdvisoryCache> {
    const dbPath = path.join(cacheDir, CACHE_FILE_NAME);
    let db: Database.Database;
    try {
      fs.mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
      db = new Database(dbPath);
      // WAL keeps concurrent scan processes from tripping over each other.
      db.pragma('journal_mode = WAL');
      db.pragma('busy_timeout = 5000');
      applyMigrations(db);
      // Cache may hold advisory data fetched over the user's network; keep it
      // private. Best-effort on Windows where POSIX modes are advisory only.
      fs.chmodSync(dbPath, 0o600);
    } catch (cause) {
      return err(
        AppError.world(
          'CACHE_OPEN_FAILED',
          `Could not open advisory cache at ${dbPath}`,
          'Check permissions on the directory, or clear it with: veripatch cache clear',
          cause,
        ),
      );
    }
    return ok(new AdvisoryCache(db, dbPath));
  }

  getPkgAdvisoryIds(pkgKey: string): CachedPkgIds | undefined {
    const row = this.db
      .prepare('SELECT advisory_ids, fetched_at FROM advisories_by_pkg WHERE pkg_key = ?')
      .get(pkgKey) as { advisory_ids: string; fetched_at: number } | undefined;
    if (row === undefined) return undefined;
    try {
      const ids = JSON.parse(row.advisory_ids) as unknown;
      if (!Array.isArray(ids) || !ids.every((x) => typeof x === 'string')) return undefined;
      return { ids, fetchedAt: row.fetched_at };
    } catch {
      return undefined; // corrupted row behaves like a miss; next fetch overwrites it
    }
  }

  setPkgAdvisoryIds(pkgKey: string, ids: string[], fetchedAt: number): void {
    this.db
      .prepare(
        `INSERT INTO advisories_by_pkg (pkg_key, advisory_ids, fetched_at) VALUES (?, ?, ?)
         ON CONFLICT(pkg_key) DO UPDATE SET advisory_ids = excluded.advisory_ids, fetched_at = excluded.fetched_at`,
      )
      .run(pkgKey, JSON.stringify(ids), fetchedAt);
  }

  getAdvisory(id: string): CachedAdvisory | undefined {
    const row = this.db
      .prepare('SELECT json, modified, fetched_at FROM advisories WHERE id = ?')
      .get(id) as { json: string; modified: string; fetched_at: number } | undefined;
    return row === undefined
      ? undefined
      : { json: row.json, modified: row.modified, fetchedAt: row.fetched_at };
  }

  setAdvisory(id: string, json: string, modified: string, fetchedAt: number): void {
    this.db
      .prepare(
        `INSERT INTO advisories (id, json, modified, fetched_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET json = excluded.json, modified = excluded.modified, fetched_at = excluded.fetched_at`,
      )
      .run(id, json, modified, fetchedAt);
  }

  stats(): CacheStats {
    const pkgRows = (
      this.db.prepare('SELECT COUNT(*) AS n FROM advisories_by_pkg').get() as { n: number }
    ).n;
    const advisoryRows = (
      this.db.prepare('SELECT COUNT(*) AS n FROM advisories').get() as { n: number }
    ).n;
    const range = this.db
      .prepare('SELECT MIN(fetched_at) AS oldest, MAX(fetched_at) AS newest FROM advisories')
      .get() as { oldest: number | null; newest: number | null };
    let dbBytes = 0;
    try {
      dbBytes = fs.statSync(this.dbPath).size;
    } catch {
      // stats stay best-effort if the file vanished under us
    }
    return {
      pkgRows,
      advisoryRows,
      dbBytes,
      oldestFetchedAt: range.oldest,
      newestFetchedAt: range.newest,
    };
  }

  clear(): void {
    this.db.exec('DELETE FROM advisories_by_pkg; DELETE FROM advisories;');
  }

  close(): void {
    this.db.close();
  }
}

/** Runs pending migrations in order, tracking progress in meta.schema_version. */
function applyMigrations(db: Database.Database): void {
  db.exec('CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)');
  const row = db.prepare("SELECT v FROM meta WHERE k = 'schema_version'").get() as
    { v: string } | undefined;
  const current = row === undefined ? 0 : Number(row.v);

  for (const migration of MIGRATIONS) {
    if (migration.version <= current) continue;
    const apply = db.transaction(() => {
      db.exec(migration.sql);
      db.prepare(
        "INSERT INTO meta (k, v) VALUES ('schema_version', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
      ).run(String(migration.version));
    });
    apply();
  }
}
