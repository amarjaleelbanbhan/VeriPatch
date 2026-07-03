/**
 * Ordered, idempotent schema migrations (blueprint §4).
 *
 * Embedded as TS constants rather than loose .sql files so the published
 * bundle stays self-contained (tsup would not ship sidecar .sql assets).
 * Each entry runs inside a transaction exactly once, tracked via
 * meta.schema_version; never edit an existing migration — append a new one.
 */
export interface Migration {
  version: number;
  sql: string;
}

export const MIGRATIONS: Migration[] = [
  {
    version: 1,
    sql: `
      CREATE TABLE IF NOT EXISTS advisories_by_pkg (
        pkg_key      TEXT PRIMARY KEY,   -- "name@version"
        advisory_ids TEXT NOT NULL,      -- JSON array of OSV ids
        fetched_at   INTEGER NOT NULL    -- unix epoch seconds
      );
      CREATE TABLE IF NOT EXISTS advisories (
        id         TEXT PRIMARY KEY,     -- OSV id (GHSA-... / CVE-...)
        json       TEXT NOT NULL,        -- normalized, validated Advisory JSON
        modified   TEXT NOT NULL,        -- upstream last-modified (ISO-8601)
        fetched_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_adv_fetched ON advisories(fetched_at);
    `,
  },
];
