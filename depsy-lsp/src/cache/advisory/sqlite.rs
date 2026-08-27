//! SQLite-backed advisory cache (L2 layer).

use std::path::PathBuf;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use r2d2::Pool;
use rusqlite::params;

use crate::cache::sqlite_manager::{NANOS_PER_SEC, SqliteConnectionManager};

use super::{AdvisoryReadCache, AdvisoryWriteCache, CachedAdvisory};

/// Default TTL for stored advisories (24 hours).
pub const DEFAULT_ADVISORY_TTL_SECS: i64 = 86_400;

#[cfg(test)]
static TEST_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

/// SQLite-backed cache for OSV advisory results.
pub struct SqliteAdvisoryCache {
    pool: Arc<Pool<SqliteConnectionManager>>,
    ttl_secs: i64,
}

impl SqliteAdvisoryCache {
    /// Build a cache at the default location (`~/.cache/depsy/advisory_cache.db`).
    pub fn new() -> anyhow::Result<Self> {
        let cache_dir = Self::cache_dir()?;
        std::fs::create_dir_all(&cache_dir)?;
        let path = cache_dir.join("advisory_cache.db");
        Self::with_path(path, DEFAULT_ADVISORY_TTL_SECS)
    }

    /// Build a cache from an [`crate::config::AdvisoryCacheConfig`] (issue #237).
    ///
    /// Uses `config.db_path` if set, otherwise the default cache location.
    /// Returns an error if the database directory cannot be created or the
    /// connection pool cannot be built.
    pub fn from_config(config: &crate::config::AdvisoryCacheConfig) -> anyhow::Result<Self> {
        let path = match &config.db_path {
            Some(p) => {
                // Create parent directories for user-supplied custom paths.
                // Without this, opening a nested override silently degrades
                // to memory-only when SQLite cannot find the directory.
                if let Some(parent) = p.parent()
                    && !parent.as_os_str().is_empty()
                {
                    std::fs::create_dir_all(parent)?;
                }
                p.clone()
            }
            None => {
                let cache_dir = Self::cache_dir()?;
                std::fs::create_dir_all(&cache_dir)?;
                cache_dir.join("advisory_cache.db")
            }
        };
        Self::with_path(path, config.ttl_secs as i64)
    }

    /// Build a cache at a custom path, with a custom TTL.
    pub fn with_path(path: PathBuf, ttl_secs: i64) -> anyhow::Result<Self> {
        let manager = SqliteConnectionManager::file_with_config(&path, 5_000, 64_000);
        let pool = Pool::builder()
            .max_size(4)
            .min_idle(Some(1))
            .connection_timeout(Duration::from_secs(5))
            .idle_timeout(Some(Duration::from_secs(600)))
            .max_lifetime(Some(Duration::from_secs(1800)))
            .build(manager)?;

        let cache = Self {
            pool: Arc::new(pool),
            ttl_secs,
        };
        cache.init_schema()?;
        Ok(cache)
    }

    /// In-memory cache for tests.
    #[cfg(test)]
    pub fn in_memory() -> anyhow::Result<Self> {
        let id = TEST_DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        let uri = format!("file:advisorymemdb{id}?mode=memory&cache=shared");
        let manager = SqliteConnectionManager::in_memory(&uri);
        let pool = Pool::builder().max_size(4).build(manager)?;
        let cache = Self {
            pool: Arc::new(pool),
            ttl_secs: DEFAULT_ADVISORY_TTL_SECS,
        };
        cache.init_schema_memory()?;
        Ok(cache)
    }

    /// Construct a cache with a custom TTL (used by negative-cache wiring).
    pub fn with_ttl_secs(self, ttl_secs: i64) -> Self {
        Self { ttl_secs, ..self }
    }

    /// Delete every expired entry. Returns the number of rows removed.
    pub async fn cleanup_expired(&self) -> anyhow::Result<usize> {
        let pool = Arc::clone(&self.pool);
        tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
            let conn = pool.get()?;
            let now = current_timestamp();
            let rows = conn.execute(
                "DELETE FROM advisories WHERE inserted_at + ttl_secs * ? < ?",
                params![NANOS_PER_SEC, now],
            )?;
            Ok(rows)
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking join error: {e}"))?
    }

    fn cache_dir() -> anyhow::Result<PathBuf> {
        let cache_dir = dirs::cache_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine cache directory"))?;
        Ok(cache_dir.join("depsy"))
    }

    fn init_schema(&self) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS advisories (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                inserted_at INTEGER NOT NULL,
                ttl_secs INTEGER NOT NULL
            )",
            [],
        )?;
        // Intentionally no expiry index. The cleanup query
        // (`WHERE inserted_at + ttl_secs * ? < ?`) wraps `inserted_at` in an
        // arithmetic expression, so SQLite cannot use a `(inserted_at,
        // ttl_secs)` index for it. Advisory rows are bounded by the small
        // number of distinct RUSTSEC IDs encountered, so a periodic full
        // scan is cheap.
        Ok(())
    }

    #[cfg(test)]
    fn init_schema_memory(&self) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS advisories (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                inserted_at INTEGER NOT NULL,
                ttl_secs INTEGER NOT NULL
            )",
            [],
        )?;
        // See `init_schema` — the expiry index is intentionally omitted
        // because it cannot be used by the cleanup query.
        Ok(())
    }
}

#[async_trait]
impl AdvisoryReadCache for SqliteAdvisoryCache {
    async fn get(&self, advisory_id: &str) -> Option<CachedAdvisory> {
        let pool = Arc::clone(&self.pool);
        let id = advisory_id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = pool.get().ok()?;
            let now = current_timestamp();
            let row: Result<(String, i64, i64), _> = conn.query_row(
                "SELECT data, inserted_at, ttl_secs FROM advisories WHERE id = ?",
                [id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            );
            match row {
                Ok((data, inserted_at, ttl_secs)) => {
                    if now > inserted_at + ttl_secs * NANOS_PER_SEC {
                        let _ = conn.execute("DELETE FROM advisories WHERE id = ?", [id.as_str()]);
                        None
                    } else {
                        match serde_json::from_str::<CachedAdvisory>(&data) {
                            Ok(advisory) => Some(advisory),
                            Err(err) => {
                                tracing::warn!("Corrupted advisory cache row for {}: {}", id, err);
                                let _ = conn
                                    .execute("DELETE FROM advisories WHERE id = ?", [id.as_str()]);
                                None
                            }
                        }
                    }
                }
                Err(_) => None,
            }
        })
        .await
        .ok()
        .flatten()
    }
}

#[async_trait]
impl AdvisoryWriteCache for SqliteAdvisoryCache {
    async fn insert(&self, advisory: CachedAdvisory) {
        let pool = Arc::clone(&self.pool);
        let ttl_secs = self.ttl_secs;
        let now = current_timestamp();
        let id = advisory.id.clone();
        let data = match serde_json::to_string(&advisory) {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!("Failed to serialise advisory {}: {}", id, err);
                return;
            }
        };
        let _ = tokio::task::spawn_blocking(move || {
            let Some(conn) = pool.get().ok() else {
                return;
            };
            let _ = conn.execute(
                "INSERT INTO advisories (id, data, inserted_at, ttl_secs) \
                 VALUES (?, ?, ?, ?) \
                 ON CONFLICT(id) DO UPDATE SET \
                   data = excluded.data, \
                   inserted_at = excluded.inserted_at, \
                   ttl_secs = excluded.ttl_secs \
                 WHERE excluded.inserted_at >= advisories.inserted_at",
                params![id, data, now, ttl_secs],
            );
        })
        .await;
    }

    async fn remove(&self, advisory_id: &str) {
        let pool = Arc::clone(&self.pool);
        let id = advisory_id.to_string();
        let _ = tokio::task::spawn_blocking(move || {
            let Some(conn) = pool.get().ok() else {
                return;
            };
            let _ = conn.execute("DELETE FROM advisories WHERE id = ?", [id.as_str()]);
        })
        .await;
    }

    async fn clear(&self) {
        let pool = Arc::clone(&self.pool);
        let _ = tokio::task::spawn_blocking(move || {
            let Some(conn) = pool.get().ok() else {
                return;
            };
            let _ = conn.execute("DELETE FROM advisories", []);
        })
        .await;
    }
}

fn current_timestamp() -> i64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    nanos.min(i64::MAX as u128) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_constructor_creates_table() {
        let cache = SqliteAdvisoryCache::in_memory().expect("open in-memory cache");
        let conn = cache.pool.get().expect("get conn");
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name = 'advisories' AND type = 'table'",
                [],
                |row| row.get(0),
            )
            .expect("query table");
        assert_eq!(count, 1);
    }

    /// Regression: the expiry index was removed because the cleanup query
    /// `WHERE inserted_at + ttl_secs * ? < ?` cannot use a
    /// `(inserted_at, ttl_secs)` index — the arithmetic forces a full scan
    /// regardless. Re-introducing the index without revising the query
    /// would just bloat the schema without benefit.
    #[tokio::test]
    async fn schema_does_not_create_unused_expiry_index() {
        let cache = SqliteAdvisoryCache::in_memory().expect("open in-memory cache");
        let conn = cache.pool.get().expect("get conn");
        let idx: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master \
                 WHERE name = 'idx_advisory_expiry' AND type = 'index'",
                [],
                |row| row.get(0),
            )
            .expect("query index");
        assert_eq!(idx, 0, "idx_advisory_expiry must not be created");
    }

    #[tokio::test]
    async fn current_timestamp_is_positive_and_monotonic() {
        let a = current_timestamp();
        tokio::time::sleep(Duration::from_millis(2)).await;
        let b = current_timestamp();
        assert!(a > 0);
        assert!(b >= a);
    }

    #[tokio::test]
    async fn with_ttl_secs_overrides_default() {
        let cache = SqliteAdvisoryCache::in_memory()
            .expect("open in-memory cache")
            .with_ttl_secs(42);
        assert_eq!(cache.ttl_secs, 42);
    }

    use std::time::SystemTime;

    use super::super::{AdvisoryKind, CachedAdvisory};

    fn sample_found() -> CachedAdvisory {
        CachedAdvisory {
            id: "RUSTSEC-2020-0036".to_string(),
            kind: AdvisoryKind::Found {
                summary: Some("unmaintained".to_string()),
                unmaintained: true,
            },
            fetched_at: SystemTime::UNIX_EPOCH,
        }
    }

    #[tokio::test]
    async fn insert_then_get_returns_advisory() {
        let cache = SqliteAdvisoryCache::in_memory().unwrap();
        let advisory = sample_found();
        cache.insert(advisory.clone()).await;
        assert_eq!(cache.get(&advisory.id).await, Some(advisory));
    }

    #[tokio::test]
    async fn get_unknown_id_returns_none() {
        let cache = SqliteAdvisoryCache::in_memory().unwrap();
        assert!(cache.get("RUSTSEC-2099-9999").await.is_none());
    }

    #[tokio::test]
    async fn expired_entries_are_dropped_on_read() {
        let cache = SqliteAdvisoryCache::in_memory()
            .expect("open in-memory cache")
            .with_ttl_secs(0);
        cache.insert(sample_found()).await;
        // ttl_secs = 0 means any positive elapsed time expires the row.
        tokio::time::sleep(Duration::from_millis(2)).await;
        assert!(cache.get("RUSTSEC-2020-0036").await.is_none());

        // Row should be deleted as a side effect of the previous get.
        let conn = cache.pool.get().expect("conn");
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM advisories WHERE id = ?",
                ["RUSTSEC-2020-0036"],
                |row| row.get(0),
            )
            .expect("query");
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn cleanup_expired_deletes_only_expired_rows() {
        let cache = SqliteAdvisoryCache::in_memory().unwrap().with_ttl_secs(0);
        cache.insert(sample_found()).await;
        tokio::time::sleep(Duration::from_millis(2)).await;

        let removed = cache.cleanup_expired().await.expect("cleanup");
        assert_eq!(removed, 1);
        assert!(cache.get("RUSTSEC-2020-0036").await.is_none());
    }

    #[tokio::test]
    async fn older_insert_does_not_clobber_newer_one() {
        let cache = SqliteAdvisoryCache::in_memory().unwrap();

        let newer = CachedAdvisory {
            id: "RUSTSEC-2020-0036".to_string(),
            kind: AdvisoryKind::Found {
                summary: Some("newer".to_string()),
                unmaintained: true,
            },
            fetched_at: SystemTime::UNIX_EPOCH,
        };

        // Manually craft an older row directly via SQL with a past timestamp.
        let older_data = serde_json::to_string(&CachedAdvisory {
            id: "RUSTSEC-2020-0036".to_string(),
            kind: AdvisoryKind::Found {
                summary: Some("older".to_string()),
                unmaintained: false,
            },
            fetched_at: SystemTime::UNIX_EPOCH,
        })
        .unwrap();
        cache.insert(newer.clone()).await;

        let conn = cache.pool.get().unwrap();
        let now = current_timestamp();
        // Try to upsert using `now - 1s` as inserted_at.
        let attempt = conn.execute(
            "INSERT INTO advisories (id, data, inserted_at, ttl_secs) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET \
               data = excluded.data, \
               inserted_at = excluded.inserted_at, \
               ttl_secs = excluded.ttl_secs \
             WHERE excluded.inserted_at >= advisories.inserted_at",
            params![
                "RUSTSEC-2020-0036",
                older_data,
                now - NANOS_PER_SEC,
                DEFAULT_ADVISORY_TTL_SECS,
            ],
        );
        assert!(attempt.is_ok());

        // Newer entry must still be present.
        assert_eq!(cache.get("RUSTSEC-2020-0036").await, Some(newer));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_get_future_does_not_corrupt_cache() {
        let cache = Arc::new(SqliteAdvisoryCache::in_memory().unwrap());
        cache.insert(sample_found()).await;

        // Spawn many gets, abort half of them mid-flight.
        let mut handles = Vec::new();
        for _ in 0..32 {
            let cache = Arc::clone(&cache);
            handles.push(tokio::spawn(
                async move { cache.get("RUSTSEC-2020-0036").await },
            ));
        }
        for (i, h) in handles.into_iter().enumerate() {
            if i % 2 == 0 {
                h.abort();
            } else {
                let _ = h.await;
            }
        }

        // Survivor reads still work.
        assert!(cache.get("RUSTSEC-2020-0036").await.is_some());
    }

    #[tokio::test]
    async fn corrupted_row_is_deleted_and_treated_as_miss() {
        let cache = SqliteAdvisoryCache::in_memory().unwrap();
        let now = current_timestamp();
        {
            let conn = cache.pool.get().unwrap();
            conn.execute(
                "INSERT INTO advisories (id, data, inserted_at, ttl_secs) VALUES (?, ?, ?, ?)",
                params![
                    "RUSTSEC-2020-0036",
                    "{not valid json",
                    now,
                    DEFAULT_ADVISORY_TTL_SECS
                ],
            )
            .unwrap();
        }
        assert!(cache.get("RUSTSEC-2020-0036").await.is_none());

        let conn = cache.pool.get().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM advisories WHERE id = ?",
                ["RUSTSEC-2020-0036"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
}
