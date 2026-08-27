//! RustSec advisory cache (issue #237)
//!
//! Caches the result of `OSV GET /vulns/{id}` to avoid redundant network
//! requests for the same RUSTSEC advisory across LSP sessions.

pub mod memory;
pub mod sqlite;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use memory::{AdvisoryCacheStats, DEFAULT_ADVISORY_TTL, MemoryAdvisoryCache};
pub use sqlite::{DEFAULT_ADVISORY_TTL_SECS, SqliteAdvisoryCache};

/// Cached classification of a single OSV advisory.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum AdvisoryKind {
    /// Advisory exists at OSV; we recorded the parts we need.
    Found {
        summary: Option<String>,
        unmaintained: bool,
    },
    /// Advisory ID returned 404 from OSV.
    NotFound,
}

/// One cache entry: an advisory ID plus its classification and fetch time.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CachedAdvisory {
    pub id: String,
    pub kind: AdvisoryKind,
    pub fetched_at: SystemTime,
}

/// Read-only access to the advisory cache.
///
/// Mirrors [`crate::cache::ReadCache`] but specialised for advisory entries.
/// Uses `#[async_trait]` so the trait remains dyn-compatible (`Arc<dyn …>`).
#[async_trait]
pub trait AdvisoryReadCache: Send + Sync {
    /// Fetch a cached advisory. Returns `None` on miss or expiry.
    async fn get(&self, advisory_id: &str) -> Option<CachedAdvisory>;

    /// Convenience wrapper around `get` for existence checks.
    async fn contains(&self, advisory_id: &str) -> bool {
        self.get(advisory_id).await.is_some()
    }
}

/// Write access to the advisory cache.
///
/// Mirrors [`crate::cache::WriteCache`] but specialised for advisory entries.
/// Unlike `WriteCache`, the key is not passed separately — `CachedAdvisory`
/// carries its own `id`.
#[async_trait]
pub trait AdvisoryWriteCache: AdvisoryReadCache {
    /// Insert (or replace) an advisory entry.
    ///
    /// The `advisory.id` field acts as the cache key; unlike
    /// [`crate::cache::WriteCache::insert`] the key is not passed separately.
    async fn insert(&self, advisory: CachedAdvisory);

    /// Remove a single advisory entry.
    async fn remove(&self, advisory_id: &str);

    /// Remove every entry from the cache.
    async fn clear(&self);
}

#[async_trait]
impl<T: AdvisoryReadCache + ?Sized> AdvisoryReadCache for Arc<T> {
    async fn get(&self, advisory_id: &str) -> Option<CachedAdvisory> {
        (**self).get(advisory_id).await
    }

    async fn contains(&self, advisory_id: &str) -> bool {
        (**self).contains(advisory_id).await
    }
}

#[async_trait]
impl<T: AdvisoryWriteCache + ?Sized> AdvisoryWriteCache for Arc<T> {
    async fn insert(&self, advisory: CachedAdvisory) {
        (**self).insert(advisory).await
    }

    async fn remove(&self, advisory_id: &str) {
        (**self).remove(advisory_id).await
    }

    async fn clear(&self) {
        (**self).clear().await
    }
}

/// No-op cache used when caching is disabled via configuration.
///
/// All reads return `None`, all writes are silently dropped.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullAdvisoryCache;

#[async_trait]
impl AdvisoryReadCache for NullAdvisoryCache {
    async fn get(&self, _advisory_id: &str) -> Option<CachedAdvisory> {
        None
    }
}

#[async_trait]
impl AdvisoryWriteCache for NullAdvisoryCache {
    async fn insert(&self, _advisory: CachedAdvisory) {}
    async fn remove(&self, _advisory_id: &str) {}
    async fn clear(&self) {}
}

/// Cleanup interval for the hybrid cache background task (30 minutes).
pub const ADVISORY_CLEANUP_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Two-tier advisory cache: in-memory L1 backed by SQLite L2.
pub struct HybridAdvisoryCache {
    memory: memory::MemoryAdvisoryCache,
    sqlite: Option<Arc<sqlite::SqliteAdvisoryCache>>,
}

impl HybridAdvisoryCache {
    /// Construct a hybrid cache, attempting to open the default SQLite path.
    pub fn new() -> Self {
        let sqlite = match sqlite::SqliteAdvisoryCache::new() {
            Ok(cache) => {
                tracing::info!("Advisory SQLite cache initialised");
                Some(Arc::new(cache))
            }
            Err(err) => {
                tracing::warn!(
                    "Advisory SQLite cache unavailable, using memory only: {}",
                    err
                );
                None
            }
        };
        let memory = memory::MemoryAdvisoryCache::new();
        Self { memory, sqlite }
    }

    /// Build directly from prepared layers (used by tests and by callers
    /// that have constructed a custom SQLite cache).
    pub fn from_parts(
        memory: memory::MemoryAdvisoryCache,
        sqlite: Option<Arc<sqlite::SqliteAdvisoryCache>>,
    ) -> Self {
        Self { memory, sqlite }
    }

    /// Build a hybrid cache from an [`crate::config::AdvisoryCacheConfig`] (issue #237).
    ///
    /// When `config.enabled` is `false`, returns a hybrid whose memory layer
    /// has a zero-second TTL and no SQLite backing. Every read therefore
    /// misses, which matches the "caching disabled" semantics without
    /// requiring callers to branch on a different concrete type.
    ///
    /// When `enabled` is `true`, the memory TTL is taken from
    /// `config.ttl_secs` and the SQLite layer is opened at `config.db_path`
    /// (or the default location). A SQLite open failure is logged and falls
    /// back to a memory-only hybrid — matching pre-existing `new()` behaviour.
    pub fn from_config(config: &crate::config::AdvisoryCacheConfig) -> Self {
        if !config.enabled {
            return Self::from_parts(
                memory::MemoryAdvisoryCache::with_ttl(Duration::from_secs(0)),
                None,
            );
        }
        let memory = memory::MemoryAdvisoryCache::with_ttl(Duration::from_secs(config.ttl_secs));
        let sqlite = match sqlite::SqliteAdvisoryCache::from_config(config) {
            Ok(cache) => {
                tracing::info!("Advisory SQLite cache initialised from config");
                Some(Arc::new(cache))
            }
            Err(err) => {
                tracing::warn!(
                    "Advisory SQLite cache unavailable, using memory only: {}",
                    err
                );
                None
            }
        };
        Self::from_parts(memory, sqlite)
    }

    /// Build a *negative* advisory cache from an [`crate::config::AdvisoryCacheConfig`].
    ///
    /// 404 OSV responses live on a different freshness schedule than real
    /// `Found` entries: a missing advisory might just mean OSV has not yet
    /// ingested a brand-new RUSTSEC ID, so we want to retry sooner. This
    /// constructor uses `config.negative_ttl_secs` for the memory TTL and
    /// deliberately omits the SQLite layer — short-TTL entries do not need
    /// cross-session persistence and would otherwise share storage with the
    /// positive cache.
    ///
    /// When `enabled = false`, the cache is zero-TTL (always misses).
    pub fn negative_from_config(config: &crate::config::AdvisoryCacheConfig) -> Self {
        if !config.enabled {
            return Self::from_parts(
                memory::MemoryAdvisoryCache::with_ttl(Duration::from_secs(0)),
                None,
            );
        }
        let memory =
            memory::MemoryAdvisoryCache::with_ttl(Duration::from_secs(config.negative_ttl_secs));
        Self::from_parts(memory, None)
    }

    /// Spawn a background task that periodically prunes expired entries from
    /// both layers. The default interval is [`ADVISORY_CLEANUP_INTERVAL`].
    ///
    /// Returns the `JoinHandle` so callers (notably the LSP backend, which
    /// rebuilds the cache trio inside `initialize`) can `abort()` the task
    /// when the cache is replaced. Without this, the old cleanup task keeps
    /// holding `Arc` clones of the previous memory/SQLite layers forever.
    #[must_use = "abort the handle when the cache is replaced to avoid leaking the cleanup task"]
    pub fn spawn_default_cleanup_task(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        self.spawn_cleanup_task(ADVISORY_CLEANUP_INTERVAL)
    }

    /// Spawn the cleanup task with a custom interval (used by tests).
    #[must_use = "abort the handle when the cache is replaced to avoid leaking the cleanup task"]
    pub fn spawn_cleanup_task(self: &Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        let memory = self.memory.clone();
        let sqlite = self.sqlite.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // skip immediate fire
            loop {
                ticker.tick().await;
                // DashMap::retain holds a write lock during the scan. For
                // very large caches this can briefly block the executor —
                // offload to the blocking pool to keep the runtime healthy.
                let memory_for_cleanup = memory.clone();
                let removed =
                    tokio::task::spawn_blocking(move || memory_for_cleanup.cleanup_expired())
                        .await
                        .unwrap_or(0);
                if removed > 0 {
                    tracing::debug!("Advisory cache: pruned {} expired memory entries", removed);
                }
                if let Some(ref sqlite) = sqlite {
                    match sqlite.cleanup_expired().await {
                        Ok(rows) if rows > 0 => {
                            tracing::debug!("Advisory cache: pruned {} expired SQLite rows", rows);
                        }
                        Ok(_) => {}
                        Err(err) => {
                            tracing::warn!("Advisory cache cleanup failed for SQLite: {}", err);
                        }
                    }
                }
            }
        })
    }
}

impl Default for HybridAdvisoryCache {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AdvisoryReadCache for HybridAdvisoryCache {
    async fn get(&self, advisory_id: &str) -> Option<CachedAdvisory> {
        if let Some(value) = self.memory.get(advisory_id).await {
            return Some(value);
        }

        if let Some(ref sqlite) = self.sqlite
            && let Some(value) = sqlite.get(advisory_id).await
        {
            // Backfill L1 with the *remaining* TTL relative to the original
            // fetch time, not a fresh full memory-TTL window. Otherwise an
            // entry that is about to expire in SQLite would gain a brand-new
            // memory-TTL on every L2 read, doubling the effective TTL.
            let remaining = match value.fetched_at.elapsed() {
                Ok(elapsed) => self.memory.ttl().saturating_sub(elapsed),
                Err(_) => Duration::from_secs(0),
            };
            if !remaining.is_zero() {
                self.memory
                    .insert_with_remaining_ttl(value.clone(), remaining)
                    .await;
            }
            return Some(value);
        }

        None
    }
}

#[async_trait]
impl AdvisoryWriteCache for HybridAdvisoryCache {
    async fn insert(&self, advisory: CachedAdvisory) {
        self.memory.insert(advisory.clone()).await;
        if let Some(ref sqlite) = self.sqlite {
            sqlite.insert(advisory).await;
        }
    }

    async fn remove(&self, advisory_id: &str) {
        self.memory.remove(advisory_id).await;
        if let Some(ref sqlite) = self.sqlite {
            sqlite.remove(advisory_id).await;
        }
    }

    async fn clear(&self) {
        self.memory.clear().await;
        if let Some(ref sqlite) = self.sqlite {
            sqlite.clear().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::memory::MemoryAdvisoryCache;
    use super::sqlite::SqliteAdvisoryCache;
    use super::*;

    fn sample_found(id: &str) -> CachedAdvisory {
        CachedAdvisory {
            id: id.to_string(),
            kind: AdvisoryKind::Found {
                summary: Some("unmaintained".to_string()),
                unmaintained: true,
            },
            fetched_at: SystemTime::UNIX_EPOCH,
        }
    }

    #[tokio::test]
    async fn hybrid_l1_hit_returns_without_consulting_l2() {
        let memory = MemoryAdvisoryCache::new();
        let sqlite = Arc::new(SqliteAdvisoryCache::in_memory().expect("in-memory sqlite"));
        let advisory = sample_found("RUSTSEC-2020-0036");
        memory.insert(advisory.clone()).await;
        // Note: deliberately NOT inserting into SQLite.
        let hybrid = HybridAdvisoryCache::from_parts(memory, Some(sqlite));
        assert_eq!(hybrid.get("RUSTSEC-2020-0036").await, Some(advisory));
    }

    #[tokio::test]
    async fn hybrid_l2_hit_backfills_l1() {
        let memory = MemoryAdvisoryCache::new();
        let sqlite = Arc::new(SqliteAdvisoryCache::in_memory().expect("in-memory sqlite"));
        let advisory = CachedAdvisory {
            id: "RUSTSEC-2020-0036".to_string(),
            kind: AdvisoryKind::Found {
                summary: Some("unmaintained".to_string()),
                unmaintained: true,
            },
            // `SystemTime::now()` so `elapsed()` succeeds and `remaining` is
            // close to the configured memory TTL.
            fetched_at: SystemTime::now(),
        };
        sqlite.insert(advisory.clone()).await;
        let hybrid = HybridAdvisoryCache::from_parts(memory.clone(), Some(sqlite));

        assert_eq!(hybrid.get(&advisory.id).await, Some(advisory.clone()));
        // After the first read, the memory layer should hold it directly.
        assert_eq!(memory.get(&advisory.id).await, Some(advisory));
    }

    /// Regression: an L2 hit must NOT extend the effective TTL past the
    /// original SQLite fetch time + memory TTL by re-stamping the L1 entry
    /// with `Instant::now()`. The L1 backfill should respect the remaining
    /// TTL relative to `fetched_at`.
    #[tokio::test]
    async fn hybrid_l2_backfill_preserves_remaining_ttl() {
        // Memory TTL of 50 ms.
        let memory = MemoryAdvisoryCache::with_ttl(Duration::from_millis(50));
        let sqlite = Arc::new(SqliteAdvisoryCache::in_memory().expect("in-memory sqlite"));
        // Advisory fetched 40 ms ago — only ~10 ms of memory TTL should remain.
        let advisory = CachedAdvisory {
            id: "RUSTSEC-2020-0036".to_string(),
            kind: AdvisoryKind::Found {
                summary: None,
                unmaintained: false,
            },
            fetched_at: SystemTime::now() - Duration::from_millis(40),
        };
        sqlite.insert(advisory.clone()).await;
        let hybrid = HybridAdvisoryCache::from_parts(memory.clone(), Some(sqlite));

        // First read: backfills L1.
        assert_eq!(hybrid.get(&advisory.id).await, Some(advisory.clone()));
        assert!(memory.get(&advisory.id).await.is_some());

        // Wait long enough that the *remaining* TTL has elapsed but a fresh
        // 50 ms window would still be alive. If backfill used the full TTL,
        // the entry would still be present.
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            memory.get(&advisory.id).await.is_none(),
            "L1 backfill must not extend effective TTL past fetched_at + memory_ttl"
        );
    }

    /// If `fetched_at` is somehow already past `memory_ttl`, the backfill
    /// should be skipped entirely (zero remaining ⇒ never write a 0-TTL row).
    #[tokio::test]
    async fn hybrid_l2_backfill_skips_when_remaining_ttl_is_zero() {
        let memory = MemoryAdvisoryCache::with_ttl(Duration::from_millis(10));
        let sqlite = Arc::new(SqliteAdvisoryCache::in_memory().expect("in-memory sqlite"));
        let advisory = CachedAdvisory {
            id: "RUSTSEC-2020-0036".to_string(),
            kind: AdvisoryKind::NotFound,
            fetched_at: SystemTime::now() - Duration::from_secs(60),
        };
        sqlite.insert(advisory.clone()).await;
        let hybrid = HybridAdvisoryCache::from_parts(memory.clone(), Some(sqlite));

        // The hybrid still returns the L2 value, but does not backfill L1.
        assert_eq!(hybrid.get(&advisory.id).await, Some(advisory.clone()));
        assert!(memory.get(&advisory.id).await.is_none());
    }

    #[tokio::test]
    async fn hybrid_double_miss_returns_none() {
        let memory = MemoryAdvisoryCache::new();
        let sqlite = Arc::new(SqliteAdvisoryCache::in_memory().expect("in-memory sqlite"));
        let hybrid = HybridAdvisoryCache::from_parts(memory, Some(sqlite));
        assert!(hybrid.get("RUSTSEC-1990-0001").await.is_none());
    }

    #[tokio::test]
    async fn hybrid_insert_writes_both_layers() {
        let memory = MemoryAdvisoryCache::new();
        let sqlite = Arc::new(SqliteAdvisoryCache::in_memory().expect("in-memory sqlite"));
        let advisory = sample_found("RUSTSEC-2020-0036");
        let hybrid = HybridAdvisoryCache::from_parts(memory.clone(), Some(Arc::clone(&sqlite)));

        hybrid.insert(advisory.clone()).await;

        assert_eq!(memory.get(&advisory.id).await, Some(advisory.clone()));
        assert_eq!(sqlite.get(&advisory.id).await, Some(advisory));
    }

    #[tokio::test]
    async fn hybrid_remove_clears_both_layers() {
        let memory = MemoryAdvisoryCache::new();
        let sqlite = Arc::new(SqliteAdvisoryCache::in_memory().expect("in-memory sqlite"));
        let advisory = sample_found("RUSTSEC-2020-0036");
        let hybrid = HybridAdvisoryCache::from_parts(memory.clone(), Some(Arc::clone(&sqlite)));

        hybrid.insert(advisory.clone()).await;
        hybrid.remove(&advisory.id).await;

        assert!(memory.get(&advisory.id).await.is_none());
        assert!(sqlite.get(&advisory.id).await.is_none());
    }

    #[tokio::test]
    async fn hybrid_clear_clears_both_layers() {
        let memory = MemoryAdvisoryCache::new();
        let sqlite = Arc::new(SqliteAdvisoryCache::in_memory().expect("in-memory sqlite"));
        let hybrid = HybridAdvisoryCache::from_parts(memory.clone(), Some(Arc::clone(&sqlite)));

        hybrid.insert(sample_found("RUSTSEC-2020-0036")).await;
        hybrid.insert(sample_found("RUSTSEC-2021-0001")).await;
        hybrid.clear().await;

        assert!(memory.get("RUSTSEC-2020-0036").await.is_none());
        assert!(sqlite.get("RUSTSEC-2021-0001").await.is_none());
    }

    #[tokio::test]
    async fn hybrid_with_no_sqlite_falls_back_to_memory_only() {
        let memory = MemoryAdvisoryCache::new();
        let hybrid = HybridAdvisoryCache::from_parts(memory.clone(), None);
        let advisory = sample_found("RUSTSEC-2020-0036");

        hybrid.insert(advisory.clone()).await;
        assert_eq!(hybrid.get(&advisory.id).await, Some(advisory));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn background_cleanup_removes_expired_memory_entries() {
        let memory = MemoryAdvisoryCache::with_ttl(Duration::from_millis(20));
        memory.insert(sample_found("RUSTSEC-2020-0036")).await;
        let sqlite = Arc::new(SqliteAdvisoryCache::in_memory().expect("in-memory sqlite"));
        let hybrid = Arc::new(HybridAdvisoryCache::from_parts(
            memory.clone(),
            Some(sqlite),
        ));
        let _cleanup = hybrid.spawn_cleanup_task(Duration::from_millis(40));

        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(memory.get("RUSTSEC-2020-0036").await.is_none());
    }

    #[test]
    fn cached_advisory_round_trips_through_json() {
        let advisory = CachedAdvisory {
            id: "RUSTSEC-2020-0036".to_string(),
            kind: AdvisoryKind::Found {
                summary: Some("failure crate is unmaintained".to_string()),
                unmaintained: true,
            },
            fetched_at: SystemTime::UNIX_EPOCH,
        };
        let json = serde_json::to_string(&advisory).expect("serialize");
        let back: CachedAdvisory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(advisory, back);
    }

    #[test]
    fn not_found_kind_round_trips() {
        let advisory = CachedAdvisory {
            id: "RUSTSEC-9999-0001".to_string(),
            kind: AdvisoryKind::NotFound,
            fetched_at: SystemTime::UNIX_EPOCH,
        };
        let json = serde_json::to_string(&advisory).expect("serialize");
        let back: CachedAdvisory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(advisory, back);
    }

    #[tokio::test]
    async fn arc_blanket_impl_forwards_reads() {
        struct DummyCache {
            value: Option<CachedAdvisory>,
        }

        #[async_trait]
        impl AdvisoryReadCache for DummyCache {
            async fn get(&self, _id: &str) -> Option<CachedAdvisory> {
                self.value.clone()
            }
        }

        let advisory = CachedAdvisory {
            id: "RUSTSEC-2020-0036".to_string(),
            kind: AdvisoryKind::NotFound,
            fetched_at: SystemTime::UNIX_EPOCH,
        };
        let cache: Arc<DummyCache> = Arc::new(DummyCache {
            value: Some(advisory.clone()),
        });
        assert_eq!(cache.get("anything").await, Some(advisory.clone()));
        assert!(cache.contains("anything").await);
    }

    #[tokio::test]
    async fn null_cache_get_returns_none() {
        let cache = NullAdvisoryCache;
        assert_eq!(cache.get("RUSTSEC-2020-0036").await, None);
        assert!(!cache.contains("RUSTSEC-2020-0036").await);
    }

    #[tokio::test]
    async fn from_config_disabled_returns_hybrid_that_always_misses() {
        let config = crate::config::AdvisoryCacheConfig {
            enabled: false,
            ttl_secs: 86_400,
            negative_ttl_secs: 3_600,
            db_path: None,
        };
        let hybrid = HybridAdvisoryCache::from_config(&config);
        // Insert an advisory, then read it back: a zero-TTL hybrid must miss
        // even immediately after insertion.
        hybrid
            .insert(CachedAdvisory {
                id: "RUSTSEC-2020-0036".to_string(),
                kind: AdvisoryKind::NotFound,
                fetched_at: SystemTime::now(),
            })
            .await;
        // Wait one tick to ensure the zero TTL has definitely elapsed.
        tokio::time::sleep(Duration::from_millis(2)).await;
        assert!(hybrid.get("RUSTSEC-2020-0036").await.is_none());
    }

    #[tokio::test]
    async fn from_config_enabled_uses_configured_ttl_for_memory_layer() {
        let tmp = tempfile::tempdir().expect("tmp dir");
        let config = crate::config::AdvisoryCacheConfig {
            enabled: true,
            ttl_secs: 3_600,
            negative_ttl_secs: 60,
            db_path: Some(tmp.path().join("advisory_cache.db")),
        };
        let hybrid = HybridAdvisoryCache::from_config(&config);
        hybrid
            .insert(CachedAdvisory {
                id: "RUSTSEC-2020-0036".to_string(),
                kind: AdvisoryKind::NotFound,
                fetched_at: SystemTime::now(),
            })
            .await;
        // With ttl_secs = 3600 the entry must be present immediately.
        assert!(hybrid.get("RUSTSEC-2020-0036").await.is_some());
    }

    #[tokio::test]
    async fn from_config_enabled_with_unwritable_path_falls_back_to_memory_only() {
        // Build a deterministic "cannot create directory" condition: place a
        // regular file where a parent directory would need to live, then ask
        // SQLite to open a path beneath it. `create_dir_all` rejects this on
        // every platform regardless of permissions (file is not a directory),
        // so the test does not depend on whether the runner has root or
        // peculiar /this/path locations.
        let tmp = tempfile::tempdir().expect("tempdir");
        let blocker = tmp.path().join("blocker_file");
        std::fs::write(&blocker, b"not a directory").expect("write blocker");
        let db_path = blocker.join("nested").join("advisory_cache.db");
        let config = crate::config::AdvisoryCacheConfig {
            enabled: true,
            ttl_secs: 60,
            negative_ttl_secs: 30,
            db_path: Some(db_path),
        };
        let hybrid = HybridAdvisoryCache::from_config(&config);
        hybrid
            .insert(CachedAdvisory {
                id: "RUSTSEC-2020-0036".to_string(),
                kind: AdvisoryKind::NotFound,
                fetched_at: SystemTime::now(),
            })
            .await;
        assert!(hybrid.get("RUSTSEC-2020-0036").await.is_some());
    }

    #[tokio::test]
    async fn null_cache_writes_are_noop() {
        let cache = NullAdvisoryCache;
        cache
            .insert(CachedAdvisory {
                id: "RUSTSEC-2020-0036".to_string(),
                kind: AdvisoryKind::NotFound,
                fetched_at: SystemTime::UNIX_EPOCH,
            })
            .await;
        cache.remove("RUSTSEC-2020-0036").await;
        cache.clear().await;
        assert_eq!(cache.get("RUSTSEC-2020-0036").await, None);
    }
}
