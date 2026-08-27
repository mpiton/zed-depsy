//! Cache layer for package version information
//!
//! This module provides traits and implementations for caching package
//! metadata. The cache layer uses a trait hierarchy:
//!
//! - **ReadCache**: For read-only cache operations
//! - **WriteCache**: Extends ReadCache with write operations
//!
//! This separation allows for:
//! - Read-only cache views for providers that don't need to write
//! - Dependency injection with minimal interface requirements
//! - Clear separation of concerns

use std::fmt::Display;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::registries::VersionInfo;

pub mod advisory;
pub mod sqlite;
pub(crate) mod sqlite_manager;

pub use advisory::{
    ADVISORY_CLEANUP_INTERVAL, AdvisoryCacheStats, AdvisoryKind, AdvisoryReadCache,
    AdvisoryWriteCache, CachedAdvisory, DEFAULT_ADVISORY_TTL, HybridAdvisoryCache,
    MemoryAdvisoryCache, NullAdvisoryCache,
};
pub use sqlite::SqliteCache;

/// Trait for read-only cache operations
///
/// This trait defines the minimal interface for reading cached values.
/// Implementations can provide additional write operations via the
/// [`WriteCache`] trait.
///
/// Note: `async_fn_in_trait` is allowed because this trait is internal and
/// already bounds `Send + Sync`. Pattern matches `crate::registries::Registry`.
#[allow(async_fn_in_trait)]
pub trait ReadCache: Send + Sync {
    /// Get a value from the cache.
    ///
    /// Returns `None` if the key doesn't exist or the entry is expired.
    async fn get(&self, key: &str) -> Option<VersionInfo>;

    /// Check if a key exists in the cache (without fetching the value).
    async fn contains(&self, key: &str) -> bool {
        self.get(key).await.is_some()
    }
}

/// Trait for writeable cache operations
///
/// This trait extends [`ReadCache`] with the ability to insert and update
/// cache entries. Caches that support both read and write operations should
/// implement this trait.
#[allow(async_fn_in_trait)]
pub trait WriteCache: ReadCache {
    /// Insert a value into the cache.
    ///
    /// If a value with the same key already exists, it will be overwritten.
    async fn insert(&self, key: String, value: VersionInfo);

    /// Remove a value from the cache.
    async fn remove(&self, key: &str);

    /// Clear all entries from the cache.
    async fn clear(&self);
}

impl<T: ReadCache> ReadCache for Arc<T> {
    async fn get(&self, key: &str) -> Option<VersionInfo> {
        (**self).get(key).await
    }

    async fn contains(&self, key: &str) -> bool {
        (**self).contains(key).await
    }
}

impl<T: WriteCache> WriteCache for Arc<T> {
    async fn insert(&self, key: String, value: VersionInfo) {
        (**self).insert(key, value).await
    }

    async fn remove(&self, key: &str) {
        (**self).remove(key).await
    }

    async fn clear(&self) {
        (**self).clear().await
    }
}

/// Default TTL for cache entries (1 hour)
const DEFAULT_TTL: Duration = Duration::from_secs(3600);

/// Cache entry with expiration
#[derive(Debug, Clone)]
struct CacheEntry {
    data: VersionInfo,
    inserted_at: Instant,
    ttl: Duration,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
    }
}

/// In-memory cache using DashMap for thread-safety
#[derive(Clone)]
pub struct MemoryCache {
    entries: Arc<DashMap<String, CacheEntry>>,
    ttl: Duration,
}

impl Default for MemoryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryCache {
    /// Create a new cache with default TTL
    pub fn new() -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            ttl: DEFAULT_TTL,
        }
    }
}

impl ReadCache for MemoryCache {
    async fn get(&self, key: &str) -> Option<VersionInfo> {
        self.entries.get(key).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.data.clone())
            }
        })
    }
}

impl WriteCache for MemoryCache {
    async fn insert(&self, key: String, value: VersionInfo) {
        self.entries.insert(
            key,
            CacheEntry {
                data: value,
                inserted_at: Instant::now(),
                ttl: self.ttl,
            },
        );
    }

    async fn remove(&self, key: &str) {
        self.entries.remove(key);
    }

    async fn clear(&self) {
        self.entries.clear();
    }
}

impl MemoryCache {
    /// Remove all expired entries from the cache
    ///
    /// Returns the number of entries removed.
    pub fn cleanup_expired(&self) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| !entry.is_expired());
        let removed = before - self.entries.len();
        if removed > 0 {
            tracing::debug!(
                "Cleaned up {} expired cache entries ({} remaining)",
                removed,
                self.entries.len()
            );
        }
        removed
    }

    /// Get statistics about the cache contents
    ///
    /// Returns counts of total, expired, and valid entries.
    pub fn stats(&self) -> CacheStats {
        let total = self.entries.len();
        let expired = self.entries.iter().filter(|e| e.is_expired()).count();
        CacheStats {
            total_entries: total,
            expired_entries: expired,
            valid_entries: total.saturating_sub(expired),
        }
    }

    /// Get the number of entries in the cache (including expired)
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the cache is empty
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Create a new cache with custom TTL
    #[cfg(test)]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            ttl,
        }
    }
}

/// Statistics about cache contents
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total number of entries in the cache
    pub total_entries: usize,
    /// Number of expired entries
    pub expired_entries: usize,
    /// Number of valid (non-expired) entries
    pub valid_entries: usize,
}

impl Display for CacheStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CacheStats {{ total: {}, expired: {}, valid: {} }}",
            self.total_entries, self.expired_entries, self.valid_entries
        )
    }
}

/// Hybrid cache that uses memory for fast access and SQLite for persistence
pub struct HybridCache {
    memory: MemoryCache,
    sqlite: Option<Arc<SqliteCache>>,
}

impl Default for HybridCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Cleanup interval for background task (30 minutes)
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30 * 60);

impl HybridCache {
    /// Create a new hybrid cache
    pub fn new() -> Self {
        let sqlite = match SqliteCache::new() {
            Ok(cache) => {
                tracing::info!("SQLite cache initialized");
                Some(Arc::new(cache))
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to initialize SQLite cache, using memory only: {}",
                    e
                );
                None
            }
        };

        let memory = MemoryCache::new();
        Self::spawn_cleanup_task(memory.clone(), sqlite.clone());

        Self { memory, sqlite }
    }

    /// Spawn a background task that periodically cleans up expired entries
    fn spawn_cleanup_task(memory: MemoryCache, sqlite: Option<Arc<SqliteCache>>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            interval.tick().await; // Skip immediate first tick

            loop {
                interval.tick().await;

                let stats = memory.stats();
                let removed = memory.cleanup_expired();
                if removed > 0 {
                    tracing::info!(
                        "Background cleanup: removed {} expired entries from memory cache (was: {})",
                        removed,
                        stats
                    );
                }

                if let Some(ref sqlite) = sqlite {
                    match sqlite.cleanup_expired().await {
                        Ok(rows) if rows > 0 => {
                            tracing::info!(
                                "Background cleanup: removed {} expired entries from SQLite cache",
                                rows
                            );
                        }
                        Ok(_) => {}
                        Err(err) => {
                            tracing::error!(
                                "Background cleanup: SQLite cleanup_expired failed: {err}"
                            );
                        }
                    }
                }
            }
        });
    }
}

impl ReadCache for HybridCache {
    async fn get(&self, key: &str) -> Option<VersionInfo> {
        // Fast path: check memory cache first
        if let Some(value) = self.memory.get(key).await {
            return Some(value);
        }

        // Slow path: check SQLite cache
        if let Some(ref sqlite) = self.sqlite
            && let Some(value) = sqlite.get(key).await
        {
            // Populate memory cache for future fast access
            self.memory.insert(key.to_string(), value.clone()).await;
            return Some(value);
        }

        None
    }
}

impl WriteCache for HybridCache {
    async fn insert(&self, key: String, value: VersionInfo) {
        self.memory.insert(key.clone(), value.clone()).await;
        if let Some(ref sqlite) = self.sqlite {
            sqlite.insert(key, value).await;
        }
    }

    async fn remove(&self, key: &str) {
        self.memory.remove(key).await;
        if let Some(ref sqlite) = self.sqlite {
            sqlite.remove(key).await;
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
    use super::*;

    fn create_test_version_info() -> VersionInfo {
        VersionInfo {
            latest: Some("1.0.0".to_string()),
            latest_prerelease: None,
            versions: vec!["1.0.0".to_string()],
            description: None,
            homepage: None,
            repository: None,
            license: None,
            vulnerabilities: vec![],
            deprecated: false,
            yanked: false,
            yanked_versions: vec![],
            release_dates: Default::default(),
            transitive_vulnerabilities: vec![],
        }
    }

    #[tokio::test]
    async fn test_memory_cache_cleanup_expired() {
        let cache = MemoryCache::with_ttl(Duration::from_millis(10));

        cache
            .insert("key1".to_string(), create_test_version_info())
            .await;
        cache
            .insert("key2".to_string(), create_test_version_info())
            .await;

        assert_eq!(cache.len(), 2);

        // Wait for entries to expire
        std::thread::sleep(Duration::from_millis(20));

        let removed = cache.cleanup_expired();
        assert_eq!(removed, 2);
        assert_eq!(cache.len(), 0);
    }

    #[tokio::test]
    async fn test_memory_cache_cleanup_partial() {
        let cache = MemoryCache::with_ttl(Duration::from_millis(200));

        cache
            .insert("key1".to_string(), create_test_version_info())
            .await;

        // Wait for first entry to almost expire
        std::thread::sleep(Duration::from_millis(150));

        // Insert second entry
        cache
            .insert("key2".to_string(), create_test_version_info())
            .await;

        // Wait for first to expire but not second
        std::thread::sleep(Duration::from_millis(100));

        let removed = cache.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 1);
        assert!(cache.get("key2").await.is_some());
    }

    #[tokio::test]
    async fn test_memory_cache_stats() {
        let cache = MemoryCache::with_ttl(Duration::from_millis(100));

        cache
            .insert("key1".to_string(), create_test_version_info())
            .await;
        cache
            .insert("key2".to_string(), create_test_version_info())
            .await;

        let stats = cache.stats();
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.expired_entries, 0);
        assert_eq!(stats.valid_entries, 2);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(150));

        let stats = cache.stats();
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.expired_entries, 2);
        assert_eq!(stats.valid_entries, 0);
    }

    #[test]
    fn test_cache_stats_display() {
        let stats = CacheStats {
            total_entries: 10,
            expired_entries: 3,
            valid_entries: 7,
        };
        let display = stats.to_string();
        assert!(display.contains("total: 10"));
        assert!(display.contains("expired: 3"));
        assert!(display.contains("valid: 7"));
    }

    #[tokio::test]
    async fn test_memory_cache_is_empty() {
        let cache = MemoryCache::with_ttl(Duration::from_secs(60));
        assert!(cache.is_empty());
        cache
            .insert("key".to_string(), create_test_version_info())
            .await;
        assert!(!cache.is_empty());
    }

    #[tokio::test]
    async fn test_read_cache_contains() {
        async fn assert_contains_via_trait<C: ReadCache>(cache: &C, key: &str) -> bool {
            cache.contains(key).await
        }

        let cache = MemoryCache::new();
        assert!(!assert_contains_via_trait(&cache, "key").await);

        cache
            .insert("key".to_string(), create_test_version_info())
            .await;
        assert!(assert_contains_via_trait(&cache, "key").await);
    }

    #[tokio::test]
    async fn test_write_cache_remove() {
        async fn insert_via_trait<C: WriteCache>(cache: &C, key: String, v: VersionInfo) {
            cache.insert(key, v).await;
        }
        async fn remove_via_trait<C: WriteCache>(cache: &C, key: &str) {
            cache.remove(key).await;
        }

        let cache = MemoryCache::new();
        insert_via_trait(&cache, "key".to_string(), create_test_version_info()).await;
        assert!(cache.get("key").await.is_some());

        remove_via_trait(&cache, "key").await;
        assert!(cache.get("key").await.is_none());
    }

    #[tokio::test]
    async fn test_write_cache_clear() {
        async fn clear_via_trait<C: WriteCache>(cache: &C) {
            cache.clear().await;
        }

        let cache = MemoryCache::new();
        cache
            .insert("key1".to_string(), create_test_version_info())
            .await;
        cache
            .insert("key2".to_string(), create_test_version_info())
            .await;
        assert_eq!(cache.len(), 2);

        clear_via_trait(&cache).await;
        assert!(cache.is_empty());
    }
}
