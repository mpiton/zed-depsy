//! Vulnerability cache for queried packages.
//!
//! Keeps the OSV result of each queried package version, so repeated lookups
//! skip the API until the entry expires.

use std::fmt::Display;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use super::osv::QueryResult;
use super::{Ecosystem, normalize_version_for_osv};
use crate::parsers::Dependency;

/// Default TTL for vulnerability cache (6 hours)
const DEFAULT_VULN_CACHE_TTL: Duration = Duration::from_secs(6 * 3600);

/// Cache key for vulnerability lookups
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct VulnCacheKey {
    /// Target ecosystem
    pub ecosystem: Ecosystem,
    /// Package name
    pub package_name: String,
    /// Package version
    pub version: String,
}

impl VulnCacheKey {
    /// Create a new cache key
    pub fn new(ecosystem: Ecosystem, package_name: &str, version: &str) -> Self {
        Self {
            ecosystem,
            package_name: package_name.to_string(),
            version: version.to_string(),
        }
    }

    /// Creates the key for `dep`'s resolved version.
    ///
    /// The version is normalized the same way as the OSV query, so readers
    /// and the background fetch agree on the key.
    pub fn for_dependency(ecosystem: Ecosystem, dep: &Dependency) -> Self {
        Self::new(
            ecosystem,
            &dep.name,
            &normalize_version_for_osv(dep.effective_version()),
        )
    }
}

/// OSV result of one package version and when it was stored
struct VulnCacheEntry {
    /// When the entry was inserted
    inserted_at: Instant,
    /// OSV result for this package version
    result: QueryResult,
}

/// Cleanup interval for background task (30 minutes)
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Stores OSV results per package version with a TTL.
///
/// Prevents redundant API calls to OSV.dev and lets every reader look up the
/// advisories of its own dependency version. Expired entries are neither
/// served nor counted as queried.
#[derive(Clone)]
pub struct VulnerabilityCache {
    /// Cache entries (package key -> OSV result and insertion time)
    entries: Arc<DashMap<VulnCacheKey, VulnCacheEntry>>,
    /// Cache TTL
    ttl: Duration,
}

impl VulnerabilityCache {
    /// Create a new cache with default TTL (6 hours) and spawn background cleanup
    pub fn new() -> Self {
        let cache = Self {
            entries: Arc::new(DashMap::new()),
            ttl: DEFAULT_VULN_CACHE_TTL,
        };
        Self::spawn_cleanup_task(cache.clone());
        cache
    }

    fn spawn_cleanup_task(cache: VulnerabilityCache) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            interval.tick().await; // Skip immediate first tick

            loop {
                interval.tick().await;

                let stats = cache.stats();
                let removed = cache.cleanup_expired();
                if removed > 0 {
                    tracing::info!(
                        "Background cleanup: removed {} expired entries from vulnerability cache (was: {})",
                        removed,
                        stats
                    );
                }
            }
        });
    }

    /// Create a cache with custom TTL in seconds (no background cleanup for tests)
    #[cfg(test)]
    pub fn with_ttl(ttl_secs: u64) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Stores the OSV result of a package version
    pub fn insert(&self, key: VulnCacheKey, result: QueryResult) {
        self.entries.insert(
            key,
            VulnCacheEntry {
                inserted_at: Instant::now(),
                result,
            },
        );
    }

    /// Returns the OSV result of a package version, unless missing or expired
    pub fn get(&self, key: &VulnCacheKey) -> Option<QueryResult> {
        self.entries
            .get(key)
            .filter(|entry| entry.inserted_at.elapsed() < self.ttl)
            .map(|entry| entry.result.clone())
    }

    /// Check if a package has been queried (and the query hasn't expired)
    pub fn contains(&self, key: &VulnCacheKey) -> bool {
        self.entries
            .get(key)
            .is_some_and(|entry| entry.inserted_at.elapsed() < self.ttl)
    }

    /// Clear all entries from cache
    #[cfg(test)]
    pub fn clear(&self) {
        self.entries.clear();
    }

    /// Get the number of entries in the cache
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the cache is empty
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn cleanup_expired(&self) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| entry.inserted_at.elapsed() < self.ttl);
        let removed = before - self.entries.len();
        if removed > 0 {
            tracing::debug!(
                "Cleaned up {} expired vulnerability cache entries ({} remaining)",
                removed,
                self.entries.len()
            );
        }
        removed
    }

    pub fn stats(&self) -> VulnCacheStats {
        let total = self.entries.len();
        let expired = self
            .entries
            .iter()
            .filter(|e| e.inserted_at.elapsed() >= self.ttl)
            .count();
        VulnCacheStats {
            total_entries: total,
            expired_entries: expired,
            valid_entries: total.saturating_sub(expired),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VulnCacheStats {
    pub total_entries: usize,
    pub expired_entries: usize,
    pub valid_entries: usize,
}

impl Display for VulnCacheStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "VulnCacheStats {{ total: {}, expired: {}, valid: {} }}",
            self.total_entries, self.expired_entries, self.valid_entries
        )
    }
}

impl Default for VulnerabilityCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_insert_and_contains() {
        let cache = VulnerabilityCache::with_ttl(3600);
        let key = VulnCacheKey::new(Ecosystem::Npm, "lodash", "4.17.0");

        assert!(!cache.contains(&key));
        cache.insert(key.clone(), QueryResult::default());
        assert!(cache.contains(&key));
    }

    #[test]
    fn expired_result_is_not_served() {
        let cache = VulnerabilityCache::with_ttl(0);
        let key = VulnCacheKey::new(Ecosystem::Npm, "minimist", "1.2.5");
        cache.insert(
            key.clone(),
            QueryResult {
                deprecated: true,
                ..QueryResult::default()
            },
        );

        std::thread::sleep(Duration::from_millis(10));

        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_cache_clear() {
        let cache = VulnerabilityCache::with_ttl(3600);
        let key = VulnCacheKey::new(Ecosystem::PyPI, "requests", "2.28.0");

        cache.insert(key.clone(), QueryResult::default());
        assert_eq!(cache.len(), 1);

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_with_custom_ttl() {
        let cache = VulnerabilityCache::with_ttl(3600);
        assert_eq!(cache.ttl, Duration::from_secs(3600));
    }

    #[test]
    fn test_vuln_cache_cleanup_expired() {
        // Use 10ms TTL for fast test
        let cache = VulnerabilityCache::with_ttl(0); // 0 seconds = immediate expiry
        let key1 = VulnCacheKey::new(Ecosystem::Npm, "pkg1", "1.0.0");
        let key2 = VulnCacheKey::new(Ecosystem::Npm, "pkg2", "1.0.0");

        cache.insert(key1, QueryResult::default());
        cache.insert(key2, QueryResult::default());

        assert_eq!(cache.len(), 2);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));

        let removed = cache.cleanup_expired();
        assert_eq!(removed, 2);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_vuln_cache_stats() {
        let cache = VulnerabilityCache::with_ttl(0); // Immediate expiry
        let key1 = VulnCacheKey::new(Ecosystem::Npm, "pkg1", "1.0.0");
        let key2 = VulnCacheKey::new(Ecosystem::Npm, "pkg2", "1.0.0");

        cache.insert(key1, QueryResult::default());
        cache.insert(key2, QueryResult::default());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));

        let stats = cache.stats();
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.expired_entries, 2);
        assert_eq!(stats.valid_entries, 0);
    }

    #[test]
    fn test_vuln_cache_stats_display() {
        let stats = VulnCacheStats {
            total_entries: 5,
            expired_entries: 2,
            valid_entries: 3,
        };
        let display = stats.to_string();
        assert!(display.contains("total: 5"));
        assert!(display.contains("expired: 2"));
        assert!(display.contains("valid: 3"));
    }
}
