//! In-memory advisory cache (L1 layer) backed by [`DashMap`].

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;

use super::{AdvisoryReadCache, AdvisoryWriteCache, CachedAdvisory};

/// Default TTL for cached advisory entries (24 hours).
pub const DEFAULT_ADVISORY_TTL: Duration = Duration::from_secs(86_400);

#[derive(Clone, Debug)]
struct MemoryAdvisoryEntry {
    advisory: CachedAdvisory,
    inserted_at: Instant,
    ttl: Duration,
}

impl MemoryAdvisoryEntry {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
    }
}

/// Thread-safe, in-memory advisory cache built on a [`DashMap`].
#[derive(Clone)]
pub struct MemoryAdvisoryCache {
    entries: Arc<DashMap<String, MemoryAdvisoryEntry>>,
    ttl: Duration,
}

impl Default for MemoryAdvisoryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryAdvisoryCache {
    /// Build a cache with the default 24-hour TTL.
    pub fn new() -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            ttl: DEFAULT_ADVISORY_TTL,
        }
    }

    /// Build a cache with a custom TTL (used by tests and for negative caching).
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            ttl,
        }
    }

    /// The configured TTL applied to fresh inserts.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Insert with an explicit TTL instead of the cache-wide default.
    ///
    /// Used by [`super::HybridAdvisoryCache`] when backfilling the L1 layer
    /// from an L2 hit so that an entry near SQLite expiry does not gain a
    /// fresh full-length TTL by being read.
    pub async fn insert_with_remaining_ttl(&self, advisory: CachedAdvisory, remaining: Duration) {
        if remaining.is_zero() {
            return;
        }
        self.entries.insert(
            advisory.id.clone(),
            MemoryAdvisoryEntry {
                advisory,
                inserted_at: Instant::now(),
                ttl: remaining,
            },
        );
    }
}

#[async_trait]
impl AdvisoryReadCache for MemoryAdvisoryCache {
    async fn get(&self, advisory_id: &str) -> Option<CachedAdvisory> {
        self.entries
            .get(advisory_id)
            .and_then(|entry| (!entry.is_expired()).then(|| entry.advisory.clone()))
    }
}

#[async_trait]
impl AdvisoryWriteCache for MemoryAdvisoryCache {
    async fn insert(&self, advisory: CachedAdvisory) {
        // A zero TTL marks the cache as disabled — drop writes so disabled
        // mode does not accumulate entries that are immediately expired but
        // still occupy memory until cleanup runs.
        if self.ttl.is_zero() {
            return;
        }
        self.entries.insert(
            advisory.id.clone(),
            MemoryAdvisoryEntry {
                advisory,
                inserted_at: Instant::now(),
                ttl: self.ttl,
            },
        );
    }

    async fn remove(&self, advisory_id: &str) {
        self.entries.remove(advisory_id);
    }

    async fn clear(&self) {
        self.entries.clear();
    }
}

impl MemoryAdvisoryCache {
    /// Remove every expired entry. Returns the number of entries removed.
    pub fn cleanup_expired(&self) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| !entry.is_expired());
        before.saturating_sub(self.entries.len())
    }

    /// Snapshot statistics about the cache.
    pub fn stats(&self) -> AdvisoryCacheStats {
        let total = self.entries.len();
        let expired = self.entries.iter().filter(|e| e.is_expired()).count();
        AdvisoryCacheStats {
            total,
            expired,
            valid: total.saturating_sub(expired),
        }
    }

    /// Test-only length accessor.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Test-only emptiness check.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Snapshot statistics for an advisory cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdvisoryCacheStats {
    pub total: usize,
    pub expired: usize,
    pub valid: usize,
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::super::AdvisoryKind;
    use super::*;

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
    async fn insert_and_get_round_trip() {
        let cache = MemoryAdvisoryCache::new();
        let advisory = sample_found();
        cache.insert(advisory.clone()).await;
        assert_eq!(cache.get(&advisory.id).await, Some(advisory));
    }

    #[tokio::test]
    async fn missing_id_returns_none() {
        let cache = MemoryAdvisoryCache::new();
        assert!(cache.get("RUSTSEC-9999-9999").await.is_none());
    }

    fn sample_not_found(id: &str) -> CachedAdvisory {
        CachedAdvisory {
            id: id.to_string(),
            kind: AdvisoryKind::NotFound,
            fetched_at: SystemTime::UNIX_EPOCH,
        }
    }

    #[tokio::test]
    async fn second_insert_overwrites_first() {
        let cache = MemoryAdvisoryCache::new();
        cache.insert(sample_found()).await;
        let replacement = CachedAdvisory {
            id: "RUSTSEC-2020-0036".to_string(),
            kind: AdvisoryKind::Found {
                summary: None,
                unmaintained: false,
            },
            fetched_at: SystemTime::UNIX_EPOCH,
        };
        cache.insert(replacement.clone()).await;
        assert_eq!(cache.get(&replacement.id).await, Some(replacement));
    }

    #[tokio::test]
    async fn remove_deletes_entry() {
        let cache = MemoryAdvisoryCache::new();
        cache.insert(sample_found()).await;
        cache.remove("RUSTSEC-2020-0036").await;
        assert!(cache.get("RUSTSEC-2020-0036").await.is_none());
    }

    #[tokio::test]
    async fn clear_empties_cache() {
        let cache = MemoryAdvisoryCache::new();
        cache.insert(sample_found()).await;
        cache.insert(sample_not_found("RUSTSEC-9999-0001")).await;
        cache.clear().await;
        assert!(cache.get("RUSTSEC-2020-0036").await.is_none());
        assert!(cache.get("RUSTSEC-9999-0001").await.is_none());
    }

    #[tokio::test]
    async fn expired_entry_is_treated_as_missing() {
        let cache = MemoryAdvisoryCache::with_ttl(Duration::from_millis(5));
        cache.insert(sample_found()).await;
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert!(cache.get("RUSTSEC-2020-0036").await.is_none());
    }

    #[tokio::test]
    async fn fresh_entry_is_returned_before_expiry() {
        let cache = MemoryAdvisoryCache::with_ttl(Duration::from_millis(200));
        cache.insert(sample_found()).await;
        let value = cache.get("RUSTSEC-2020-0036").await;
        assert!(matches!(value, Some(c) if c.kind == AdvisoryKind::Found {
            summary: Some("unmaintained".to_string()),
            unmaintained: true,
        }));
    }

    #[tokio::test]
    async fn cleanup_expired_removes_only_expired_entries() {
        let cache = MemoryAdvisoryCache::with_ttl(Duration::from_millis(20));
        cache.insert(sample_found()).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        cache.insert(sample_not_found("RUSTSEC-9999-0001")).await;

        let removed = cache.cleanup_expired();
        assert_eq!(removed, 1);
        assert!(cache.get("RUSTSEC-2020-0036").await.is_none());
        assert!(cache.get("RUSTSEC-9999-0001").await.is_some());
    }

    #[tokio::test]
    async fn ttl_getter_returns_configured_ttl() {
        let cache = MemoryAdvisoryCache::with_ttl(Duration::from_secs(1234));
        assert_eq!(cache.ttl(), Duration::from_secs(1234));
        let default_cache = MemoryAdvisoryCache::new();
        assert_eq!(default_cache.ttl(), DEFAULT_ADVISORY_TTL);
    }

    #[tokio::test]
    async fn insert_with_remaining_ttl_uses_explicit_value_not_default() {
        let cache = MemoryAdvisoryCache::with_ttl(Duration::from_secs(60));
        cache
            .insert_with_remaining_ttl(sample_found(), Duration::from_millis(20))
            .await;
        // The entry must respect the *short* explicit TTL, not the 60-second
        // default, otherwise backfill would silently extend SQLite TTLs.
        assert!(cache.get("RUSTSEC-2020-0036").await.is_some());
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(cache.get("RUSTSEC-2020-0036").await.is_none());
    }

    #[tokio::test]
    async fn stats_report_total_expired_and_valid() {
        let cache = MemoryAdvisoryCache::with_ttl(Duration::from_millis(20));
        cache.insert(sample_found()).await;
        let before = cache.stats();
        assert_eq!(before.total, 1);
        assert_eq!(before.expired, 0);
        assert_eq!(before.valid, 1);
        tokio::time::sleep(Duration::from_millis(30)).await;
        let after = cache.stats();
        assert_eq!(after.total, 1);
        assert_eq!(after.expired, 1);
        assert_eq!(after.valid, 0);
    }
}
