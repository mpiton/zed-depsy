//! Smoke test: HybridAdvisoryCache constructs without panic and survives a
//! cache-miss lookup. Guards Task 26 of the RustSec advisory cache plan
//! (issue #237): the LSP backend must be able to instantiate the cache at
//! startup without exploding even when the SQLite layer is unavailable.

use std::sync::Arc;

use depsy_lsp::cache::{AdvisoryReadCache, HybridAdvisoryCache};
use depsy_lsp::config::AdvisoryCacheConfig;

#[tokio::test]
async fn hybrid_advisory_cache_constructs_without_panic() {
    // Use an isolated db_path so a previous run that persisted a hit for
    // RUSTSEC-2020-0036 in the user's default cache cannot turn this miss
    // assertion into a flake.
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = AdvisoryCacheConfig {
        enabled: true,
        ttl_secs: 60,
        negative_ttl_secs: 30,
        db_path: Some(tmp.path().join("advisory_cache.db")),
    };
    let cache = Arc::new(HybridAdvisoryCache::from_config(&config));
    assert!(cache.get("RUSTSEC-2020-0036").await.is_none());
}
