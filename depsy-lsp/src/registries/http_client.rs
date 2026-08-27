//! Shared HTTP client for all registry clients.
//!
//! This module provides a shared HTTP client with proper configuration
//! for connection pooling, HTTP/2, and timeout handling. Sharing a single
//! client across all registries enables:
//!
//! - Connection reuse across different registries
//! - HTTP/2 multiplexing where supported
//! - Reduced TLS handshake overhead
//! - Shared DNS cache
//! - Lower memory footprint

use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;

const USER_AGENT: &str = concat!(
    "depsy-lsp/",
    env!("CARGO_PKG_VERSION"),
    " (https://github.com/mpiton/zed-depsy)"
);

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub fn create_shared_client() -> anyhow::Result<Arc<Client>> {
    let client = Client::builder()
        .user_agent(USER_AGENT)
        .timeout(DEFAULT_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .pool_idle_timeout(POOL_IDLE_TIMEOUT)
        .pool_max_idle_per_host(10)
        .tcp_keepalive(Duration::from_secs(60))
        .build()?;

    Ok(Arc::new(client))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registries::Registry;
    use crate::registries::crates_io::CratesIoRegistry;
    use crate::registries::go_proxy::GoProxyRegistry;
    use crate::registries::npm::NpmRegistry;
    use crate::registries::nuget::NuGetRegistry;
    use crate::registries::packagist::PackagistRegistry;
    use crate::registries::pub_dev::PubDevRegistry;
    use crate::registries::pypi::PyPiRegistry;
    use crate::registries::rubygems::RubyGemsRegistry;

    #[test]
    fn test_create_shared_client() {
        let client = create_shared_client().expect("Failed to create client");
        assert!(Arc::strong_count(&client) == 1);
    }

    #[test]
    fn test_client_can_be_cloned() {
        let client = create_shared_client().expect("Failed to create client");
        let client2 = Arc::clone(&client);
        assert!(Arc::strong_count(&client) == 2);
        drop(client2);
        assert!(Arc::strong_count(&client) == 1);
    }

    #[test]
    fn test_registries_share_client_instance() {
        use crate::config::NpmRegistryConfig;

        let shared_client = create_shared_client().expect("Failed to create client");
        let client_ptr = Arc::as_ptr(&shared_client);

        let crates_io = CratesIoRegistry::with_client(Arc::clone(&shared_client));
        let npm = NpmRegistry::with_client_and_config(
            Arc::clone(&shared_client),
            &NpmRegistryConfig::default(),
        );
        let pypi = PyPiRegistry::with_client(Arc::clone(&shared_client));
        let go_proxy = GoProxyRegistry::with_client(Arc::clone(&shared_client));
        let packagist = PackagistRegistry::with_client(Arc::clone(&shared_client));
        let pub_dev = PubDevRegistry::with_client(Arc::clone(&shared_client));
        let nuget = NuGetRegistry::with_client(Arc::clone(&shared_client));
        let rubygems = RubyGemsRegistry::with_client(Arc::clone(&shared_client));

        assert_eq!(Arc::as_ptr(&crates_io.http_client()), client_ptr);
        assert_eq!(Arc::as_ptr(&npm.http_client()), client_ptr);
        assert_eq!(Arc::as_ptr(&pypi.http_client()), client_ptr);
        assert_eq!(Arc::as_ptr(&go_proxy.http_client()), client_ptr);
        assert_eq!(Arc::as_ptr(&packagist.http_client()), client_ptr);
        assert_eq!(Arc::as_ptr(&pub_dev.http_client()), client_ptr);
        assert_eq!(Arc::as_ptr(&nuget.http_client()), client_ptr);
        assert_eq!(Arc::as_ptr(&rubygems.http_client()), client_ptr);

        assert_eq!(Arc::strong_count(&shared_client), 9);
    }

    #[test]
    fn test_default_registries_create_separate_clients() {
        let crates_io = CratesIoRegistry::default();
        let npm = NpmRegistry::default();

        assert_ne!(
            Arc::as_ptr(&crates_io.http_client()),
            Arc::as_ptr(&npm.http_client())
        );
    }
}
