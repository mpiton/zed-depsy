//! Authentication support for private registries.
//!
//! This module provides authentication mechanisms for accessing private package registries.
//! Tokens are read from environment variables only - they should NEVER be stored in LSP settings.
//!
//! ## Security
//!
//! - Tokens are read from environment variables at initialization time
//! - Tokens are NEVER logged in any circumstances
//! - All authenticated requests use HTTPS only
//! - Sensitive data is redacted in error messages
//!
//! ## Architecture
//!
//! The authentication system is built around the [`TokenProvider`] trait:
//!
//! - [`TokenProvider`]: Trait for getting auth headers for requests
//! - [`EnvTokenProvider`]: Reads token from environment variable
//! - [`TokenProviderManager`]: Associates tokens with registry URL prefixes
//!
//! ## Submodules
//!
//! - [`cargo_credentials`]: Parser for Cargo credentials files (`~/.cargo/credentials.toml`)
//! - [`npmrc`]: Parser for npm configuration files (`.npmrc`)

pub mod cargo_credentials;
pub mod npmrc;

use core::fmt::{self, Write};
use std::sync::Arc;

use hashbrown::HashMap;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use tokio::sync::RwLock;

/// Token provider trait for registry authentication.
///
/// Implementations provide authorization headers for HTTP requests to registries.
/// All implementations must be thread-safe (`Send + Sync`).
pub trait TokenProvider: Send + Sync {
    /// Get authorization headers for a request to the given URL.
    ///
    /// Returns `Some(headers)` if authentication should be applied,
    /// or `None` if no authentication is needed.
    fn get_auth_headers(&self, url: &str) -> Option<HeaderMap>;
}

/// Environment variable token provider.
///
/// Reads a token from an environment variable at construction time
/// and provides Bearer authentication headers.
pub struct EnvTokenProvider {
    token: String,
}

impl EnvTokenProvider {
    /// Create a new provider with the given token.
    ///
    /// # Security
    /// The token is stored in memory. Ensure tokens are not logged.
    pub fn new(token: String) -> Self {
        Self { token }
    }
}

impl TokenProvider for EnvTokenProvider {
    fn get_auth_headers(&self, _url: &str) -> Option<HeaderMap> {
        let auth_value = format!("Bearer {}", self.token);
        let mut headers = HeaderMap::new();
        if let Ok(value) = HeaderValue::from_str(&auth_value) {
            headers.insert(AUTHORIZATION, value);
            Some(headers)
        } else {
            None
        }
    }
}

/// No-op provider for public registries.
///
/// Always returns `None`, indicating no authentication is needed.
#[cfg(test)]
pub struct NoAuthProvider;

#[cfg(test)]
impl TokenProvider for NoAuthProvider {
    fn get_auth_headers(&self, _url: &str) -> Option<HeaderMap> {
        None
    }
}

/// Token provider manager for URL-based provider selection.
///
/// Associates registry URL prefixes with token providers, allowing
/// different authentication for different registries.
///
/// # Thread Safety
///
/// Uses `RwLock` for concurrent access - reads are parallel, writes are exclusive.
///
/// # Example
///
/// ```ignore
/// use depsy_lsp::auth::{TokenProviderManager, EnvTokenProvider};
/// use std::sync::Arc;
///
/// let manager = TokenProviderManager::new();
///
/// // Register provider for GitHub npm
/// if let Ok(token) = std::env::var("GITHUB_TOKEN") {
///     let provider = EnvTokenProvider::new(token);
///     manager.register("https://npm.pkg.github.com".to_string(), Arc::new(provider)).await;
/// }
///
/// // Get headers for a request
/// let headers = manager.get_auth_headers("https://npm.pkg.github.com/@org/package").await;
/// ```
pub struct TokenProviderManager {
    providers: RwLock<HashMap<String, Arc<dyn TokenProvider>>>,
}

impl Default for TokenProviderManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenProviderManager {
    /// Create a new empty provider manager.
    pub fn new() -> Self {
        Self {
            providers: RwLock::new(HashMap::new()),
        }
    }

    /// Register a token provider for a registry URL prefix.
    ///
    /// The URL prefix is used for matching - requests to URLs starting with
    /// this prefix will use the registered provider.
    ///
    /// # Security
    /// Only register providers for HTTPS URLs to prevent credential leakage.
    pub async fn register(&self, url_prefix: String, provider: Arc<dyn TokenProvider>) {
        if !url_prefix.starts_with("https://") {
            tracing::error!(
                "SECURITY: Refusing to register auth provider for non-HTTPS URL: {}",
                url_prefix
            );
            return;
        }

        tracing::debug!("Registering auth provider for URL prefix: {}", url_prefix);
        let mut providers = self.providers.write().await;
        providers.insert(url_prefix, provider);
    }

    /// Get authentication headers for a request URL.
    ///
    /// Finds the provider with the longest matching URL prefix and returns
    /// its auth headers. Returns empty headers if no provider matches.
    ///
    /// # Matching
    /// Uses longest-prefix matching to support nested registries.
    #[cfg(test)]
    pub async fn get_auth_headers(&self, url: &str) -> HeaderMap {
        let providers = self.providers.read().await;

        // Find the longest matching URL prefix
        let mut best_match: Option<(&str, &Arc<dyn TokenProvider>)> = None;

        for (prefix, provider) in providers.iter() {
            if url.starts_with(prefix) {
                match best_match {
                    None => best_match = Some((prefix, provider)),
                    Some((current_prefix, _)) if prefix.len() > current_prefix.len() => {
                        best_match = Some((prefix, provider));
                    }
                    _ => {}
                }
            }
        }

        if let Some((prefix, provider)) = best_match
            && let Some(headers) = provider.get_auth_headers(url)
        {
            tracing::trace!(
                "Using auth provider for prefix '{}' on URL: {}",
                prefix,
                url
            );
            return headers;
        }

        HeaderMap::new()
    }

    /// Check if a provider is registered for a URL prefix.
    #[cfg(test)]
    pub async fn has_provider(&self, url_prefix: &str) -> bool {
        let providers = self.providers.read().await;
        providers.contains_key(url_prefix)
    }

    /// Get the number of registered providers.
    pub async fn provider_count(&self) -> usize {
        let providers = self.providers.read().await;
        providers.len()
    }
}

/// Returns an <code>[fmt::Display] + [fmt::Debug]</code> implementation
/// which redacts the given token for safe logging.
///
/// Shows only the first few characters to help identify which token is in use
/// without exposing the full secret.
///
/// # Unicode Handling
///
/// The `fmt` implementation is UTF-8 safe and operates on characters, not bytes.
#[must_use = "returns a type implementing Display and Debug, which does not have any effects unless they are used"]
pub fn fmt_redact_token(token: &str) -> impl fmt::Display + fmt::Debug {
    fmt::from_fn(move |f| {
        if token.chars().count() <= 4 {
            f.write_str("****")
        } else {
            token.chars().take(4).try_for_each(|c| f.write_char(c))?;
            f.write_str("...")
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redact_token(token: &str) -> String {
        fmt_redact_token(token).to_string()
    }

    #[test]
    fn test_redact_token() {
        assert_eq!(redact_token("abc"), "****");
        assert_eq!(redact_token("abcdefgh"), "abcd...");
        assert_eq!(redact_token("npm_1234567890"), "npm_...");
    }

    #[test]
    fn test_redact_token_utf8_safe() {
        // Multi-byte UTF-8 characters should not panic
        assert_eq!(redact_token("日本語テスト"), "日本語テ...");
        assert_eq!(redact_token("🔑🔒🔓🔐secret"), "🔑🔒🔓🔐...");
        assert_eq!(redact_token("émojis"), "émoj...");
        // Short multi-byte tokens should be fully redacted
        assert_eq!(redact_token("日本"), "****");
        assert_eq!(redact_token("🔑🔒"), "****");
    }

    #[test]
    fn test_env_token_provider_new() {
        let provider = EnvTokenProvider::new("test_token".to_string());
        let headers = provider.get_auth_headers("https://example.com");
        assert!(headers.is_some());
        let headers = headers.unwrap();
        assert!(headers.contains_key(AUTHORIZATION));
        let auth_value = headers.get(AUTHORIZATION).unwrap().to_str().unwrap();
        assert_eq!(auth_value, "Bearer test_token");
    }

    #[test]
    fn test_no_auth_provider() {
        let provider = NoAuthProvider;
        let headers = provider.get_auth_headers("https://example.com");
        assert!(headers.is_none());
    }

    #[tokio::test]
    async fn test_token_provider_manager_register_https() {
        let manager = TokenProviderManager::new();
        let provider = Arc::new(EnvTokenProvider::new("token123".to_string()));

        manager
            .register("https://npm.company.com".to_string(), provider)
            .await;

        assert!(manager.has_provider("https://npm.company.com").await);
        assert_eq!(manager.provider_count().await, 1);
    }

    #[tokio::test]
    async fn test_token_provider_manager_reject_http() {
        let manager = TokenProviderManager::new();
        let provider = Arc::new(EnvTokenProvider::new("token123".to_string()));

        // HTTP should be rejected
        manager
            .register("http://insecure.com".to_string(), provider)
            .await;

        assert!(!manager.has_provider("http://insecure.com").await);
        assert_eq!(manager.provider_count().await, 0);
    }

    #[tokio::test]
    async fn test_token_provider_manager_get_headers() {
        let manager = TokenProviderManager::new();
        let provider = Arc::new(EnvTokenProvider::new("my_secret_token".to_string()));

        manager
            .register("https://npm.company.com".to_string(), provider)
            .await;

        // Matching URL
        let headers = manager
            .get_auth_headers("https://npm.company.com/@company/utils")
            .await;
        assert!(!headers.is_empty());
        let auth = headers.get(AUTHORIZATION).unwrap().to_str().unwrap();
        assert_eq!(auth, "Bearer my_secret_token");

        // Non-matching URL
        let headers = manager
            .get_auth_headers("https://registry.npmjs.org/lodash")
            .await;
        assert!(headers.is_empty());
    }

    #[tokio::test]
    async fn test_token_provider_manager_longest_prefix() {
        let manager = TokenProviderManager::new();

        // Register more specific first
        let provider1 = Arc::new(EnvTokenProvider::new("specific_token".to_string()));
        manager
            .register("https://npm.company.com/@internal".to_string(), provider1)
            .await;

        // Register less specific
        let provider2 = Arc::new(EnvTokenProvider::new("general_token".to_string()));
        manager
            .register("https://npm.company.com".to_string(), provider2)
            .await;

        // Should match the more specific provider
        let headers = manager
            .get_auth_headers("https://npm.company.com/@internal/pkg")
            .await;
        let auth = headers.get(AUTHORIZATION).unwrap().to_str().unwrap();
        assert_eq!(auth, "Bearer specific_token");

        // Should match the less specific provider
        let headers = manager
            .get_auth_headers("https://npm.company.com/@public/pkg")
            .await;
        let auth = headers.get(AUTHORIZATION).unwrap().to_str().unwrap();
        assert_eq!(auth, "Bearer general_token");
    }
}
