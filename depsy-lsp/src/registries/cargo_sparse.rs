//! # Cargo Sparse Registry Client
//!
//! Client for alternative Cargo registries using the sparse index protocol.
//! Supports registries like Kellnr, Cloudsmith, and other Cargo-compatible registries.

use std::sync::Arc;

use hashbrown::HashMap;
use reqwest::Client;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::Deserialize;

use super::http_client::create_shared_client;
use super::version_utils::is_prerelease_rust;
use super::{Registry, VersionInfo};

/// Compute the sparse index path for a crate name.
///
/// Path format follows the Cargo registry index specification:
/// - 1 character: `1/{name}`
/// - 2 characters: `2/{name}`
/// - 3 characters: `3/{first_char}/{name}`
/// - 4+ characters: `{first_two}/{next_two}/{name}`
fn sparse_index_path(name: &str) -> String {
    let name = name.to_lowercase();
    match name.len() {
        0 => name,
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[..1]),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    }
}

/// A single entry from the sparse index (one JSON line per version)
#[derive(Debug, Deserialize)]
struct SparseIndexEntry {
    #[allow(dead_code)]
    name: String,
    vers: String,
    #[serde(default)]
    yanked: bool,
}

/// Client for Cargo sparse registries (alternative registries)
pub struct CargoSparseRegistry {
    client: Arc<Client>,
    index_url: String,
    auth_headers: Option<HeaderMap>,
}

impl CargoSparseRegistry {
    /// Create a new sparse registry client with the given configuration.
    pub fn with_client_and_config(
        client: Arc<Client>,
        index_url: String,
        auth_token: Option<String>,
    ) -> Self {
        let auth_headers = auth_token.and_then(|token| {
            let mut headers = HeaderMap::new();
            let auth_value = format!("Bearer {token}");
            if let Ok(value) = HeaderValue::from_str(&auth_value) {
                headers.insert(AUTHORIZATION, value);
                Some(headers)
            } else {
                None
            }
        });

        Self {
            client,
            index_url: index_url.trim_end_matches('/').to_string(),
            auth_headers,
        }
    }
}

impl Default for CargoSparseRegistry {
    fn default() -> Self {
        Self::with_client_and_config(
            create_shared_client().expect("Failed to create HTTP client"),
            String::new(),
            None,
        )
    }
}

impl Registry for CargoSparseRegistry {
    fn http_client(&self) -> Arc<Client> {
        Arc::clone(&self.client)
    }

    async fn get_version_info(&self, package_name: &str) -> anyhow::Result<VersionInfo> {
        let path = sparse_index_path(package_name);
        let url = format!("{}/{path}", self.index_url);

        let mut request = self.client.get(&url);
        if let Some(headers) = &self.auth_headers {
            for (key, value) in headers.iter() {
                request = request.header(key, value);
            }
        }

        let response = request.send().await?;

        anyhow::ensure!(
            response.status().is_success(),
            "Failed to fetch crate info for {package_name} from sparse registry: {}",
            response.status()
        );

        let body = response.text().await?;

        // Parse newline-delimited JSON entries
        let mut all_versions: Vec<String> = Vec::new();
        let mut yanked_versions: Vec<String> = Vec::new();

        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            match serde_json::from_str::<SparseIndexEntry>(line) {
                Ok(entry) => {
                    if entry.yanked {
                        yanked_versions.push(entry.vers);
                    } else {
                        all_versions.push(entry.vers);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to parse sparse index entry for {}: {}",
                        package_name,
                        e
                    );
                }
            }
        }

        // Find latest stable version (not yanked, not prerelease)
        let latest_stable = all_versions
            .iter()
            .filter(|v| !is_prerelease_rust(v))
            .max_by(|a, b| {
                semver::Version::parse(a)
                    .unwrap_or_else(|_| semver::Version::new(0, 0, 0))
                    .cmp(
                        &semver::Version::parse(b)
                            .unwrap_or_else(|_| semver::Version::new(0, 0, 0)),
                    )
            })
            .cloned();

        // Find latest prerelease
        let latest_prerelease = all_versions
            .iter()
            .filter(|v| is_prerelease_rust(v))
            .max_by(|a, b| {
                semver::Version::parse(a)
                    .unwrap_or_else(|_| semver::Version::new(0, 0, 0))
                    .cmp(
                        &semver::Version::parse(b)
                            .unwrap_or_else(|_| semver::Version::new(0, 0, 0)),
                    )
            })
            .cloned();

        // Check if the most recent version overall (by semver) is yanked
        let semver_cmp = |a: &&String, b: &&String| {
            semver::Version::parse(a)
                .unwrap_or_else(|_| semver::Version::new(0, 0, 0))
                .cmp(&semver::Version::parse(b).unwrap_or_else(|_| semver::Version::new(0, 0, 0)))
        };
        let max_non_yanked = all_versions.iter().max_by(semver_cmp);
        let max_yanked = yanked_versions.iter().max_by(semver_cmp);
        let yanked = match (max_non_yanked, max_yanked) {
            (Some(non_yanked), Some(yanked_ver)) => {
                // If the highest yanked version is newer than the highest non-yanked, yanked = true
                semver_cmp(&yanked_ver, &non_yanked) == std::cmp::Ordering::Greater
            }
            (None, Some(_)) => true, // All versions are yanked
            _ => false,              // No yanked versions, or no versions at all
        };

        Ok(VersionInfo {
            latest: latest_stable,
            latest_prerelease,
            versions: all_versions,
            description: None,
            homepage: None,
            repository: None,
            license: None,
            vulnerabilities: vec![],
            deprecated: false,
            yanked,
            yanked_versions,
            release_dates: HashMap::new(),
            transitive_vulnerabilities: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sparse_index_path_single_char() {
        assert_eq!(sparse_index_path("a"), "1/a");
    }

    #[test]
    fn test_sparse_index_path_two_chars() {
        assert_eq!(sparse_index_path("ab"), "2/ab");
    }

    #[test]
    fn test_sparse_index_path_three_chars() {
        assert_eq!(sparse_index_path("foo"), "3/f/foo");
    }

    #[test]
    fn test_sparse_index_path_four_plus_chars() {
        assert_eq!(sparse_index_path("serde"), "se/rd/serde");
        assert_eq!(sparse_index_path("tokio"), "to/ki/tokio");
        assert_eq!(sparse_index_path("my-crate"), "my/-c/my-crate");
    }

    #[test]
    fn test_sparse_index_path_case_insensitive() {
        assert_eq!(sparse_index_path("Serde"), "se/rd/serde");
        assert_eq!(sparse_index_path("TOKIO"), "to/ki/tokio");
    }

    #[test]
    fn test_parse_sparse_index_entry() {
        let line = r#"{"name":"serde","vers":"1.0.0","deps":[],"cksum":"abc","features":{},"yanked":false}"#;
        let entry: SparseIndexEntry = serde_json::from_str(line).unwrap();
        assert_eq!(entry.name, "serde");
        assert_eq!(entry.vers, "1.0.0");
        assert!(!entry.yanked);
    }

    #[test]
    fn test_parse_sparse_index_entry_yanked() {
        let line = r#"{"name":"serde","vers":"0.9.0","deps":[],"cksum":"abc","features":{},"yanked":true}"#;
        let entry: SparseIndexEntry = serde_json::from_str(line).unwrap();
        assert_eq!(entry.vers, "0.9.0");
        assert!(entry.yanked);
    }
}
