//! Parser for Cargo credentials files.
//!
//! Parses `~/.cargo/credentials.toml` or `$CARGO_HOME/credentials.toml`
//! to extract authentication tokens for alternative Cargo registries.
//!
//! Note: This module provides parsing utilities for Cargo credential files.
//! The parsing logic is tested; file I/O integration will be added when
//! this is wired into the main auth flow.

use hashbrown::HashMap;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CargoCredentials {
    #[serde(default)]
    registries: HashMap<String, RegistryCredential>,
}

#[derive(Debug, Deserialize)]
struct RegistryCredential {
    token: Option<String>,
}

pub fn parse_credentials_content(content: &str) -> HashMap<String, String> {
    let credentials: CargoCredentials = match toml::from_str(content) {
        Ok(c) => c,
        Err(_) => return HashMap::new(),
    };

    credentials
        .registries
        .into_iter()
        .filter_map(|(name, cred)| cred.token.map(|t| (name, t)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_credentials() {
        let content = r#"
[registries.my-registry]
token = "secret_token_123"

[registries.another-registry]
token = "another_secret"
"#;

        let result = parse_credentials_content(content);

        assert_eq!(result.len(), 2);
        assert_eq!(
            result.get("my-registry"),
            Some(&"secret_token_123".to_string())
        );
        assert_eq!(
            result.get("another-registry"),
            Some(&"another_secret".to_string())
        );
    }

    #[test]
    fn test_parse_empty_credentials() {
        let content = "";
        let result = parse_credentials_content(content);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_no_registries() {
        let content = r#"
[net]
git-fetch-with-cli = true
"#;
        let result = parse_credentials_content(content);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_registry_without_token() {
        let content = r#"
[registries.my-registry]
# token not set
"#;
        let result = parse_credentials_content(content);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_mixed_registries() {
        let content = r#"
[registries.with-token]
token = "has_token"

[registries.without-token]
# no token here
"#;
        let result = parse_credentials_content(content);
        assert_eq!(result.len(), 1);
        assert_eq!(result.get("with-token"), Some(&"has_token".to_string()));
    }
}
