//! Parser for `.npmrc` configuration files.
//!
//! Parses npm configuration to extract authentication tokens and registry URLs.
//! Supports environment variable substitution (`${VAR}` syntax).
//!
//! Note: This module provides parsing utilities for .npmrc files.
//! The parsing logic is tested; file I/O integration will be added when
//! this is wired into the main auth flow.

#[cfg(test)]
fn parse_token_from_content(content: &str) -> Option<String> {
    for line in content.lines() {
        let line = line.trim();

        // Skip comments
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        // Look for _authToken patterns
        // Format: _authToken=TOKEN or //registry.example.com/:_authToken=TOKEN
        if let Some(token_part) = extract_auth_token(line) {
            return resolve_env_var(token_part);
        }
    }

    None
}

#[cfg(test)]
fn parse_registry_from_content(content: &str) -> Option<String> {
    for line in content.lines() {
        let line = line.trim();

        // Skip comments
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        // Look for registry=URL pattern
        if let Some(url) = line.strip_prefix("registry=") {
            let url = url.trim();
            if !url.is_empty() {
                return Some(url.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
fn extract_auth_token(line: &str) -> Option<&str> {
    // Direct _authToken=...
    if let Some(token) = line.strip_prefix("_authToken=") {
        return Some(token.trim());
    }

    // Registry-specific: //registry.example.com/:_authToken=...
    if line.starts_with("//")
        && let Some(idx) = line.find(":_authToken=")
    {
        return Some(line[idx + 12..].trim());
    }

    None
}

#[cfg(test)]
fn resolve_env_var(value: &str) -> Option<String> {
    // Handle ${VAR} syntax
    if let Some(inner) = value.strip_prefix("${").and_then(|v| v.strip_suffix('}')) {
        return std::env::var(inner).ok();
    }

    // Handle $VAR syntax (without braces)
    if let Some(var_name) = value.strip_prefix('$')
        && !var_name.contains('{')
    {
        return std::env::var(var_name).ok();
    }

    // Return as-is if not an env var reference
    if !value.is_empty() {
        Some(value.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_parse_direct_token() {
        let content = "_authToken=npm_abc123";
        assert_eq!(
            parse_token_from_content(content),
            Some("npm_abc123".to_string())
        );
    }

    #[test]
    fn test_parse_registry_scoped_token() {
        let content = "//npm.company.com/:_authToken=npm_xyz789";
        assert_eq!(
            parse_token_from_content(content),
            Some("npm_xyz789".to_string())
        );
    }

    #[test]
    #[serial]
    fn test_parse_env_var_token() {
        // SAFETY: serial_test ensures this test runs exclusively, preventing race conditions
        unsafe {
            std::env::set_var("TEST_NPM_TOKEN", "env_token_value");
        }
        let content = "_authToken=${TEST_NPM_TOKEN}";
        assert_eq!(
            parse_token_from_content(content),
            Some("env_token_value".to_string())
        );
        // SAFETY: serial_test ensures this test runs exclusively, preventing race conditions
        unsafe {
            std::env::remove_var("TEST_NPM_TOKEN");
        }
    }

    #[test]
    #[serial]
    fn test_parse_env_var_without_braces() {
        // SAFETY: serial_test ensures this test runs exclusively, preventing race conditions
        unsafe {
            std::env::set_var("TEST_NPM_TOKEN2", "env_value2");
        }
        let content = "_authToken=$TEST_NPM_TOKEN2";
        assert_eq!(
            parse_token_from_content(content),
            Some("env_value2".to_string())
        );
        // SAFETY: serial_test ensures this test runs exclusively, preventing race conditions
        unsafe {
            std::env::remove_var("TEST_NPM_TOKEN2");
        }
    }

    #[test]
    fn test_skip_comments() {
        let content = r#"
# This is a comment
; Another comment
_authToken=real_token
"#;
        assert_eq!(
            parse_token_from_content(content),
            Some("real_token".to_string())
        );
    }

    #[test]
    fn test_parse_registry_url() {
        let content = "registry=https://npm.company.com";
        assert_eq!(
            parse_registry_from_content(content),
            Some("https://npm.company.com".to_string())
        );
    }

    #[test]
    fn test_parse_registry_with_other_config() {
        let content = r#"
# npm config
registry=https://private.registry.com
_authToken=secret
save-exact=true
"#;
        assert_eq!(
            parse_registry_from_content(content),
            Some("https://private.registry.com".to_string())
        );
    }

    #[test]
    fn test_missing_token_returns_none() {
        let content = "registry=https://example.com";
        assert_eq!(parse_token_from_content(content), None);
    }

    #[test]
    fn test_missing_env_var_returns_none() {
        let content = "_authToken=${NONEXISTENT_VAR_12345}";
        assert_eq!(parse_token_from_content(content), None);
    }
}
