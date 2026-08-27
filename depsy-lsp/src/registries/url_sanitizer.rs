//! Repository URL sanitization shared by registry adapters.
//!
//! Allows only `http`/`https` URLs after stripping common package-manager
//! prefixes (`git+`) and suffixes (`.git`). Any other scheme is dropped.

const ALLOWED_SCHEMES: &[&str] = &["http", "https"];

/// Sanitize a repository URL from package metadata.
///
/// Accepted input shapes:
///   * `https://...`, `http://...`
///   * `git+https://...`, `git+http://...` (the `git+` prefix is stripped)
///   * `git://...`, `git+git://...` (rewritten to `https://` for legacy compat)
///
/// Anything else (`ssh`, `git+ssh`, `ftp`, `file`, `javascript`, `data`,
/// `mailto`, unparseable input, empty/whitespace input) returns `None`.
///
/// A trailing `.git` is stripped from the path; query and fragment are
/// preserved. The scheme is normalized to lowercase by the underlying URL
/// parser.
pub(crate) fn sanitize_repo_url(raw: &str) -> Option<String> {
    let normalized = normalize_compound_scheme(raw.trim());
    let mut parsed = url::Url::parse(&normalized).ok()?;
    validate_external_url(&parsed)?;
    strip_dot_git_suffix(&mut parsed)?;
    Some(parsed.as_str().to_owned())
}

/// Sanitize a generic external URL from package metadata (e.g. `homepage`,
/// `documentation`).
///
/// Same allowlist semantics as [`sanitize_repo_url`] — only `http` and
/// `https` schemes are accepted, and embedded userinfo is rejected — but
/// without the repository-specific `git+` prefix stripping or `.git`
/// suffix removal. A homepage URL whose path legitimately ends in `.git`
/// must not be rewritten.
pub(crate) fn sanitize_external_url(raw: &str) -> Option<String> {
    let parsed = url::Url::parse(raw.trim()).ok()?;
    validate_external_url(&parsed)?;
    Some(parsed.as_str().to_owned())
}

/// Apply the allowlist + userinfo rejection check shared by both
/// `sanitize_repo_url` and `sanitize_external_url`.
fn validate_external_url(parsed: &url::Url) -> Option<()> {
    if !ALLOWED_SCHEMES.contains(&parsed.scheme()) {
        return None;
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    Some(())
}

/// Strip the `git+` prefix and rewrite legacy `git://` to `https://`.
///
/// Prefix matching is ASCII-case-insensitive because URL schemes are
/// case-insensitive per RFC 3986 §3.1, so inputs like `GIT+https://`
/// and `Git://` must be normalised the same way as their lowercase
/// counterparts.
///
/// Note: the `git://` -> `https://` rewrite assumes the remote host
/// also serves the same path over HTTPS. This holds for GitHub, GitLab
/// and Bitbucket (the overwhelming majority of package metadata), but
/// is not guaranteed for self-hosted or legacy registries. Carryover
/// from the previous per-registry helper, kept for compatibility.
fn normalize_compound_scheme(input: &str) -> String {
    let without_prefix = strip_prefix_ascii_case(input, "git+").unwrap_or(input);
    if let Some(rest) = strip_prefix_ascii_case(without_prefix, "git://") {
        format!("https://{rest}")
    } else {
        without_prefix.to_string()
    }
}

/// Like `str::strip_prefix`, but matches the prefix case-insensitively
/// across the ASCII range. The returned slice preserves the original
/// case of the remainder.
fn strip_prefix_ascii_case<'a>(input: &'a str, prefix: &str) -> Option<&'a str> {
    input
        .get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|_| &input[prefix.len()..])
}

/// Remove a trailing `.git` from the URL path, in place.
///
/// Returns `Some(())` on success, or `None` when stripping `.git` would
/// collapse the entire path (e.g. `/.git`) — that input is pathological
/// metadata and should be dropped rather than silently rewritten to a
/// bare host URL.
fn strip_dot_git_suffix(url: &mut url::Url) -> Option<()> {
    let path = url.path().to_string();
    if let Some(without_git) = path.strip_suffix(".git") {
        if without_git.is_empty() || without_git == "/" {
            return None;
        }
        url.set_path(without_git);
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https() {
        assert_eq!(
            sanitize_repo_url("https://github.com/user/repo"),
            Some("https://github.com/user/repo".to_string())
        );
    }

    #[test]
    fn accepts_http() {
        assert_eq!(
            sanitize_repo_url("http://example.com/repo"),
            Some("http://example.com/repo".to_string())
        );
    }

    #[test]
    fn strips_git_plus_https() {
        assert_eq!(
            sanitize_repo_url("git+https://github.com/user/repo.git"),
            Some("https://github.com/user/repo".to_string())
        );
    }

    #[test]
    fn strips_git_plus_http() {
        assert_eq!(
            sanitize_repo_url("git+http://example.com/repo.git"),
            Some("http://example.com/repo".to_string())
        );
    }

    #[test]
    fn legacy_git_protocol_converted_to_https() {
        assert_eq!(
            sanitize_repo_url("git://github.com/user/repo"),
            Some("https://github.com/user/repo".to_string())
        );
    }

    #[test]
    fn legacy_git_plus_git_protocol_converted_to_https() {
        assert_eq!(
            sanitize_repo_url("git+git://github.com/user/repo.git"),
            Some("https://github.com/user/repo".to_string())
        );
    }

    #[test]
    fn rejects_ssh() {
        assert_eq!(sanitize_repo_url("ssh://git@github.com/user/repo"), None);
    }

    #[test]
    fn rejects_git_plus_ssh() {
        assert_eq!(
            sanitize_repo_url("git+ssh://git@github.com/user/repo.git"),
            None
        );
    }

    #[test]
    fn rejects_ftp() {
        assert_eq!(sanitize_repo_url("ftp://example.com/repo"), None);
    }

    #[test]
    fn rejects_file() {
        assert_eq!(sanitize_repo_url("file:///etc/passwd"), None);
    }

    #[test]
    fn rejects_javascript() {
        assert_eq!(sanitize_repo_url("javascript:alert(1)"), None);
    }

    #[test]
    fn rejects_data_uri() {
        assert_eq!(
            sanitize_repo_url("data:text/html,<script>alert(1)</script>"),
            None
        );
    }

    #[test]
    fn rejects_mailto() {
        assert_eq!(sanitize_repo_url("mailto:foo@bar.com"), None);
    }

    #[test]
    fn rejects_empty_string() {
        assert_eq!(sanitize_repo_url(""), None);
    }

    #[test]
    fn rejects_whitespace_only() {
        assert_eq!(sanitize_repo_url("   "), None);
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(sanitize_repo_url("not a url"), None);
    }

    #[test]
    fn strips_dot_git_suffix() {
        assert_eq!(
            sanitize_repo_url("https://github.com/user/repo.git"),
            Some("https://github.com/user/repo".to_string())
        );
    }

    #[test]
    fn preserves_path_without_dot_git() {
        assert_eq!(
            sanitize_repo_url("https://gitlab.com/user/repo/subgroup"),
            Some("https://gitlab.com/user/repo/subgroup".to_string())
        );
    }

    #[test]
    fn preserves_query_and_fragment() {
        assert_eq!(
            sanitize_repo_url("https://example.com/r?ref=v1#section"),
            Some("https://example.com/r?ref=v1#section".to_string())
        );
    }

    #[test]
    fn case_insensitive_scheme() {
        assert_eq!(
            sanitize_repo_url("HTTPS://github.com/user/repo"),
            Some("https://github.com/user/repo".to_string())
        );
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(
            sanitize_repo_url("  https://example.com/r  "),
            Some("https://example.com/r".to_string())
        );
    }

    #[test]
    fn rejects_bare_dot_git_path() {
        // path of `/.git` would otherwise strip to `/` and leak a bogus
        // root URL — return None instead.
        assert_eq!(sanitize_repo_url("https://github.com/.git"), None);
    }

    #[test]
    fn preserves_non_default_port() {
        assert_eq!(
            sanitize_repo_url("https://example.com:8443/user/repo"),
            Some("https://example.com:8443/user/repo".to_string())
        );
    }

    #[test]
    fn rejects_userinfo_in_url() {
        // credentials embedded in a metadata URL are never legitimate; drop them.
        assert_eq!(
            sanitize_repo_url("https://user:pass@github.com/user/repo"),
            None
        );
    }

    #[test]
    fn preserves_percent_encoding_when_stripping_dot_git() {
        // Regression guard: `url::Url::set_path` must not double-encode
        // pre-existing `%XX` sequences in the path (e.g. `my%20repo`
        // must stay `my%20repo`, not become `my%2520repo`).
        assert_eq!(
            sanitize_repo_url("https://github.com/user/my%20repo.git"),
            Some("https://github.com/user/my%20repo".to_string())
        );
    }

    #[test]
    fn accepts_uppercase_git_plus_prefix() {
        // URL schemes are case-insensitive per RFC 3986; an upper-cased
        // `GIT+https://` prefix must be normalised the same way as `git+`.
        assert_eq!(
            sanitize_repo_url("GIT+https://github.com/user/repo.git"),
            Some("https://github.com/user/repo".to_string())
        );
    }

    #[test]
    fn accepts_uppercase_legacy_git_protocol() {
        // Same case-insensitivity rule applies to the legacy `git://`
        // scheme that we rewrite to `https://`.
        assert_eq!(
            sanitize_repo_url("GIT://github.com/user/repo"),
            Some("https://github.com/user/repo".to_string())
        );
    }

    // sanitize_external_url — variant for non-repository fields (homepage,
    // documentation links). Same allowlist, but no `git+` strip and no
    // `.git` suffix removal because those are repository-specific.

    #[test]
    fn external_accepts_https() {
        assert_eq!(
            sanitize_external_url("https://example.com/"),
            Some("https://example.com/".to_string())
        );
    }

    #[test]
    fn external_accepts_http() {
        assert_eq!(
            sanitize_external_url("http://example.com/docs"),
            Some("http://example.com/docs".to_string())
        );
    }

    #[test]
    fn external_rejects_javascript() {
        assert_eq!(sanitize_external_url("javascript:alert(1)"), None);
    }

    #[test]
    fn external_rejects_file() {
        assert_eq!(sanitize_external_url("file:///etc/passwd"), None);
    }

    #[test]
    fn external_rejects_data_uri() {
        assert_eq!(
            sanitize_external_url("data:text/html,<script>alert(1)</script>"),
            None
        );
    }

    #[test]
    fn external_rejects_ssh() {
        assert_eq!(sanitize_external_url("ssh://git@example.com/x"), None);
    }

    #[test]
    fn external_rejects_userinfo() {
        assert_eq!(
            sanitize_external_url("https://user:pass@example.com/"),
            None
        );
    }

    #[test]
    fn external_does_not_strip_git_suffix() {
        // unlike sanitize_repo_url, the homepage variant must not rewrite
        // a path that happens to end in `.git`.
        assert_eq!(
            sanitize_external_url("https://example.com/foo.git"),
            Some("https://example.com/foo.git".to_string())
        );
    }

    #[test]
    fn external_rejects_empty() {
        assert_eq!(sanitize_external_url(""), None);
    }

    #[test]
    fn external_rejects_garbage() {
        assert_eq!(sanitize_external_url("not a url"), None);
    }
}
