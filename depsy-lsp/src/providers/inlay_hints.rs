//! Inlay hint provider — displays version status inline next to dependency declarations.
//!
//! The central function [`crate::providers::inlay_hints::create_inlay_hint`]
//! constructs an [`tower_lsp::lsp_types::InlayHint`] for one dependency using
//! metadata from the version cache.  Status labels follow a strict priority
//! order:
//!
//! 1. **Local/path dependency** — `→ Local` (no registry lookup performed).
//! 2. **Yanked version** — `⊘ Yanked [→ latest]`.
//! 3. **Deprecated package** — `⚠ Deprecated [→ latest]`.
//! 4. **Vulnerabilities** — `⚠ N vuln(s) [→ latest]`.
//! 5. **Up to date** — `✓`.
//! 6. **Update available** — `→ X.Y.Z`.
//! 7. **Unknown** — `? Unknown` (registry unreachable, package not found, etc.).
//!
//! Pure helper functions
//! [`crate::providers::inlay_hints::is_local_dependency`],
//! [`crate::providers::inlay_hints::compare_versions`], and
//! [`crate::providers::inlay_hints::normalize_version`] are public so other
//! providers and tests can reuse them.

use core::fmt::{self, Write};

use tower_lsp::lsp_types::{InlayHint, InlayHintKind, InlayHintLabel, Position};

use crate::file_types::FileType;
use crate::registries::{VersionInfo, VulnerabilitySeverity};
use crate::utils::fmt_truncate_string;
use crate::{parsers::Dependency, registries::Vulnerability};

/// Outcome of comparing a dependency's declared version against the latest available.
///
/// Produced by [`compare_versions`] and consumed by [`create_inlay_hint`] as
/// well as the diagnostics and code-actions providers.
#[derive(Debug, Clone)]
pub enum VersionStatus {
    /// The declared version is at least as recent as the latest known version.
    UpToDate,
    /// A newer version is available; the inner `String` is the latest version string.
    UpdateAvailable(String),
    /// Version status could not be determined (e.g. no cache entry, no `latest` field).
    Unknown,
}

/// Build an [`InlayHint`] for a single dependency.
///
/// The hint is positioned immediately after the version span and displays a
/// label chosen by the priority rules documented in the [module level
/// docs](self).  A tooltip string is attached when additional context is
/// available (vulnerability details, deprecation reasons, etc.).
///
/// # Parameters
///
/// - `dep` — parsed dependency; its `version_span` determines hint placement.
/// - `version_info` — cached registry metadata, or `None` when unavailable.
/// - `file_type` — used to format registry URLs inside tooltips.
///
/// # Examples
///
/// ```
/// use depsy_lsp::providers::inlay_hints::create_inlay_hint;
/// use depsy_lsp::file_types::FileType;
/// use depsy_lsp::registries::VersionInfo;
/// use depsy_lsp::parsers::{Dependency, Span};
/// use tower_lsp::lsp_types::InlayHintLabel;
///
/// let dep = Dependency {
///     name: "serde".to_string(),
///     version: "1.0.0".to_string(),
///     name_span: Span { line: 5, line_start: 0, line_end: 5 },
///     version_span: Span { line: 5, line_start: 9, line_end: 14 },
///     dev: false, optional: false, registry: None, resolved_version: None,
///     has_additional_version_constraints: false,
/// };
/// let info = VersionInfo { latest: Some("1.0.0".to_string()), ..Default::default() };
/// let hint = create_inlay_hint(&dep, Some(&info), FileType::Cargo);
/// assert_eq!(hint.position.line, 5);
/// assert!(matches!(hint.label, InlayHintLabel::String(ref s) if s.contains("✓")));
/// ```
pub fn create_inlay_hint(
    dep: &Dependency,
    version_info: Option<&VersionInfo>,
    file_type: FileType,
) -> InlayHint {
    let status = match version_info {
        Some(info) => compare_versions(dep.effective_version(), info),
        None => VersionStatus::Unknown,
    };

    // Check for vulnerabilities and deprecation
    let vuln_count = version_info
        .map(|info| info.vulnerabilities.len())
        .unwrap_or(0);

    let is_deprecated = version_info.map(|info| info.deprecated).unwrap_or(false);

    if is_deprecated {
        tracing::debug!("Package {} {} is deprecated", dep.name, dep.version);
    }

    let (label, tooltip) =
        create_hint_label_and_tooltip(&status, vuln_count, dep, version_info, file_type);

    InlayHint {
        position: Position {
            line: dep.version_span.line,
            character: dep.version_span.line_end + 1,
        },
        label: InlayHintLabel::String(format!(" {label}")),
        kind: Some(InlayHintKind::PARAMETER),
        text_edits: None,
        tooltip: tooltip.map(tower_lsp::lsp_types::InlayHintTooltip::String),
        padding_left: Some(true),
        padding_right: None,
        data: None,
    }
}

/// Create label and tooltip based on version status and vulnerabilities
fn create_hint_label_and_tooltip(
    status: &VersionStatus,
    vuln_count: usize,
    dep: &Dependency,
    version_info: Option<&VersionInfo>,
    file_type: FileType,
) -> (String, Option<String>) {
    let dep_name = &*dep.name;

    // Handle local dependencies first (highest priority - no registry lookup needed)
    if is_local_dependency(&dep.version) {
        let tooltip = format!(
            "**Local Dependency**\n\n\
            \"{dep_name}\" is a local/path dependency.\n\n\
            Version info is not available for local packages.\n\n\
            This is expected for dependencies using:\n\
            • path = \"./...\"\n\
            • git = \"https://...\"\n\
            • git = \"git@...\"\n\
            • github:owner/repo",
        );
        return ("→ Local".to_string(), Some(tooltip));
    }

    let dep_version = dep.effective_version();
    tracing::debug!("Not a local dependency: {dep_name} with version '{dep_version}'",);

    // Handle yanked versions (highest priority - critical issue)
    if let Some(info) = version_info
        && info.is_version_yanked(dep_version)
    {
        let yanked_label = "⊘ Yanked";
        let yanked_tooltip = fmt_yanked_tooltip(dep, info, file_type);

        return match status {
            VersionStatus::UpdateAvailable(latest) => {
                let label = format!("{yanked_label} -> {latest}");
                let tooltip = format!(
                    "{yanked_tooltip}\n\n---\n**Update available:** {dep_version} -> {latest}",
                );
                (label, Some(tooltip))
            }
            _ => (yanked_label.to_string(), Some(yanked_tooltip.to_string())),
        };
    }

    // Handle deprecation (second highest priority)
    if let Some(info) = version_info
        && info.deprecated
    {
        let dep_label = "⚠ Deprecated";
        let dep_tooltip = fmt_deprecation_tooltip(dep, info);

        // Combine with update info if available
        return match status {
            VersionStatus::UpdateAvailable(latest) => {
                let label = format!("{dep_label} -> {latest}");
                let tooltip = format!(
                    "{dep_tooltip}\n\n---\n**Update available:** {dep_version} -> {latest}",
                );
                (label, Some(tooltip))
            }
            _ => (dep_label.to_string(), Some(dep_tooltip.to_string())),
        };
    }

    // Handle vulnerabilities (vuln_count > 0 implies version_info is Some)
    if vuln_count > 0 {
        let vuln_label = fmt::from_fn(move |f| {
            write!(f, "⚠ {vuln_count} vuln")?;
            if vuln_count != 1 {
                f.write_char('s')?;
            }
            Ok(())
        });
        let Some(info) = version_info else {
            return (vuln_label.to_string(), None);
        };
        let vuln_tooltip = fmt_vulnerability_tooltip(info);

        // Combine with update info if available
        return match status {
            VersionStatus::UpdateAvailable(latest) => {
                let label = format!("{vuln_label} -> {latest}");
                let tooltip = format!(
                    "{vuln_tooltip}\n\n---\n**Update available:** {dep_version} -> {latest}",
                );
                (label, Some(tooltip))
            }
            _ => (vuln_label.to_string(), Some(vuln_tooltip.to_string())),
        };
    }

    // No vulnerabilities - show version status
    match status {
        VersionStatus::UpToDate => ("✓".to_string(), Some("Up to date".to_string())),
        VersionStatus::UpdateAvailable(latest) => {
            let label = format!("-> {latest}");
            let tooltip = format!("Update available: {dep_version} -> {latest}");
            (label, Some(tooltip))
        }
        VersionStatus::Unknown => {
            let tooltip = format!(
                "**Could not fetch version info**\n\n\
                Possible causes:\n\
                • Network error - check internet connection\n\
                • Package not found - verify spelling\n\
                • Rate limiting - wait and retry\n\
                • Registry down - try again later\n\n\
                **Troubleshooting:**\n\
                1. Check your network connection\n\
                2. Verify the package name \"{dep_name}\" is spelled correctly\n\
                3. Search for the package on the registry\n\
                4. If recently published, wait a few minutes for indexing",
            );
            ("? Unknown".to_string(), Some(tooltip))
        }
    }
}

/// Format vulnerability details for tooltip
#[must_use = "returns a type implementing Display and Debug, which does not have any effects unless they are used"]
fn fmt_vulnerability_tooltip(info: &VersionInfo) -> impl fmt::Display + fmt::Debug {
    let count = info.vulnerabilities.len();

    fmt::from_fn(move |f| {
        writeln!(
            f,
            "**⚠ {count} {} Found**",
            if count == 1 {
                "Vulnerability"
            } else {
                "Vulnerabilities"
            }
        )?;
        writeln!(f)?;

        for (
            i,
            Vulnerability {
                id,
                severity,
                description,
                url,
            },
        ) in info.vulnerabilities.iter().take(5).enumerate()
        {
            let severity_icon = match severity {
                VulnerabilitySeverity::Critical => "⚠ CRITICAL",
                VulnerabilitySeverity::High => "▲ HIGH",
                VulnerabilitySeverity::Medium => "● MEDIUM",
                VulnerabilitySeverity::Low => "○ LOW",
            };

            writeln!(f, "{n}. **{id}** ({severity_icon})", n = i + 1)?;
            writeln!(f, "   {}", fmt_truncate_string(description, 100))?;

            if let Some(url) = url.as_deref() {
                writeln!(f, "   [View Advisory]({url})")?;
            }
        }

        if count > 5 {
            writeln!(f)?;
            writeln!(f, "... and {rest} more vulnerabilities", rest = count - 5)?;
        }

        Ok(())
    })
}

/// Format deprecation warning for tooltip
#[must_use = "returns a type implementing Display and Debug, which does not have any effects unless they are used"]
fn fmt_deprecation_tooltip(dep: &Dependency, info: &VersionInfo) -> impl fmt::Display + fmt::Debug {
    let dep_name = &*dep.name;
    fmt::from_fn(move |f| {
        writeln!(
            f,
            "**⚠ PACKAGE DEPRECATED**\n\
             \n\
             The package \"{dep_name}\" is deprecated.\n\
             \n\
             **Why was it deprecated?**\n\
             • Superseded by a better alternative\n\
             • Has unresolved critical bugs\n\
             • Known security vulnerabilities\n\
             • No longer maintained\n\
             • Has been renamed\n\
             \n\
             **What should you do?**",
        )?;

        if let Some(homepage) = info.homepage.as_deref() {
            writeln!(f, "• Check the package homepage: {homepage}")?;
        }

        if let Some(repo) = info.repository.as_deref() {
            writeln!(f, "• View the repository for more information: {repo}")?;
        }

        writeln!(f, "• Search for an alternative package on the registry")?;

        if let Some(latest) = info.latest.as_deref() {
            writeln!(
                f,
                "• Consider the latest version: {latest} (may not be deprecated)"
            )?;
        }

        Ok(())
    })
}

/// Format yanked version warning for tooltip
#[must_use = "returns a type implementing Display and Debug, which does not have any effects unless they are used"]
fn fmt_yanked_tooltip(
    dep: &Dependency,
    info: &VersionInfo,
    file_type: FileType,
) -> impl fmt::Display + fmt::Debug {
    let dep_name = &*dep.name;
    let dep_version = dep.effective_version();
    let has_custom_registry = dep.registry.is_some();

    fmt::from_fn(move |f| {
        if has_custom_registry {
            writeln!(
                f,
                "**⊘ YANKED VERSION**\n\
                 \n\
                 The version \"{dep_version}\" of \"{dep_name}\" has been yanked.\n\
                 \n\
                 **Why was it yanked?**\n\
                 A yanked version typically has:\n\
                 • Critical bugs that break functionality\n\
                 • Security vulnerabilities\n\
                 • Published by mistake\n\
                 • Corrupted or incomplete package\n\
                 \n\
                 **What should you do?**"
            )?;
        } else {
            let registry = file_type.registry_name();
            writeln!(
                f,
                "**⊘ YANKED VERSION**\n\
                 \n\
                 The version \"{dep_version}\" of \"{dep_name}\" has been yanked from {registry}.\n\
                 \n\
                 **Why was it yanked?**\n\
                 A yanked version typically has:\n\
                 • Critical bugs that break functionality\n\
                 • Security vulnerabilities\n\
                 • Published by mistake\n\
                 • Corrupted or incomplete package\n\
                 \n\
                 **What should you do?**"
            )?;
        }

        if let Some(latest) = info.latest.as_deref() {
            writeln!(f, "• Update to the latest version: {latest}")?;
        }

        if let Some(repo) = info.repository.as_deref() {
            writeln!(f, "• Check the repository for more info: {repo}")?;
        }

        if has_custom_registry {
            Ok(())
        } else {
            let registry = file_type.registry_name();
            writeln!(
                f,
                "• View on {registry}: {}",
                file_type.fmt_registry_package_url(dep_name),
            )
        }
    })
}

/// Returns `true` when `version` refers to a local path, git repository, or
/// URL source rather than a plain registry version string.
///
/// The following prefixes are recognised as local/non-registry sources:
/// `./`, `../`, `/`, `file:`, `git+`, `git@`, `git:`, `https://`, `http://`,
/// `github:`, `gitlab:`, `bitbucket:`, `workspace:`, `link:`, `portal:`, `npm:`.
///
/// # Examples
///
/// ```
/// use depsy_lsp::providers::inlay_hints::is_local_dependency;
/// assert!(is_local_dependency("git+https://example.com/foo.git"));
/// assert!(is_local_dependency("./my-lib"));
/// assert!(is_local_dependency("../shared"));
/// assert!(is_local_dependency("workspace:*"));
/// assert!(is_local_dependency("file:./local-pkg"));
/// assert!(!is_local_dependency("1.2.3"));
/// assert!(!is_local_dependency("^1.0.0"));
/// assert!(!is_local_dependency("latest"));
/// ```
pub fn is_local_dependency(version: &str) -> bool {
    // Path-based dependencies
    version.starts_with("./")
        || version.starts_with("../")
        || version.starts_with('/')
        // File protocol (npm uses "file:" not "file://")
        || version.starts_with("file:")
        // Git dependencies
        || version.starts_with("git+")
        || version.starts_with("git@")
        || version.starts_with("git:")
        // URL-based (git repos)
        || version.starts_with("https://")
        || version.starts_with("http://")
        // Platform shortcuts (npm/yarn)
        || version.starts_with("github:")
        || version.starts_with("gitlab:")
        || version.starts_with("bitbucket:")
        // Yarn/pnpm workspace protocols
        || version.starts_with("workspace:")
        || version.starts_with("link:")
        || version.starts_with("portal:")
        // npm aliases
        || version.starts_with("npm:")
}

/// Strip PEP 440 pre-release suffixes from a version string
/// Examples: "4.0a" → "4.0", "4.0a1" → "4.0", "4.0.0b2" → "4.0.0", "4.0rc1" → "4.0"
fn strip_python_prerelease(version: &str) -> String {
    version
        .split('.')
        .map(|part| {
            let lower = part.to_lowercase();
            // Long patterns first (to avoid partial matches with short ones)
            for pattern in ["alpha", "beta", "dev", "rc"] {
                if let Some(pos) = lower.find(pattern) {
                    return if pos > 0 {
                        &part[..pos]
                    } else {
                        // Pure pre-release segment like "dev1" → "0"
                        "0"
                    };
                }
            }
            // Short patterns (a, b, c) — only when preceded by a digit
            if let Some(pos @ 1..) = lower.find(['a', 'b', 'c'])
                && lower.as_bytes()[pos - 1].is_ascii_digit()
            {
                return &part[..pos];
            }
            part
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Compare a dependency's declared version against the latest version in `info`.
///
/// The comparison handles several version-string formats:
///
/// - **Standard semver** — `^`, `~`, `>=`, `<=`, `>`, `<`, `=`, `v` prefixes
///   are stripped before parsing.
/// - **Python compatible-release operator** (`~=X.Y`) — compared at the same
///   granularity as the base specifier (see PEP 440).
/// - **PEP 440 pre-release suffixes** (`a`, `b`, `rc`, `alpha`, `beta`, `dev`)
///   — stripped for the semver parse attempt so that e.g. `4.0.0a6` compared
///   against stable `3.11.2` correctly returns [`VersionStatus::UpToDate`]
///   rather than suggesting a downgrade.
/// - **Calendar versions** — four-segment versions like `2024.1.1.5` are not
///   truncated when they do not contain pre-release markers.
///
/// Returns [`VersionStatus::Unknown`] when `info.latest` is `None`.
///
/// # Examples
///
/// ```
/// use depsy_lsp::providers::inlay_hints::{compare_versions, VersionStatus};
/// use depsy_lsp::registries::VersionInfo;
///
/// let up_to_date = VersionInfo { latest: Some("1.0.0".to_string()), ..Default::default() };
/// assert!(matches!(compare_versions("1.0.0", &up_to_date), VersionStatus::UpToDate));
///
/// let outdated = VersionInfo { latest: Some("2.0.0".to_string()), ..Default::default() };
/// assert!(matches!(
///     compare_versions("^1.0.0", &outdated),
///     VersionStatus::UpdateAvailable(ref v) if v == "2.0.0"
/// ));
///
/// let no_latest = VersionInfo { latest: None, ..Default::default() };
/// assert!(matches!(compare_versions("1.0.0", &no_latest), VersionStatus::Unknown));
/// ```
pub fn compare_versions(current: &str, info: &VersionInfo) -> VersionStatus {
    let Some(latest) = info.latest.as_deref() else {
        return VersionStatus::Unknown;
    };

    // Handle Python compatible release operator (~=)
    // ~=X.Y means >=X.Y, ==X.* — compare at the same granularity
    if let Some(base) = current.strip_prefix("~=") {
        let base = base.trim();
        // Strip PEP 440 pre-release markers (e.g., "4.0a" → "4.0") so that
        // semver parsing succeeds and we compare numeric parts correctly
        let base_clean = strip_python_prerelease(base);
        let segments = base_clean.split('.').count();
        let truncated_latest = truncate_version(latest, segments);

        let base_normalized = normalize_version(&base_clean);
        let truncated_normalized = normalize_version(&truncated_latest);

        return match (
            semver::Version::parse(&base_normalized),
            semver::Version::parse(&truncated_normalized),
        ) {
            (Ok(base_ver), Ok(trunc_ver)) => {
                if base_ver >= trunc_ver {
                    VersionStatus::UpToDate
                } else {
                    VersionStatus::UpdateAvailable(truncated_latest)
                }
            }
            _ => {
                if base_normalized == truncated_normalized {
                    VersionStatus::UpToDate
                } else {
                    VersionStatus::UpdateAvailable(truncated_latest)
                }
            }
        };
    }

    // Normalize versions for comparison
    let current_normalized = normalize_version(current);
    let latest_normalized = normalize_version(latest);

    // First attempt: direct semver parse (handles clean semver and semver pre-release
    // like Rust's `1.0.0-alpha.1`).
    if let (Ok(current_ver), Ok(latest_ver)) = (
        semver::Version::parse(&current_normalized),
        semver::Version::parse(&latest_normalized),
    ) {
        return if current_ver >= latest_ver {
            VersionStatus::UpToDate
        } else {
            VersionStatus::UpdateAvailable(latest.to_owned())
        };
    }

    // Second attempt: strip PEP 440 pre-release markers, then retry semver parse.
    // Handles Python bare pre-release versions (e.g., `4.0.0a6` coming from a
    // lockfile resolution or an explicit pin like `==4.0.0a6`), which the first
    // attempt cannot parse and which would otherwise trigger a bogus downgrade
    // suggestion via the string-equality fallback (see issue #154).
    //
    // Only truncate to 3 segments when stripping actually changed the input
    // (a PEP 440 marker like `dev1` can expand to a trailing `.0` that pushes
    // the result to 4 segments). Leaving genuine 4-segment calendar versions
    // like `2024.1.1.5` untouched avoids silently collapsing them.
    let current_clean = clean_for_semver(&current_normalized);
    let latest_clean = clean_for_semver(&latest_normalized);

    match (
        semver::Version::parse(&current_clean),
        semver::Version::parse(&latest_clean),
    ) {
        (Ok(current_ver), Ok(latest_ver)) => match current_ver.cmp(&latest_ver) {
            core::cmp::Ordering::Greater => VersionStatus::UpToDate,
            core::cmp::Ordering::Less => VersionStatus::UpdateAvailable(latest.to_owned()),
            core::cmp::Ordering::Equal => {
                // Cleaned versions parsed equal — check whether stripping
                // collapsed a real difference (e.g., `4.0.0a6` vs `4.0.0a7`
                // both strip to `4.0.0`). If originals differ, report an
                // update rather than hiding the change.
                if current_normalized == latest_normalized {
                    VersionStatus::UpToDate
                } else {
                    VersionStatus::UpdateAvailable(latest.to_owned())
                }
            }
        },
        _ => {
            // Final fallback: string comparison on cleaned versions
            if current_clean == latest_clean {
                VersionStatus::UpToDate
            } else {
                VersionStatus::UpdateAvailable(latest.to_owned())
            }
        }
    }
}

/// Normalize a version for the second-attempt semver parse in `compare_versions`.
/// Strips PEP 440 pre-release markers. Truncates to 3 segments only when the
/// strip actually modified the input, so genuine 4-segment calendar versions
/// (e.g., `2024.1.1.5`) are preserved.
fn clean_for_semver(version: &str) -> String {
    let stripped = strip_python_prerelease(version);
    if stripped == version {
        normalize_version(&stripped)
    } else {
        normalize_version(&truncate_version(&stripped, 3))
    }
}

/// Truncate a version string to a specific number of segments
/// e.g., truncate_version("14.3.3", 2) → "14.3"
fn truncate_version(version: &str, segments: usize) -> String {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() <= segments {
        version.to_string()
    } else {
        parts[..segments].join(".")
    }
}

/// Normalize a version string into a three-component `MAJOR.MINOR.PATCH` form.
///
/// Leading range operators (`^`, `~`, `>=`, `<=`, `>`, `<`, `=`, `~=`, `~>`,
/// `==`, `!=`, `===`) are stripped.  When the string contains a
/// comma-separated range (e.g. `>=1.0, <2.0`), only the first component is
/// kept.  One- and two-component versions are padded with `.0` segments.
///
/// Note: the bare `v` prefix is **not** stripped by this function; use
/// `format_version` in the code-actions provider when writing back to the
/// manifest.
///
/// # Examples
///
/// ```
/// use depsy_lsp::providers::inlay_hints::normalize_version;
/// assert_eq!(normalize_version("1.0.0"),       "1.0.0");
/// assert_eq!(normalize_version("^1.0"),        "1.0.0");
/// assert_eq!(normalize_version("~=14.3"),      "14.3.0");
/// assert_eq!(normalize_version(">=1.0, <2.0"), "1.0.0");
/// assert_eq!(normalize_version("3"),           "3.0.0");
/// ```
pub fn normalize_version(version: &str) -> String {
    let version = version.trim();

    // Remove common prefixes (multi-char operators first to avoid partial matches)
    let version = version
        .strip_prefix("~=")
        .or_else(|| version.strip_prefix("~>"))
        .or_else(|| version.strip_prefix("==="))
        .or_else(|| version.strip_prefix("!="))
        .or_else(|| version.strip_prefix("=="))
        .or_else(|| version.strip_prefix(">="))
        .or_else(|| version.strip_prefix("<="))
        .or_else(|| version.strip_prefix('^'))
        .or_else(|| version.strip_prefix('~'))
        .or_else(|| version.strip_prefix('>'))
        .or_else(|| version.strip_prefix('<'))
        .or_else(|| version.strip_prefix('='))
        .map(str::trim_start) // end was already trimmed
        .unwrap_or(version);

    // Handle version ranges like ">=1.0, <2.0" - take the first part
    let version = version
        .split(',')
        .next()
        .map(str::trim_end) // start was already trimmed
        .unwrap_or(version);

    // Ensure we have at least major.minor.patch
    let parts: Vec<&str> = version.split('.').collect();
    match *parts.as_slice() {
        [major] => format!("{major}.0.0"),
        [major, minor] => format!("{major}.{minor}.0"),
        _ => version.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_types::FileType;
    use crate::parsers::Span;
    use crate::registries::Vulnerability;

    fn make_version_info(latest: &str) -> VersionInfo {
        VersionInfo {
            latest: Some(latest.to_string()),
            ..Default::default()
        }
    }

    fn make_test_dep(name: &str, version: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.to_string(),
            name_span: Span {
                line: 5,
                line_start: 0,
                line_end: name.len() as u32,
            },
            version_span: Span {
                line: 5,
                line_start: name.len() as u32 + 4,
                line_end: name.len() as u32 + 4 + version.len() as u32,
            },
            dev: false,
            optional: false,
            registry: None,
            resolved_version: None,
            has_additional_version_constraints: false,
        }
    }

    #[test]
    fn test_compare_versions_up_to_date() {
        let info = make_version_info("1.0.0");
        assert!(matches!(
            compare_versions("1.0.0", &info),
            VersionStatus::UpToDate
        ));
    }

    #[test]
    fn test_compare_versions_update_available() {
        let info = make_version_info("2.0.0");
        match compare_versions("1.0.0", &info) {
            VersionStatus::UpdateAvailable(v) => assert_eq!(v, "2.0.0"),
            _ => panic!("Expected UpdateAvailable"),
        }
    }

    #[test]
    fn test_compare_versions_with_caret() {
        let info = make_version_info("1.5.0");
        match compare_versions("^1.0", &info) {
            VersionStatus::UpdateAvailable(v) => assert_eq!(v, "1.5.0"),
            _ => panic!("Expected UpdateAvailable"),
        }
    }

    #[test]
    fn test_compare_versions_with_tilde() {
        let info = make_version_info("1.0.5");
        match compare_versions("~1.0.0", &info) {
            VersionStatus::UpdateAvailable(v) => assert_eq!(v, "1.0.5"),
            _ => panic!("Expected UpdateAvailable"),
        }
    }

    #[test]
    fn test_normalize_version() {
        assert_eq!(normalize_version("1.0.0"), "1.0.0");
        assert_eq!(normalize_version("^1.0"), "1.0.0");
        assert_eq!(normalize_version("~1.0.0"), "1.0.0");
        assert_eq!(normalize_version(">=1.0, <2.0"), "1.0.0");
        assert_eq!(normalize_version("1"), "1.0.0");
        assert_eq!(normalize_version("1.2"), "1.2.0");
        // Python operators
        assert_eq!(normalize_version("~=14.3"), "14.3.0");
        assert_eq!(normalize_version("==2.0.0"), "2.0.0");
        assert_eq!(normalize_version("!=1.0"), "1.0.0");
    }

    #[test]
    fn test_compare_versions_compatible_release_up_to_date() {
        // ~=14.3 with latest 14.3.3: latest truncated to 14.3, matches base → UpToDate
        let info = make_version_info("14.3.3");
        assert!(matches!(
            compare_versions("~=14.3", &info),
            VersionStatus::UpToDate
        ));
    }

    #[test]
    fn test_compare_versions_compatible_release_outdated() {
        // ~=14.2 with latest 14.3.3: truncated to 14.3, 14.2 < 14.3 → UpdateAvailable("14.3")
        let info = make_version_info("14.3.3");
        match compare_versions("~=14.2", &info) {
            VersionStatus::UpdateAvailable(v) => assert_eq!(v, "14.3"),
            _ => panic!("Expected UpdateAvailable"),
        }
    }

    #[test]
    fn test_compare_versions_compatible_release_3_segments() {
        // ~=14.3.2 with latest 14.3.5: truncated to 14.3.5, 14.3.2 < 14.3.5 → UpdateAvailable
        let info = make_version_info("14.3.5");
        match compare_versions("~=14.3.2", &info) {
            VersionStatus::UpdateAvailable(v) => assert_eq!(v, "14.3.5"),
            _ => panic!("Expected UpdateAvailable"),
        }
    }

    #[test]
    fn test_compare_versions_compatible_release_3_segments_up_to_date() {
        // ~=14.3.3 with latest 14.3.3: truncated matches → UpToDate
        let info = make_version_info("14.3.3");
        assert!(matches!(
            compare_versions("~=14.3.3", &info),
            VersionStatus::UpToDate
        ));
    }

    #[test]
    fn test_compare_versions_compatible_release_major_jump() {
        // ~=14.3 with latest 15.0.0: truncated to 15.0, 14.3 < 15.0 → UpdateAvailable("15.0")
        let info = make_version_info("15.0.0");
        match compare_versions("~=14.3", &info) {
            VersionStatus::UpdateAvailable(v) => assert_eq!(v, "15.0"),
            _ => panic!("Expected UpdateAvailable"),
        }
    }

    #[test]
    fn test_strip_python_prerelease() {
        assert_eq!(strip_python_prerelease("4.0a"), "4.0");
        assert_eq!(strip_python_prerelease("4.0a1"), "4.0");
        assert_eq!(strip_python_prerelease("4.0.0a1"), "4.0.0");
        assert_eq!(strip_python_prerelease("1.0b2"), "1.0");
        assert_eq!(strip_python_prerelease("1.0.0b2"), "1.0.0");
        assert_eq!(strip_python_prerelease("2.0rc1"), "2.0");
        assert_eq!(strip_python_prerelease("2.0.0rc1"), "2.0.0");
        assert_eq!(strip_python_prerelease("1.0alpha"), "1.0");
        assert_eq!(strip_python_prerelease("1.0beta"), "1.0");
        assert_eq!(strip_python_prerelease("4.0.dev1"), "4.0.0");
        // Stable versions should pass through unchanged
        assert_eq!(strip_python_prerelease("3.11.0"), "3.11.0");
        assert_eq!(strip_python_prerelease("14.3"), "14.3");
        assert_eq!(strip_python_prerelease("1.0.0"), "1.0.0");
        // Post-releases are stable per PEP 440
        assert_eq!(strip_python_prerelease("1.0.0.post1"), "1.0.0.post1");
    }

    #[test]
    fn test_compare_versions_compatible_release_prerelease_up_to_date() {
        // ~=4.0a with latest 3.11.0: user is on a pre-release of 4.0, which is
        // a higher major-minor than 3.11 → UpToDate (no downgrade suggestion)
        let info = make_version_info("3.11.0");
        assert!(matches!(
            compare_versions("~=4.0a", &info),
            VersionStatus::UpToDate
        ));
    }

    #[test]
    fn test_issue_154_compatible_release_matches_real_pypi_latest() {
        // Reproduces the reported scenario of issue #154: a PyPI package
        // (apscheduler) with stable latest in a lower major than the pinned
        // pre-release (`~=4.0a`) — must be UpToDate, not a downgrade suggestion.
        let info = make_version_info("3.11.2");
        let result = compare_versions("~=4.0a", &info);
        assert!(matches!(result, VersionStatus::UpToDate), "Got: {result:?}");
    }

    #[test]
    fn test_issue_154_bare_prerelease_from_lockfile() {
        // If a Python lockfile resolves apscheduler to a pre-release (e.g., "4.0.0a6"),
        // `effective_version()` returns the bare pre-release, which bypasses the ~= path
        let info = make_version_info("3.11.2");
        let result = compare_versions("4.0.0a6", &info);
        assert!(matches!(result, VersionStatus::UpToDate), "Got: {result:?}");
    }

    #[test]
    fn test_issue_154_bare_prerelease_variants() {
        let info = make_version_info("3.11.2");
        for v in [
            "4.0a",
            "4.0a1",
            "4.0.0a1",
            "4.0.0b2",
            "4.0.0rc1",
            "4.0.0.dev1",
        ] {
            let result = compare_versions(v, &info);
            assert!(
                matches!(result, VersionStatus::UpToDate),
                "Input {v}: Got {result:?}"
            );
        }
    }

    #[test]
    fn test_issue_154_exact_pin_prerelease() {
        // Exact pin with == operator
        let info = make_version_info("3.11.2");
        let result = compare_versions("==4.0.0a6", &info);
        assert!(matches!(result, VersionStatus::UpToDate), "Got: {result:?}");
    }

    #[test]
    fn test_compare_versions_prerelease_older_than_latest_prerelease() {
        // When latest itself is a pre-release (no stable on PyPI yet), a lower
        // pre-release on the same base version must still report an update
        // instead of collapsing to UpToDate via the strip.
        let info = make_version_info("4.0.0a7");
        match compare_versions("4.0.0a6", &info) {
            VersionStatus::UpdateAvailable(v) => assert_eq!(v, "4.0.0a7"),
            other => panic!("Expected UpdateAvailable, got: {other:?}"),
        }
    }

    #[test]
    fn test_compare_versions_prerelease_vs_same_base_stable() {
        // Pre-release on the same base as a released stable must report an
        // update: 4.0.0a6 < 4.0.0.
        let info = make_version_info("4.0.0");
        match compare_versions("4.0.0a6", &info) {
            VersionStatus::UpdateAvailable(v) => assert_eq!(v, "4.0.0"),
            other => panic!("Expected UpdateAvailable, got: {other:?}"),
        }
    }

    #[test]
    fn test_compare_versions_calver_four_segments_update_available() {
        // Calendar-versioned packages can legitimately use 4 segments (e.g.,
        // `2024.1.1.5`). The second-attempt path must not silently truncate
        // `latest` and report UpToDate when a real update exists.
        let info = make_version_info("2024.1.1.5");
        match compare_versions("2024.1.1.3", &info) {
            VersionStatus::UpdateAvailable(v) => assert_eq!(v, "2024.1.1.5"),
            other => panic!("Expected UpdateAvailable, got: {other:?}"),
        }
    }

    #[test]
    fn test_compare_versions_calver_four_segments_up_to_date() {
        let info = make_version_info("2024.1.1.5");
        let result = compare_versions("2024.1.1.5", &info);
        assert!(matches!(result, VersionStatus::UpToDate), "Got: {result:?}");
    }

    #[test]
    fn test_compare_versions_compatible_release_prerelease_alpha_newer() {
        // ~=4.0a with latest 4.1.0: user is on 4.0a, latest truncated to 4.1,
        // 4.0 < 4.1 → legitimate UpdateAvailable
        let info = make_version_info("4.1.0");
        match compare_versions("~=4.0a", &info) {
            VersionStatus::UpdateAvailable(v) => assert_eq!(v, "4.1"),
            _ => panic!("Expected UpdateAvailable"),
        }
    }

    #[test]
    fn test_compare_versions_compatible_release_prerelease_rc() {
        // ~=2.0rc1 with latest 1.9.0: 2.0 > 1.9 → UpToDate
        let info = make_version_info("1.9.0");
        assert!(matches!(
            compare_versions("~=2.0rc1", &info),
            VersionStatus::UpToDate
        ));
    }

    #[test]
    fn test_compare_versions_compatible_release_prerelease_beta_3seg() {
        // ~=1.0.0b2 with latest 1.0.5: base_clean = 1.0.0, truncated = 1.0.5,
        // 1.0.0 < 1.0.5 → UpdateAvailable
        let info = make_version_info("1.0.5");
        match compare_versions("~=1.0.0b2", &info) {
            VersionStatus::UpdateAvailable(v) => assert_eq!(v, "1.0.5"),
            _ => panic!("Expected UpdateAvailable"),
        }
    }

    #[test]
    fn test_compare_versions_compatible_release_prerelease_dev() {
        // ~=4.0.dev1 with latest 3.11.0: base_clean = 4.0.0 (dev1 → 0),
        // segments = 3, truncated = 3.11.0, 4.0.0 > 3.11.0 → UpToDate
        let info = make_version_info("3.11.0");
        assert!(matches!(
            compare_versions("~=4.0.dev1", &info),
            VersionStatus::UpToDate
        ));
    }

    #[test]
    fn test_truncate_version() {
        assert_eq!(truncate_version("14.3.3", 2), "14.3");
        assert_eq!(truncate_version("14.3.3", 3), "14.3.3");
        assert_eq!(truncate_version("14.3.3", 1), "14");
        assert_eq!(truncate_version("1.0", 2), "1.0");
        assert_eq!(truncate_version("1.0", 3), "1.0");
    }

    #[test]
    fn test_create_inlay_hint_up_to_date() {
        let dep = make_test_dep("serde", "1.0.0");
        let info = make_version_info("1.0.0");
        let hint = create_inlay_hint(&dep, Some(&info), FileType::Cargo);

        assert_eq!(hint.position.line, 5);
        match hint.label {
            InlayHintLabel::String(s) => assert!(s.contains("✓")),
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_create_inlay_hint_update_available() {
        let dep = make_test_dep("serde", "1.0.0");
        let info = make_version_info("2.0.0");
        let hint = create_inlay_hint(&dep, Some(&info), FileType::Cargo);

        match hint.label {
            InlayHintLabel::String(s) => {
                assert!(s.contains("->"));
                assert!(s.contains("2.0.0"));
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_deprecated_inlay_hint() {
        let dep = make_test_dep("old-dep", "1.0.0");
        let info = VersionInfo {
            deprecated: true,
            latest: Some("2.0.0".to_string()),
            description: Some("Superseded by new-package".to_string()),
            homepage: Some("https://example.com".to_string()),
            ..Default::default()
        };
        let hint = create_inlay_hint(&dep, Some(&info), FileType::Cargo);

        match hint.label {
            InlayHintLabel::String(s) => {
                assert!(s.contains("Deprecated"));
                assert!(s.contains("⚠"));
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_deprecated_with_update() {
        let dep = make_test_dep("old-dep", "1.0.0");
        let info = VersionInfo {
            deprecated: true,
            latest: Some("2.0.0".to_string()),
            ..Default::default()
        };
        let hint = create_inlay_hint(&dep, Some(&info), FileType::Cargo);

        match hint.label {
            InlayHintLabel::String(s) => {
                assert!(s.contains("Deprecated"));
                assert!(s.contains("2.0.0"));
                assert!(s.contains("->"));
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_no_deprecated_warning() {
        let dep = make_test_dep("serde", "1.0.0");
        let info = VersionInfo {
            deprecated: false,
            latest: Some("1.0.0".to_string()),
            ..Default::default()
        };
        let hint = create_inlay_hint(&dep, Some(&info), FileType::Cargo);

        match hint.label {
            InlayHintLabel::String(s) => {
                assert!(!s.contains("Deprecated"));
                assert!(!s.contains("⚠"));
                assert!(s.contains("✓"));
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_vulnerability_label_singular() {
        let dep = make_test_dep("serde", "1.0.0");
        let info = VersionInfo {
            latest: Some("1.0.0".to_string()),
            vulnerabilities: vec![Vulnerability {
                id: "CVE-2024-1234".to_string(),
                severity: VulnerabilitySeverity::High,
                description: "Test vulnerability".to_string(),
                url: None,
            }],
            ..Default::default()
        };
        let hint = create_inlay_hint(&dep, Some(&info), FileType::Cargo);

        match hint.label {
            InlayHintLabel::String(s) => {
                assert!(
                    s.contains("⚠ 1 vuln"),
                    "Expected '⚠ 1 vuln' in label, got: {s}"
                );
                assert!(!s.contains("vulns"), "Should use singular 'vuln', got: {s}");
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_vulnerability_label_plural() {
        let dep = make_test_dep("serde", "1.0.0");
        let info = VersionInfo {
            latest: Some("1.0.0".to_string()),
            vulnerabilities: vec![
                Vulnerability {
                    id: "CVE-2024-1234".to_string(),
                    severity: VulnerabilitySeverity::High,
                    description: "Test vulnerability 1".to_string(),
                    url: None,
                },
                Vulnerability {
                    id: "CVE-2024-5678".to_string(),
                    severity: VulnerabilitySeverity::Medium,
                    description: "Test vulnerability 2".to_string(),
                    url: None,
                },
            ],
            ..Default::default()
        };
        let hint = create_inlay_hint(&dep, Some(&info), FileType::Cargo);

        match hint.label {
            InlayHintLabel::String(s) => {
                assert!(
                    s.contains("⚠ 2 vulns"),
                    "Expected '⚠ 2 vulns' in label, got: {s}"
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_vulnerability_with_update_label() {
        let dep = make_test_dep("serde", "1.0.0");
        let info = VersionInfo {
            latest: Some("2.0.0".to_string()),
            vulnerabilities: vec![
                Vulnerability {
                    id: "CVE-2024-1234".to_string(),
                    severity: VulnerabilitySeverity::High,
                    description: "Test vulnerability 1".to_string(),
                    url: None,
                },
                Vulnerability {
                    id: "CVE-2024-5678".to_string(),
                    severity: VulnerabilitySeverity::Medium,
                    description: "Test vulnerability 2".to_string(),
                    url: None,
                },
            ],
            ..Default::default()
        };
        let hint = create_inlay_hint(&dep, Some(&info), FileType::Cargo);

        match hint.label {
            InlayHintLabel::String(s) => {
                assert!(
                    s.contains("⚠ 2 vulns"),
                    "Expected '⚠ 2 vulns' in label, got: {s}",
                );
                assert!(
                    s.contains("-> 2.0.0"),
                    "Expected '-> 2.0.0' in label, got: {s}",
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_deprecated_priority_over_vulnerabilities() {
        let dep = make_test_dep("dep", "1.0.0");
        let info = VersionInfo {
            deprecated: true,
            latest: None,
            vulnerabilities: vec![Vulnerability {
                id: "CVE-2024-1234".to_string(),
                severity: VulnerabilitySeverity::High,
                description: "Test vulnerability".to_string(),
                url: None,
            }],
            ..Default::default()
        };
        let hint = create_inlay_hint(&dep, Some(&info), FileType::Cargo);

        match hint.label {
            InlayHintLabel::String(s) => {
                assert!(s.contains("Deprecated"));
                assert!(!s.contains("vuln"));
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_yanked_inlay_hint() {
        let dep = make_test_dep("serde", "1.0.0");
        let info = VersionInfo {
            yanked_versions: vec!["1.0.0".to_string()],
            latest: Some("2.0.0".to_string()),
            ..Default::default()
        };
        let hint = create_inlay_hint(&dep, Some(&info), FileType::Cargo);

        match hint.label {
            InlayHintLabel::String(s) => {
                assert!(s.contains("Yanked"));
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_yanked_with_update() {
        let dep = make_test_dep("serde", "1.0.0");
        let info = VersionInfo {
            yanked_versions: vec!["1.0.0".to_string()],
            latest: Some("2.0.0".to_string()),
            ..Default::default()
        };
        let hint = create_inlay_hint(&dep, Some(&info), FileType::Cargo);

        match hint.label {
            InlayHintLabel::String(s) => {
                assert!(s.contains("Yanked"));
                assert!(s.contains("2.0.0"));
                assert!(s.contains("->"));
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_no_yanked_warning() {
        let dep = make_test_dep("serde", "1.0.0");
        let info = VersionInfo {
            yanked_versions: vec!["0.9.0".to_string()],
            latest: Some("1.0.0".to_string()),
            ..Default::default()
        };
        let hint = create_inlay_hint(&dep, Some(&info), FileType::Cargo);

        match hint.label {
            InlayHintLabel::String(s) => {
                assert!(!s.contains("Yanked"));
                assert!(s.contains("✓"));
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_yanked_priority_over_deprecated() {
        let dep = make_test_dep("dep", "1.0.0");
        let info = VersionInfo {
            yanked_versions: vec!["1.0.0".to_string()],
            deprecated: true,
            latest: Some("2.0.0".to_string()),
            ..Default::default()
        };
        let hint = create_inlay_hint(&dep, Some(&info), FileType::Cargo);

        match hint.label {
            InlayHintLabel::String(s) => {
                assert!(s.contains("Yanked"));
                assert!(!s.contains("Deprecated"));
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_yanked_priority_over_vulnerabilities() {
        let dep = make_test_dep("dep", "1.0.0");
        let info = VersionInfo {
            yanked_versions: vec!["1.0.0".to_string()],
            vulnerabilities: vec![Vulnerability {
                id: "CVE-2024-1234".to_string(),
                severity: VulnerabilitySeverity::High,
                description: "Test vulnerability".to_string(),
                url: None,
            }],
            latest: Some("2.0.0".to_string()),
            ..Default::default()
        };
        let hint = create_inlay_hint(&dep, Some(&info), FileType::Cargo);

        match hint.label {
            InlayHintLabel::String(s) => {
                assert!(s.contains("Yanked"));
                assert!(!s.contains("⚠"));
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_is_local_dependency() {
        // Path-based
        assert!(is_local_dependency("./my-lib"));
        assert!(is_local_dependency("../other-lib"));
        assert!(is_local_dependency("/absolute/path"));

        // File protocol (npm style)
        assert!(is_local_dependency("file:./my-local-lib"));
        assert!(is_local_dependency("file:../shared"));
        assert!(is_local_dependency("file:///absolute/path"));

        // Git dependencies
        assert!(is_local_dependency("git+https://github.com/user/repo"));
        assert!(is_local_dependency("git@github.com:user/repo.git"));
        assert!(is_local_dependency("git://github.com/user/repo.git"));

        // URL-based
        assert!(is_local_dependency("https://github.com/user/repo"));
        assert!(is_local_dependency("http://example.com/repo.tgz"));

        // Platform shortcuts
        assert!(is_local_dependency("github:user/repo"));
        assert!(is_local_dependency("gitlab:user/repo"));
        assert!(is_local_dependency("bitbucket:user/repo"));

        // Workspace protocols
        assert!(is_local_dependency("workspace:*"));
        assert!(is_local_dependency("link:./my-lib"));
        assert!(is_local_dependency("portal:./my-lib"));
        assert!(is_local_dependency("npm:lodash@^4.0.0"));

        // Not local - regular versions
        assert!(!is_local_dependency("1.0.0"));
        assert!(!is_local_dependency("^1.0"));
        assert!(!is_local_dependency("~1.0.0"));
        assert!(!is_local_dependency(">=1.0, <2.0"));
        assert!(!is_local_dependency("*"));
        assert!(!is_local_dependency("latest"));
    }

    #[test]
    fn test_npm_local_deps_detection() {
        use crate::parsers::{Parser, npm::NpmParser};

        let content = r#"{
  "dependencies": {
    "express": "^4.17.0",
    "my-local-lib": "file:./my-local-lib",
    "shared-utils": "../shared-utils",
    "git-package": "git+https://github.com/user/repo.git",
    "github-dep": "github:owner/project"
  }
}"#;

        let parser = NpmParser::new();
        let deps = parser.parse(content);

        assert_eq!(deps.len(), 5);

        for dep in &deps {
            println!("Dep: {} @ '{}'", dep.name, dep.version);
            let is_local = is_local_dependency(&dep.version);
            println!("  -> is_local: {is_local}");
        }

        let my_local = deps.iter().find(|d| d.name == "my-local-lib").unwrap();
        assert!(
            is_local_dependency(&my_local.version),
            "file:./my-local-lib should be local, got version: '{}'",
            my_local.version
        );

        let shared = deps.iter().find(|d| d.name == "shared-utils").unwrap();
        assert!(
            is_local_dependency(&shared.version),
            "../shared-utils should be local, got version: '{}'",
            shared.version
        );

        let git_pkg = deps.iter().find(|d| d.name == "git-package").unwrap();
        assert!(
            is_local_dependency(&git_pkg.version),
            "git+https://... should be local, got version: '{}'",
            git_pkg.version
        );

        let github = deps.iter().find(|d| d.name == "github-dep").unwrap();
        assert!(
            is_local_dependency(&github.version),
            "github:... should be local, got version: '{}'",
            github.version
        );

        let express = deps.iter().find(|d| d.name == "express").unwrap();
        assert!(
            !is_local_dependency(&express.version),
            "^4.17.0 should NOT be local"
        );
    }

    #[test]
    fn test_unknown_status_local_dependency() {
        let dep = make_test_dep("my-local-lib", "./my-local-lib");
        let hint = create_inlay_hint(&dep, None, FileType::Cargo);

        match hint.label {
            InlayHintLabel::String(s) => {
                assert!(
                    s.contains("→") || s.contains("Local"),
                    "Expected → Local in label, got: {s}"
                );
            }
            _ => panic!("Expected string label"),
        }

        if let Some(tower_lsp::lsp_types::InlayHintTooltip::String(tooltip)) = hint.tooltip {
            assert!(tooltip.contains("Local Dependency"));
            assert!(tooltip.contains("my-local-lib"));
        } else {
            panic!("Expected string tooltip");
        }
    }

    #[test]
    fn test_unknown_status_network_error() {
        let dep = make_test_dep("unknown-package", "1.0.0");
        let hint = create_inlay_hint(&dep, None, FileType::Cargo);

        match hint.label {
            InlayHintLabel::String(s) => {
                assert!(s.contains("?"), "Expected ? in label, got: {s}");
                assert!(!s.contains("Local"));
            }
            _ => panic!("Expected string label"),
        }

        if let Some(tower_lsp::lsp_types::InlayHintTooltip::String(tooltip)) = hint.tooltip {
            assert!(tooltip.contains("Could not fetch version info"));
            assert!(tooltip.contains("unknown-package"));
            assert!(tooltip.contains("Troubleshooting"));
        } else {
            panic!("Expected string tooltip");
        }
    }

    #[test]
    fn test_unknown_status_git_dependency() {
        let dep = make_test_dep("git-dep", "git@github.com:user/repo.git");
        let hint = create_inlay_hint(&dep, None, FileType::Cargo);

        match hint.label {
            InlayHintLabel::String(s) => {
                assert!(
                    s.contains("→") || s.contains("Local"),
                    "Expected → Local in label, got: {s}",
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    // --- Cargo.lock resolved version tests (issue #184) ---

    fn make_test_dep_with_resolved(name: &str, version: &str, resolved: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.to_string(),
            name_span: Span {
                line: 5,
                line_start: 0,
                line_end: name.len() as u32,
            },
            version_span: Span {
                line: 5,
                line_start: name.len() as u32 + 4,
                line_end: name.len() as u32 + 4 + version.len() as u32,
            },
            dev: false,
            optional: false,
            registry: None,
            resolved_version: Some(resolved.to_string()),
            has_additional_version_constraints: false,
        }
    }

    #[test]
    fn test_effective_version_with_resolved() {
        let dep = make_test_dep_with_resolved("bon", "3.9", "3.9.1");
        assert_eq!(dep.effective_version(), "3.9.1");
    }

    #[test]
    fn test_effective_version_without_resolved() {
        let dep = make_test_dep("bon", "3.9");
        assert_eq!(dep.effective_version(), "3.9");
    }

    #[test]
    fn test_resolved_version_prevents_false_positive() {
        // Issue #184: "bon = 3.9" with Cargo.lock having 3.9.1, latest is 3.9.1
        // Without resolved_version: compare_versions("3.9", info) → "3.9.0" < "3.9.1" → UpdateAvailable (BUG)
        // With resolved_version: compare_versions("3.9.1", info) → UpToDate (FIXED)
        let dep = make_test_dep_with_resolved("bon", "3.9", "3.9.1");
        let info = make_version_info("3.9.1");
        assert!(matches!(
            compare_versions(dep.effective_version(), &info),
            VersionStatus::UpToDate
        ));
    }

    #[test]
    fn test_resolved_version_caret_syntax() {
        // "^3.9" with Cargo.lock having 3.9.1, latest is 3.9.1
        let dep = make_test_dep_with_resolved("bon", "^3.9", "3.9.1");
        let info = make_version_info("3.9.1");
        assert!(matches!(
            compare_versions(dep.effective_version(), &info),
            VersionStatus::UpToDate
        ));
    }

    #[test]
    fn test_resolved_version_real_update_available() {
        // "3.9" with Cargo.lock having 3.9.1, but latest is 3.10.0
        let dep = make_test_dep_with_resolved("bon", "3.9", "3.9.1");
        let info = make_version_info("3.10.0");
        match compare_versions(dep.effective_version(), &info) {
            VersionStatus::UpdateAvailable(v) => assert_eq!(v, "3.10.0"),
            _ => panic!("Expected UpdateAvailable for genuine update"),
        }
    }

    #[test]
    fn test_resolved_version_major_only() {
        // "1" with Cargo.lock having 1.5.3, latest is 1.5.3
        let dep = make_test_dep_with_resolved("serde", "1", "1.5.3");
        let info = make_version_info("1.5.3");
        assert!(matches!(
            compare_versions(dep.effective_version(), &info),
            VersionStatus::UpToDate
        ));
    }

    #[test]
    fn test_inlay_hint_uses_resolved_version() {
        // End-to-end: create_inlay_hint should show UpToDate when resolved matches latest
        let dep = make_test_dep_with_resolved("bon", "3.9", "3.9.1");
        let info = make_version_info("3.9.1");
        let hint = create_inlay_hint(&dep, Some(&info), FileType::Cargo);
        match hint.label {
            InlayHintLabel::String(s) => assert!(
                s.contains("✓"),
                "Expected ✓ (up to date) with resolved version, got: {s}",
            ),
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_inlay_hint_without_resolved_shows_update() {
        // Without resolved_version, minimal syntax shows update available (original behavior)
        let dep = make_test_dep("bon", "3.9");
        let info = make_version_info("3.9.1");
        let hint = create_inlay_hint(&dep, Some(&info), FileType::Cargo);
        match hint.label {
            InlayHintLabel::String(s) => assert!(
                s.contains("->"),
                "Expected -> (update available) without resolved version, got: {s}",
            ),
            _ => panic!("Expected string label"),
        }
    }
}
