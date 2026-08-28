//! Diagnostic provider for dependency manifests.
//!
//! [`crate::providers::diagnostics::create_diagnostics`] is the main entry
//! point. For each non-ignored dependency it pushes LSP
//! [`tower_lsp::lsp_types::Diagnostic`] entries chosen as follows:
//!
//! - **Local / path dependency** — a single informational `→ Local` hint;
//!   no further diagnostics are emitted for the entry.
//! - **Registry dependency** — an optional **outdated** hint
//!   (`Update available: X → Y`) plus, when applicable, exactly one of the
//!   higher-severity diagnostics below, picked in this priority order:
//!
//!   1. **Yanked version** — warning with a link to the registry page.
//!   2. **Deprecated package** — warning with optional homepage / repository links.
//!   3. **Vulnerability summary** — error/warning/hint depending on max severity.
//!
//! Helper function
//! [`crate::providers::diagnostics::build_transitive_summary_message`] is
//! public so the vulnerability report generator can reuse the formatting logic.

use core::fmt;

use tower_lsp::lsp_types::*;

use crate::cache::ReadCache;
use crate::file_types::FileType;
use crate::parsers::Dependency;
use crate::providers::inlay_hints::{VersionStatus, compare_versions, is_local_dependency};
use crate::registries::{TransitiveVuln, VersionInfo, Vulnerability, VulnerabilitySeverity};
use crate::utils::fmt_truncate_string;

/// Build LSP diagnostics for the given dependency list.
///
/// For each non-ignored dependency the function performs a single cache lookup
/// and may emit an outdated-version hint plus, when applicable, one
/// higher-severity diagnostic (yanked, deprecated, or vulnerability summary)
/// following the priority order documented in the [module level docs](self).
///
/// # Parameters
///
/// - `dependencies` — all dependencies parsed from the current manifest.
/// - `cache` — read-only cache handle used to look up version metadata.
/// - `cache_key_fn` — maps a package name to its cache key.
/// - `min_severity` — when `Some`, vulnerability diagnostics are suppressed
///   unless at least one vulnerability meets the threshold.
/// - `file_type` — used to format registry names in yanked-version messages.
/// - `doc_transitive_vulns` — per-document transitive vulnerability data keyed
///   by direct-dependency name.  Stored separately from the shared version cache
///   to avoid cross-workspace contamination.
/// - `ignored` — package names (wildcards supported) that should be skipped.
///
/// # Returns
///
/// A [`Vec<Diagnostic>`] in the same order as `dependencies`, with at most
/// one entry per dependency.
pub async fn create_diagnostics(
    dependencies: &[Dependency],
    cache: &impl ReadCache,
    cache_key_fn: impl Fn(&str) -> String,
    min_severity: Option<VulnerabilitySeverity>,
    file_type: FileType,
    doc_transitive_vulns: &hashbrown::HashMap<String, Vec<TransitiveVuln>>,
    ignored: &[String],
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    for dep in dependencies {
        // Skip dependencies matching any `ignore` pattern (matches inlay_hints behavior).
        if crate::config::is_package_ignored(&dep.name, ignored) {
            continue;
        }

        // Show informational diagnostic for local/path dependencies
        if is_local_dependency(&dep.version) {
            diagnostics.push(create_local_dependency_diagnostic(dep));
            continue;
        }

        // Single cache lookup per dependency: reuse the result for the outdated,
        // yanked, deprecated, and vulnerability checks below. Avoids two
        // back-to-back `spawn_blocking` round-trips against `SqliteCache`.
        let cache_key = cache_key_fn(&dep.name);
        let cached = cache.get(&cache_key).await;

        // Add outdated version diagnostic
        if let Some(diag) = create_outdated_diagnostic(dep, cached.as_ref()) {
            diagnostics.push(diag);
        }

        if let Some(version_info) = cached {
            // Add yanked version diagnostic (highest priority)
            if version_info.is_version_yanked(dep.effective_version()) {
                tracing::debug!(
                    "Package {} {} is yanked, creating diagnostic",
                    dep.name,
                    dep.version
                );
                diagnostics.push(create_yanked_diagnostic(dep, &version_info, file_type));
            } else if version_info.deprecated {
                // Add deprecation diagnostic
                tracing::debug!(
                    "Package {} {} is deprecated, creating diagnostic",
                    dep.name,
                    dep.version
                );
                diagnostics.push(create_deprecation_diagnostic(dep, &version_info));
            } else {
                // Add vulnerability diagnostic (summary) only if not deprecated or yanked.
                // Per-document transitive vulns are sourced from doc_transitive_vulns to avoid
                // cross-workspace contamination from the shared global version_cache.
                let filtered_vulns: Vec<_> = version_info
                    .vulnerabilities
                    .iter()
                    .filter(|vuln| {
                        min_severity
                            .as_ref()
                            .map(|min| meets_severity_threshold(&vuln.severity, min))
                            .unwrap_or(true)
                    })
                    .collect();

                let filtered_transitive: Vec<&TransitiveVuln> = doc_transitive_vulns
                    .get(&dep.name)
                    .map(|v| {
                        v.iter()
                            .filter(|t| {
                                min_severity
                                    .as_ref()
                                    .map(|min| {
                                        meets_severity_threshold(&t.vulnerability.severity, min)
                                    })
                                    .unwrap_or(true)
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                if !filtered_vulns.is_empty() || !filtered_transitive.is_empty() {
                    diagnostics.push(create_vulnerability_summary_diagnostic(
                        dep,
                        &filtered_vulns,
                        &filtered_transitive,
                    ));
                }
            }
        }
    }

    diagnostics
}

/// Check if a vulnerability severity meets the minimum threshold
fn meets_severity_threshold(severity: &VulnerabilitySeverity, min: &VulnerabilitySeverity) -> bool {
    severity.meets_threshold(min)
}

/// Create a diagnostic for an outdated dependency.
///
/// Takes the already-fetched `VersionInfo` to avoid an extra cache round-trip
/// (the caller in `create_diagnostics` looks the value up once and reuses it
/// for outdated, yanked, deprecated, and vulnerability checks).
fn create_outdated_diagnostic(
    dep: &Dependency,
    version_info: Option<&VersionInfo>,
) -> Option<Diagnostic> {
    let version_info = version_info?;

    match compare_versions(dep.effective_version(), version_info) {
        VersionStatus::UpdateAvailable(new_version) => Some(Diagnostic {
            range: Range {
                start: Position {
                    line: dep.version_span.line,
                    character: dep.version_span.line_start,
                },
                end: Position {
                    line: dep.version_span.line,
                    character: dep.version_span.line_end,
                },
            },
            severity: Some(DiagnosticSeverity::HINT),
            code: Some(NumberOrString::String("outdated".to_string())),
            source: Some("depsy".to_string()),
            message: format!(
                "Update available: {} -> {new_version}",
                dep.effective_version()
            ),
            related_information: None,
            tags: None,
            code_description: None,
            data: None,
        }),
        VersionStatus::UpToDate | VersionStatus::Unknown => None,
    }
}

/// Create a diagnostic for a local/path dependency
fn create_local_dependency_diagnostic(dep: &Dependency) -> Diagnostic {
    Diagnostic {
        range: Range {
            start: Position {
                line: dep.version_span.line,
                character: dep.version_span.line_start,
            },
            end: Position {
                line: dep.version_span.line,
                character: dep.version_span.line_end,
            },
        },
        severity: Some(DiagnosticSeverity::HINT),
        code: Some(NumberOrString::String("local".to_string())),
        source: Some("depsy".to_string()),
        message: "→ Local".to_string(),
        related_information: None,
        tags: None,
        code_description: None,
        data: None,
    }
}

/// Create a diagnostic for a deprecated package
fn create_deprecation_diagnostic(dep: &Dependency, version_info: &VersionInfo) -> Diagnostic {
    let mut message = format!(
        "The package '{}' is deprecated. Consider migrating to an alternative.",
        dep.name
    );

    if let Some(latest) = version_info.latest.as_deref() {
        message.push_str(&format!(
            " Latest version: {latest} (may not be deprecated)."
        ));
    }

    let mut related_info = Vec::new();

    if let Some(homepage) = &version_info.homepage {
        related_info.push(DiagnosticRelatedInformation {
            location: Location {
                uri: Url::parse(homepage).unwrap_or_else(|_| {
                    Url::parse("https://example.com").expect("Invalid fallback URL")
                }),
                range: Range::default(),
            },
            message: "Visit package homepage".to_string(),
        });
    }

    if let Some(repo) = &version_info.repository {
        related_info.push(DiagnosticRelatedInformation {
            location: Location {
                uri: Url::parse(repo).unwrap_or_else(|_| {
                    Url::parse("https://github.com").expect("Invalid fallback URL")
                }),
                range: Range::default(),
            },
            message: "View repository for migration guide".to_string(),
        });
    }

    Diagnostic {
        range: Range {
            start: Position {
                line: dep.version_span.line,
                character: dep.version_span.line_start,
            },
            end: Position {
                line: dep.version_span.line,
                character: dep.version_span.line_end,
            },
        },
        severity: Some(DiagnosticSeverity::WARNING),
        code: Some(NumberOrString::String("deprecated-package".to_string())),
        source: Some("depsy".to_string()),
        message,
        related_information: if related_info.is_empty() {
            None
        } else {
            Some(related_info)
        },
        tags: None,
        code_description: None,
        data: None,
    }
}

/// Create a diagnostic for a yanked version
fn create_yanked_diagnostic(
    dep: &Dependency,
    version_info: &VersionInfo,
    file_type: FileType,
) -> Diagnostic {
    let dep_name = &*dep.name;
    let dep_version = dep.effective_version();
    let has_custom_registry = dep.registry.is_some();

    let message = if has_custom_registry {
        // Alternative registry — omit registry name since fmt_registry_package_url
        // would incorrectly point to the default registry
        fmt::from_fn(|f| {
            write!(
                f,
                "The version '{dep_version}' of '{dep_name}' has been yanked and should not be used.",
            )?;
            if let Some(latest) = version_info.latest.as_deref() {
                write!(f, " Update to {latest}.")?;
            }
            Ok(())
        })
        .to_string()
    } else {
        let registry = file_type.registry_name();
        fmt::from_fn(|f| {
            write!(
                f,
                "The version '{dep_version}' of '{dep_name}' has been yanked from {registry} and should not be used.",
            )?;
            if let Some(latest) = version_info.latest.as_deref() {
                write!(f, " Update to {latest}.")?;
            }
            Ok(())
        })
        .to_string()
    };

    let mut related_info = Vec::new();

    // Only add registry package link for default registries
    if !has_custom_registry {
        let registry_url_str = file_type.fmt_registry_package_url(&dep.name).to_string();
        if let Ok(url) = Url::parse(&registry_url_str) {
            related_info.push(DiagnosticRelatedInformation {
                location: Location {
                    uri: url,
                    range: Range::default(),
                },
                message: format!("View package on {}", file_type.registry_name()),
            });
        }
    }

    if let Some(repo) = &version_info.repository {
        related_info.push(DiagnosticRelatedInformation {
            location: Location {
                uri: Url::parse(repo).unwrap_or_else(|_| {
                    Url::parse("https://github.com").expect("fallback URL is valid")
                }),
                range: Range::default(),
            },
            message: "View repository for more information".to_string(),
        });
    }

    // Use registry URL for code_description only for default registries
    let code_description_href = if has_custom_registry {
        version_info
            .repository
            .as_deref()
            .and_then(|r| Url::parse(r).ok())
    } else {
        let registry_url_str = file_type.fmt_registry_package_url(&dep.name).to_string();
        Url::parse(&registry_url_str).ok()
    };

    Diagnostic {
        range: Range {
            start: Position {
                line: dep.version_span.line,
                character: dep.version_span.line_start,
            },
            end: Position {
                line: dep.version_span.line,
                character: dep.version_span.line_end,
            },
        },
        severity: Some(DiagnosticSeverity::WARNING),
        code: Some(NumberOrString::String("yanked-version".to_string())),
        source: Some("depsy".to_string()),
        message,
        related_information: if related_info.is_empty() {
            None
        } else {
            Some(related_info)
        },
        tags: None,
        code_description: code_description_href.map(|href| CodeDescription { href }),
        data: None,
    }
}

/// Format a short summary of transitive vulnerabilities for display in a diagnostic message.
///
/// Lists up to three entries as `pkg@ver (ID)` and appends `+N more` when
/// there are additional entries.  Returns an empty string when `tv` is empty.
///
/// # Examples
///
/// ```
/// use depsy_lsp::providers::diagnostics::build_transitive_summary_message;
/// use depsy_lsp::registries::{TransitiveVuln, Vulnerability, VulnerabilitySeverity};
///
/// let tv = vec![TransitiveVuln {
///     package_name: "scheduler".to_string(),
///     package_version: "1.2.3".to_string(),
///     vulnerability: Vulnerability {
///         id: "CVE-1".to_string(),
///         severity: VulnerabilitySeverity::High,
///         description: "desc".to_string(),
///         url: None,
///     },
/// }];
/// let refs: Vec<&_> = tv.iter().collect();
/// let msg = build_transitive_summary_message(&refs);
/// assert!(msg.contains("scheduler@1.2.3"));
/// assert!(msg.contains("CVE-1"));
/// assert!(msg.contains("1 transitive"));
/// ```
pub fn build_transitive_summary_message(tv: &[&TransitiveVuln]) -> String {
    if tv.is_empty() {
        return String::new();
    }
    let mut parts: Vec<String> = tv
        .iter()
        .take(3)
        .map(|t| {
            let name = &t.package_name;
            let ver = &t.package_version;
            let id = &t.vulnerability.id;
            format!("{name}@{ver} ({id})")
        })
        .collect();
    if tv.len() > 3 {
        parts.push(format!("+{} more", tv.len() - 3));
    }
    let n = tv.len();
    format!("{n} transitive vuln(s): {}", parts.join(", "))
}

/// Create a summary diagnostic for multiple vulnerabilities
fn create_vulnerability_summary_diagnostic(
    dep: &Dependency,
    vulns: &[&Vulnerability],
    transitive_vulns: &[&TransitiveVuln],
) -> Diagnostic {
    let count = vulns.len();

    // Use the highest severity among all vulnerabilities (direct + transitive)
    let severity_to_num = |s: &VulnerabilitySeverity| match s {
        VulnerabilitySeverity::Critical => 4,
        VulnerabilitySeverity::High => 3,
        VulnerabilitySeverity::Medium => 2,
        VulnerabilitySeverity::Low => 1,
    };
    let max_direct_sev = vulns
        .iter()
        .map(|v| &v.severity)
        .max_by_key(|s| severity_to_num(s))
        .unwrap_or(&VulnerabilitySeverity::Low);
    let max_transitive_sev = transitive_vulns
        .iter()
        .map(|t| &t.vulnerability.severity)
        .max_by_key(|s| severity_to_num(s));
    let max_severity = if vulns.is_empty() {
        max_transitive_sev.unwrap_or(&VulnerabilitySeverity::Low)
    } else {
        match max_transitive_sev {
            Some(ts) if severity_to_num(ts) > severity_to_num(max_direct_sev) => ts,
            _ => max_direct_sev,
        }
    };

    let diagnostic_severity = match max_severity {
        VulnerabilitySeverity::Critical | VulnerabilitySeverity::High => DiagnosticSeverity::ERROR,
        VulnerabilitySeverity::Medium => DiagnosticSeverity::WARNING,
        VulnerabilitySeverity::Low => DiagnosticSeverity::HINT,
    };

    // Build summary message: direct only, transitive only, or both
    let message = if vulns.is_empty() {
        // Transitive-only case
        build_transitive_summary_message(transitive_vulns)
    } else {
        let vuln_word = if count == 1 { "vuln" } else { "vulns" };
        let vuln_ids: Vec<_> = vulns.iter().map(|v| v.id.as_str()).collect();
        let mut msg = format!("⚠ {count} {vuln_word}: {}", vuln_ids.join(", "));
        if !transitive_vulns.is_empty() {
            let tv_msg = build_transitive_summary_message(transitive_vulns);
            msg.push_str(" — ");
            msg.push_str(&tv_msg);
        }
        msg
    };

    // The diagnostic code uses the total count (direct + transitive vuln entries)
    let total_count = count + transitive_vulns.len();

    // Collect related information for direct vulnerabilities
    let related_info: Vec<_> = vulns
        .iter()
        .filter_map(|&vuln| {
            vuln.url.as_deref().map(|url| DiagnosticRelatedInformation {
                location: Location {
                    uri: Url::parse(url).unwrap_or_else(|_| {
                        Url::parse("https://osv.dev").expect("Invalid fallback URL")
                    }),
                    range: Range::default(),
                },
                message: format!(
                    "{}: {}",
                    vuln.id,
                    fmt_truncate_string(&vuln.description, 80)
                ),
            })
        })
        .collect();

    Diagnostic {
        range: Range {
            start: Position {
                line: dep.version_span.line,
                character: dep.version_span.line_start,
            },
            end: Position {
                line: dep.version_span.line,
                character: dep.version_span.line_end,
            },
        },
        severity: Some(diagnostic_severity),
        code: Some(NumberOrString::String(format!("{total_count}-vulns"))),
        source: Some("depsy-security".to_string()),
        message,
        related_information: (!related_info.is_empty()).then_some(related_info),
        tags: None,
        code_description: vulns.first().and_then(|v| {
            v.url
                .as_ref()
                .and_then(|url| Url::parse(url).ok().map(|href| CodeDescription { href }))
        }),
        data: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{MemoryCache, WriteCache};
    use crate::file_types::FileType;
    use crate::parsers::Span;
    use crate::registries::VersionInfo;

    fn create_test_dependency(name: &str, version: &str, line: u32) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.to_string(),
            name_span: Span {
                line,
                line_start: 0,
                line_end: name.len() as u32,
            },
            version_span: Span {
                line,
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

    #[tokio::test]
    async fn test_create_diagnostic_outdated() {
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:serde".to_string(),
                VersionInfo {
                    latest: Some("2.0.0".to_string()),
                    ..Default::default()
                },
            )
            .await;

        let deps = vec![create_test_dependency("serde", "1.0.0", 5)];
        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &[],
        )
        .await;

        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].message.contains("2.0.0"));
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::HINT));
    }

    #[tokio::test]
    async fn test_no_diagnostic_up_to_date() {
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:serde".to_string(),
                VersionInfo {
                    latest: Some("1.0.0".to_string()),
                    ..Default::default()
                },
            )
            .await;

        let deps = vec![create_test_dependency("serde", "1.0.0", 5)];
        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &[],
        )
        .await;

        assert_eq!(diagnostics.len(), 0);
    }

    #[tokio::test]
    async fn test_no_diagnostic_no_cache() {
        let cache = MemoryCache::new();
        let deps = vec![create_test_dependency("unknown", "1.0.0", 5)];
        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &[],
        )
        .await;

        assert_eq!(diagnostics.len(), 0);
    }

    #[test]
    fn test_severity_filtering() {
        assert!(meets_severity_threshold(
            &VulnerabilitySeverity::Critical,
            &VulnerabilitySeverity::Low
        ));
        assert!(meets_severity_threshold(
            &VulnerabilitySeverity::High,
            &VulnerabilitySeverity::Medium
        ));
        assert!(!meets_severity_threshold(
            &VulnerabilitySeverity::Low,
            &VulnerabilitySeverity::High
        ));
        assert!(meets_severity_threshold(
            &VulnerabilitySeverity::Medium,
            &VulnerabilitySeverity::Medium
        ));
    }

    #[tokio::test]
    async fn test_deprecated_diagnostic() {
        let deps = vec![create_test_dependency("old-dep", "1.0.0", 5)];
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:old-dep".to_string(),
                VersionInfo {
                    deprecated: true,
                    latest: Some("2.0.0".to_string()),
                    homepage: Some("https://example.com".to_string()),
                    ..Default::default()
                },
            )
            .await;

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &[],
        )
        .await;

        let deprecation_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| {
                d.code
                    .as_ref()
                    .and_then(|c| match c {
                        NumberOrString::String(s) => Some(s.contains("deprecated")),
                        _ => None,
                    })
                    .unwrap_or(false)
            })
            .collect();

        assert_eq!(deprecation_diags.len(), 1);
        assert!(deprecation_diags[0].message.contains("deprecated"));
        assert_eq!(
            deprecation_diags[0].severity,
            Some(DiagnosticSeverity::WARNING)
        );
        assert!(deprecation_diags[0].related_information.is_some());
    }

    #[tokio::test]
    async fn test_no_deprecated_diagnostic_for_active() {
        let deps = vec![create_test_dependency("serde", "1.0.0", 5)];
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:serde".to_string(),
                VersionInfo {
                    deprecated: false,
                    latest: Some("1.0.0".to_string()),
                    ..Default::default()
                },
            )
            .await;

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &[],
        )
        .await;

        let deprecation_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| {
                d.code
                    .as_ref()
                    .and_then(|c| match c {
                        NumberOrString::String(s) => Some(s.contains("deprecated")),
                        _ => None,
                    })
                    .unwrap_or(false)
            })
            .collect();

        assert_eq!(deprecation_diags.len(), 0);
    }

    #[tokio::test]
    async fn test_deprecated_with_vulnerabilities() {
        let deps = vec![create_test_dependency("vuln-dep", "1.0.0", 5)];
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:vuln-dep".to_string(),
                VersionInfo {
                    deprecated: true,
                    vulnerabilities: vec![Vulnerability {
                        id: "CVE-2024-1234".to_string(),
                        severity: VulnerabilitySeverity::High,
                        description: "Test vulnerability".to_string(),
                        url: None,
                    }],
                    ..Default::default()
                },
            )
            .await;

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &[],
        )
        .await;

        let deprecation_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| {
                d.code
                    .as_ref()
                    .and_then(|c| match c {
                        NumberOrString::String(s) => Some(s.contains("deprecated")),
                        _ => None,
                    })
                    .unwrap_or(false)
            })
            .collect();

        let vuln_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| {
                d.code
                    .as_ref()
                    .and_then(|c| match c {
                        NumberOrString::String(s) => Some(s.starts_with("CVE")),
                        _ => None,
                    })
                    .unwrap_or(false)
            })
            .collect();

        assert_eq!(deprecation_diags.len(), 1);
        assert_eq!(
            vuln_diags.len(),
            0,
            "Deprecated packages should not show individual vulnerability diagnostics"
        );
    }

    #[tokio::test]
    async fn test_yanked_diagnostic() {
        let deps = vec![create_test_dependency("serde", "1.0.0", 5)];
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:serde".to_string(),
                VersionInfo {
                    yanked_versions: vec!["1.0.0".to_string()],
                    latest: Some("2.0.0".to_string()),
                    ..Default::default()
                },
            )
            .await;

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &[],
        )
        .await;

        let yanked_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| {
                d.code
                    .as_ref()
                    .and_then(|c| match c {
                        NumberOrString::String(s) => Some(s.contains("yanked")),
                        _ => None,
                    })
                    .unwrap_or(false)
            })
            .collect();

        assert_eq!(yanked_diags.len(), 1);
        assert!(yanked_diags[0].message.contains("yanked"));
        assert_eq!(yanked_diags[0].severity, Some(DiagnosticSeverity::WARNING));
    }

    #[tokio::test]
    async fn test_no_yanked_diagnostic_for_non_yanked() {
        let deps = vec![create_test_dependency("serde", "1.0.0", 5)];
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:serde".to_string(),
                VersionInfo {
                    yanked_versions: vec!["0.9.0".to_string()],
                    latest: Some("1.0.0".to_string()),
                    ..Default::default()
                },
            )
            .await;

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &[],
        )
        .await;

        let yanked_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| {
                d.code
                    .as_ref()
                    .and_then(|c| match c {
                        NumberOrString::String(s) => Some(s.contains("yanked")),
                        _ => None,
                    })
                    .unwrap_or(false)
            })
            .collect();

        assert_eq!(yanked_diags.len(), 0);
    }

    #[tokio::test]
    async fn test_yanked_priority_over_deprecated_diagnostic() {
        let deps = vec![create_test_dependency("serde", "1.0.0", 5)];
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:serde".to_string(),
                VersionInfo {
                    yanked_versions: vec!["1.0.0".to_string()],
                    deprecated: true,
                    latest: Some("2.0.0".to_string()),
                    ..Default::default()
                },
            )
            .await;

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &[],
        )
        .await;

        let yanked_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| {
                d.code
                    .as_ref()
                    .and_then(|c| match c {
                        NumberOrString::String(s) => Some(s.contains("yanked")),
                        _ => None,
                    })
                    .unwrap_or(false)
            })
            .collect();

        let deprecated_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| {
                d.code
                    .as_ref()
                    .and_then(|c| match c {
                        NumberOrString::String(s) => Some(s.contains("deprecated")),
                        _ => None,
                    })
                    .unwrap_or(false)
            })
            .collect();

        assert_eq!(yanked_diags.len(), 1, "Should show yanked diagnostic");
        assert_eq!(
            deprecated_diags.len(),
            0,
            "Yanked packages should not show deprecated diagnostic"
        );
    }

    #[tokio::test]
    async fn test_yanked_priority_over_vulnerabilities_diagnostic() {
        let deps = vec![create_test_dependency("serde", "1.0.0", 5)];
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:serde".to_string(),
                VersionInfo {
                    yanked_versions: vec!["1.0.0".to_string()],
                    vulnerabilities: vec![Vulnerability {
                        id: "CVE-2024-1234".to_string(),
                        severity: VulnerabilitySeverity::High,
                        description: "Test vulnerability".to_string(),
                        url: None,
                    }],
                    latest: Some("2.0.0".to_string()),
                    ..Default::default()
                },
            )
            .await;

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &[],
        )
        .await;

        let yanked_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| {
                d.code
                    .as_ref()
                    .and_then(|c| match c {
                        NumberOrString::String(s) => Some(s.contains("yanked")),
                        _ => None,
                    })
                    .unwrap_or(false)
            })
            .collect();

        let vuln_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| {
                d.code
                    .as_ref()
                    .and_then(|c| match c {
                        NumberOrString::String(s) => Some(s.starts_with("CVE")),
                        _ => None,
                    })
                    .unwrap_or(false)
            })
            .collect();

        assert_eq!(yanked_diags.len(), 1, "Should show yanked diagnostic");
        assert_eq!(
            vuln_diags.len(),
            0,
            "Yanked packages should not show vulnerability diagnostics"
        );
    }

    #[tokio::test]
    async fn test_local_dependency_diagnostic() {
        let deps = vec![create_test_dependency("local-crate", "../local", 5)];
        let cache = MemoryCache::new();

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &[],
        )
        .await;

        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].message.contains("Local"));
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::HINT));
    }

    #[tokio::test]
    async fn test_vulnerability_summary_diagnostic() {
        let deps = vec![create_test_dependency("vuln-dep", "1.0.0", 5)];
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:vuln-dep".to_string(),
                VersionInfo {
                    latest: Some("1.0.0".to_string()),
                    vulnerabilities: vec![
                        Vulnerability {
                            id: "CVE-2024-1234".to_string(),
                            severity: VulnerabilitySeverity::High,
                            description: "High severity vulnerability".to_string(),
                            url: Some("https://osv.dev/CVE-2024-1234".to_string()),
                        },
                        Vulnerability {
                            id: "CVE-2024-5678".to_string(),
                            severity: VulnerabilitySeverity::Medium,
                            description: "Medium severity vulnerability".to_string(),
                            url: None,
                        },
                    ],
                    ..Default::default()
                },
            )
            .await;

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &[],
        )
        .await;

        let vuln_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| {
                d.code
                    .as_ref()
                    .is_some_and(|c| matches!(c, NumberOrString::String(s) if s.contains("vulns")))
            })
            .collect();

        assert_eq!(vuln_diags.len(), 1);
        assert!(vuln_diags[0].message.contains("2 vulns"));
        assert_eq!(vuln_diags[0].severity, Some(DiagnosticSeverity::ERROR));
        assert!(vuln_diags[0].related_information.is_some());
    }

    #[tokio::test]
    async fn test_vulnerability_severity_filtering() {
        let deps = vec![create_test_dependency("vuln-dep", "1.0.0", 5)];
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:vuln-dep".to_string(),
                VersionInfo {
                    latest: Some("1.0.0".to_string()),
                    vulnerabilities: vec![
                        Vulnerability {
                            id: "CVE-2024-LOW".to_string(),
                            severity: VulnerabilitySeverity::Low,
                            description: "Low severity".to_string(),
                            url: None,
                        },
                        Vulnerability {
                            id: "CVE-2024-HIGH".to_string(),
                            severity: VulnerabilitySeverity::High,
                            description: "High severity".to_string(),
                            url: None,
                        },
                    ],
                    ..Default::default()
                },
            )
            .await;

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            Some(VulnerabilitySeverity::High),
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &[],
        )
        .await;

        let vuln_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| {
                d.code
                    .as_ref()
                    .is_some_and(|c| matches!(c, NumberOrString::String(s) if s.contains("vulns")))
            })
            .collect();

        assert_eq!(vuln_diags.len(), 1);
        assert!(vuln_diags[0].message.contains("1 vuln"));
    }

    #[tokio::test]
    async fn test_deprecation_diagnostic_with_repository() {
        let deps = vec![create_test_dependency("old-dep", "1.0.0", 5)];
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:old-dep".to_string(),
                VersionInfo {
                    deprecated: true,
                    latest: Some("2.0.0".to_string()),
                    repository: Some("https://github.com/user/old-dep".to_string()),
                    ..Default::default()
                },
            )
            .await;

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &[],
        )
        .await;

        let deprecation_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| {
                d.code.as_ref().is_some_and(
                    |c| matches!(c, NumberOrString::String(s) if s.contains("deprecated")),
                )
            })
            .collect();

        assert_eq!(deprecation_diags.len(), 1);
        assert!(deprecation_diags[0].related_information.is_some());
        let related = deprecation_diags[0].related_information.as_ref().unwrap();
        assert!(!related.is_empty());
    }

    #[tokio::test]
    async fn test_yanked_diagnostic_with_repository() {
        let deps = vec![create_test_dependency("serde", "1.0.0", 5)];
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:serde".to_string(),
                VersionInfo {
                    yanked_versions: vec!["1.0.0".to_string()],
                    latest: Some("2.0.0".to_string()),
                    repository: Some("https://github.com/serde-rs/serde".to_string()),
                    ..Default::default()
                },
            )
            .await;

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &[],
        )
        .await;

        let yanked_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| {
                d.code
                    .as_ref()
                    .is_some_and(|c| matches!(c, NumberOrString::String(s) if s.contains("yanked")))
            })
            .collect();

        assert_eq!(yanked_diags.len(), 1);
        assert!(yanked_diags[0].related_information.is_some());
        let related = yanked_diags[0].related_information.as_ref().unwrap();
        assert_eq!(related.len(), 2);
    }

    #[test]
    fn test_build_transitive_summary_message_formats_correctly() {
        let tvs = [crate::registries::TransitiveVuln {
            package_name: "scheduler".to_string(),
            package_version: "1.2.3".to_string(),
            vulnerability: crate::registries::Vulnerability {
                id: "CVE-1".to_string(),
                severity: crate::registries::VulnerabilitySeverity::High,
                description: "x".to_string(),
                url: None,
            },
        }];
        let refs: Vec<&_> = tvs.iter().collect();
        let msg = build_transitive_summary_message(&refs);
        assert!(msg.contains("scheduler@1.2.3"));
        assert!(msg.contains("CVE-1"));
        assert!(msg.contains("1 transitive"));
    }

    #[test]
    fn test_build_transitive_summary_message_truncates_after_three() {
        let mk = |name: &str, id: &str| crate::registries::TransitiveVuln {
            package_name: name.to_string(),
            package_version: "1.0.0".to_string(),
            vulnerability: crate::registries::Vulnerability {
                id: id.to_string(),
                severity: crate::registries::VulnerabilitySeverity::Low,
                description: "x".to_string(),
                url: None,
            },
        };
        let tvs = [
            mk("a", "X1"),
            mk("b", "X2"),
            mk("c", "X3"),
            mk("d", "X4"),
            mk("e", "X5"),
        ];
        let refs: Vec<&_> = tvs.iter().collect();
        let msg = build_transitive_summary_message(&refs);
        assert!(msg.contains("+2 more"));
    }

    #[test]
    fn test_build_transitive_summary_message_empty() {
        let msg = build_transitive_summary_message(&[]);
        assert_eq!(msg, "");
    }

    #[tokio::test]
    async fn test_vulnerability_low_severity_hint() {
        let deps = vec![create_test_dependency("vuln-dep", "1.0.0", 5)];
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:vuln-dep".to_string(),
                VersionInfo {
                    latest: Some("1.0.0".to_string()),
                    vulnerabilities: vec![Vulnerability {
                        id: "CVE-2024-LOW".to_string(),
                        severity: VulnerabilitySeverity::Low,
                        description: "Low severity".to_string(),
                        url: None,
                    }],
                    ..Default::default()
                },
            )
            .await;

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &[],
        )
        .await;

        let vuln_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| {
                d.code
                    .as_ref()
                    .is_some_and(|c| matches!(c, NumberOrString::String(s) if s.contains("vulns")))
            })
            .collect();

        assert_eq!(vuln_diags.len(), 1);
        assert_eq!(vuln_diags[0].severity, Some(DiagnosticSeverity::HINT));
    }

    #[tokio::test]
    async fn test_vulnerability_medium_severity_warning() {
        let deps = vec![create_test_dependency("vuln-dep", "1.0.0", 5)];
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:vuln-dep".to_string(),
                VersionInfo {
                    latest: Some("1.0.0".to_string()),
                    vulnerabilities: vec![Vulnerability {
                        id: "CVE-2024-MED".to_string(),
                        severity: VulnerabilitySeverity::Medium,
                        description: "Medium severity".to_string(),
                        url: None,
                    }],
                    ..Default::default()
                },
            )
            .await;

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &[],
        )
        .await;

        let vuln_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| {
                d.code
                    .as_ref()
                    .is_some_and(|c| matches!(c, NumberOrString::String(s) if s.contains("vulns")))
            })
            .collect();

        assert_eq!(vuln_diags.len(), 1);
        assert_eq!(vuln_diags[0].severity, Some(DiagnosticSeverity::WARNING));
    }

    #[tokio::test]
    async fn test_vulnerability_critical_severity_error() {
        let deps = vec![create_test_dependency("vuln-dep", "1.0.0", 5)];
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:vuln-dep".to_string(),
                VersionInfo {
                    latest: Some("1.0.0".to_string()),
                    vulnerabilities: vec![Vulnerability {
                        id: "CVE-2024-CRIT".to_string(),
                        severity: VulnerabilitySeverity::Critical,
                        description: "Critical severity".to_string(),
                        url: None,
                    }],
                    ..Default::default()
                },
            )
            .await;

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &[],
        )
        .await;

        let vuln_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| {
                d.code
                    .as_ref()
                    .is_some_and(|c| matches!(c, NumberOrString::String(s) if s.contains("vulns")))
            })
            .collect();

        assert_eq!(vuln_diags.len(), 1);
        assert_eq!(vuln_diags[0].severity, Some(DiagnosticSeverity::ERROR));
    }

    #[tokio::test]
    async fn test_yanked_diagnostic_uses_registry_name_npm() {
        let deps = vec![create_test_dependency("lodash", "1.0.0", 5)];
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:lodash".to_string(),
                VersionInfo {
                    yanked_versions: vec!["1.0.0".to_string()],
                    latest: Some("4.17.21".to_string()),
                    ..Default::default()
                },
            )
            .await;

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Npm,
            &hashbrown::HashMap::new(),
            &[],
        )
        .await;

        let yanked_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| {
                d.code
                    .as_ref()
                    .is_some_and(|c| matches!(c, NumberOrString::String(s) if s.contains("yanked")))
            })
            .collect();

        assert_eq!(yanked_diags.len(), 1);
        // Must reference npm, NOT crates.io
        assert!(
            yanked_diags[0].message.contains("npm"),
            "Yanked diagnostic should reference 'npm', got: {}",
            yanked_diags[0].message
        );
        assert!(
            !yanked_diags[0].message.contains("crates.io"),
            "Yanked diagnostic should NOT reference 'crates.io' for npm packages"
        );
    }

    #[tokio::test]
    async fn test_diagnostic_fires_on_transitive_only_vulns() {
        use crate::registries::{
            TransitiveVuln, VersionInfo, Vulnerability, VulnerabilitySeverity,
        };

        let deps = vec![create_test_dependency("my-dep", "1.0.0", 5)];
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:my-dep".to_string(),
                VersionInfo {
                    latest: Some("1.0.0".to_string()),
                    ..Default::default()
                },
            )
            .await;

        // Transitive vulns are now stored per-document, not in version_cache.
        let mut doc_transitives: hashbrown::HashMap<String, Vec<TransitiveVuln>> =
            hashbrown::HashMap::new();
        doc_transitives.insert(
            "my-dep".to_string(),
            vec![TransitiveVuln {
                package_name: "scheduler".into(),
                package_version: "1.2.3".into(),
                vulnerability: Vulnerability {
                    id: "CVE-1".into(),
                    severity: VulnerabilitySeverity::High,
                    description: "desc".into(),
                    url: None,
                },
            }],
        );

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &doc_transitives,
            &[],
        )
        .await;

        let vuln_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| {
                d.code
                    .as_ref()
                    .is_some_and(|c| matches!(c, NumberOrString::String(s) if s.contains("vulns")))
            })
            .collect();

        assert_eq!(
            vuln_diags.len(),
            1,
            "Should emit diagnostic for transitive-only vulns"
        );
        assert!(
            vuln_diags[0].message.contains("transitive"),
            "Message should contain 'transitive', got: {}",
            vuln_diags[0].message
        );
        assert!(
            vuln_diags[0].message.contains("scheduler@1.2.3"),
            "Message should contain 'scheduler@1.2.3', got: {}",
            vuln_diags[0].message
        );
        assert_eq!(vuln_diags[0].severity, Some(DiagnosticSeverity::ERROR));
    }

    #[tokio::test]
    async fn test_transitive_vulns_respect_min_severity() {
        let deps = vec![create_test_dependency("my-dep", "1.0.0", 5)];
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:my-dep".to_string(),
                VersionInfo {
                    latest: Some("1.0.0".to_string()),
                    ..Default::default()
                },
            )
            .await;

        let mut doc_transitives: hashbrown::HashMap<String, Vec<TransitiveVuln>> =
            hashbrown::HashMap::new();
        doc_transitives.insert(
            "my-dep".to_string(),
            vec![
                TransitiveVuln {
                    package_name: "low-pkg".into(),
                    package_version: "1.0".into(),
                    vulnerability: Vulnerability {
                        id: "LOW-1".into(),
                        severity: VulnerabilitySeverity::Low,
                        description: "low".into(),
                        url: None,
                    },
                },
                TransitiveVuln {
                    package_name: "high-pkg".into(),
                    package_version: "2.0".into(),
                    vulnerability: Vulnerability {
                        id: "HIGH-1".into(),
                        severity: VulnerabilitySeverity::High,
                        description: "high".into(),
                        url: None,
                    },
                },
            ],
        );

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            Some(VulnerabilitySeverity::High),
            FileType::Cargo,
            &doc_transitives,
            &[],
        )
        .await;

        let vuln_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| {
                d.code
                    .as_ref()
                    .is_some_and(|c| matches!(c, NumberOrString::String(s) if s.contains("vulns")))
            })
            .collect();

        assert_eq!(
            vuln_diags.len(),
            1,
            "Should emit exactly one diagnostic for the high-severity transitive vuln"
        );
        assert!(
            vuln_diags[0].message.contains("HIGH-1"),
            "Message should contain HIGH-1, got: {}",
            vuln_diags[0].message
        );
        assert!(
            !vuln_diags[0].message.contains("LOW-1"),
            "Message should NOT contain LOW-1 when min_severity=High, got: {}",
            vuln_diags[0].message
        );
    }

    #[tokio::test]
    async fn test_diagnostic_skipped_for_ignored_package() {
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:lodash".to_string(),
                VersionInfo {
                    latest: Some("2.0.0".to_string()),
                    ..Default::default()
                },
            )
            .await;
        let deps = vec![create_test_dependency("lodash", "1.0.0", 5)];
        let ignored = vec!["lodash".to_string()];

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &ignored,
        )
        .await;

        assert!(
            diagnostics.is_empty(),
            "ignored package should not produce diagnostics"
        );
    }

    #[tokio::test]
    async fn test_diagnostic_skipped_for_wildcard_match() {
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:@internal/utils".to_string(),
                VersionInfo {
                    latest: Some("2.0.0".to_string()),
                    ..Default::default()
                },
            )
            .await;
        let deps = vec![create_test_dependency("@internal/utils", "1.0.0", 5)];
        let ignored = vec!["@internal/*".to_string()];

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &ignored,
        )
        .await;

        assert!(
            diagnostics.is_empty(),
            "wildcard-matched package should not produce diagnostics"
        );
    }

    #[tokio::test]
    async fn test_diagnostic_emitted_when_not_ignored() {
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:react".to_string(),
                VersionInfo {
                    latest: Some("18.0.0".to_string()),
                    ..Default::default()
                },
            )
            .await;
        let deps = vec![create_test_dependency("react", "17.0.0", 5)];
        let ignored = vec!["lodash".to_string()];

        let diagnostics = create_diagnostics(
            &deps,
            &cache,
            |name| format!("test:{name}"),
            None,
            FileType::Cargo,
            &hashbrown::HashMap::new(),
            &ignored,
        )
        .await;

        assert_eq!(
            diagnostics.len(),
            1,
            "non-ignored package should produce diagnostic"
        );
    }
}
