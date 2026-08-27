//! Completion provider for dependency version suggestions.
//!
//! When the cursor is positioned inside a version field,
//! [`crate::providers::completion::get_completions`] returns up to ten recent
//! versions as [`tower_lsp::lsp_types::CompletionItem`] entries, ordered
//! newest-first.  Each item includes the version string, an optional release
//! age computed by [`crate::providers::completion::fmt_release_age`], and a
//! Markdown documentation block that marks the latest stable version.

use core::fmt::{self, Write};

use chrono::{DateTime, Utc};
use tower_lsp::lsp_types::*;

use crate::cache::ReadCache;
use crate::parsers::Dependency;

/// Returns an <code>[fmt::Display] + [fmt::Debug]</code> implementation
/// which formats a release date as a human-readable age string.
///
/// # Side Effects
///
/// The `fmt` implementation calls [`chrono::Utc::now`] to get the current time,
/// so its result is not idempotent.
#[must_use = "returns a type implementing Display and Debug, which does not have any effects unless they are used"]
pub fn fmt_release_age(released_at: DateTime<Utc>) -> impl fmt::Display + fmt::Debug {
    fmt::from_fn(move |f| {
        let now = Utc::now();
        let duration = now.signed_duration_since(released_at);

        let plural_suffix = |amount| {
            fmt::from_fn(move |f| {
                if amount == 1 {
                    Ok(())
                } else {
                    f.write_char('s')
                }
            })
        };

        if duration.num_seconds() <= 0 {
            return f.write_str("just now");
        }
        let days = duration.num_days();

        if days == 0 {
            let hours = duration.num_hours();
            if hours == 0 {
                let mins = duration.num_minutes();
                if mins < 1 {
                    return f.write_str("just now");
                }
                return write!(f, "{mins} min{s} ago", s = plural_suffix(mins));
            }
            return write!(f, "{hours} hour{s} ago", s = plural_suffix(hours));
        }

        if days == 1 {
            return f.write_str("yesterday");
        }

        if days < 7 {
            return write!(f, "{days} days ago");
        }

        if days < 30 {
            let weeks = days / 7;
            return write!(f, "{weeks} week{s} ago", s = plural_suffix(weeks));
        }

        if days < 365 {
            let months = days / 30;
            return write!(f, "{months} month{s} ago", s = plural_suffix(months));
        }

        let years = days / 365;
        write!(f, "{years} year{s} ago", s = plural_suffix(years))
    })
}

/// Return version completions for the dependency whose `version_span` contains `position`.
///
/// Looks up the dependency name in `cache` using a key produced by
/// `cache_key_fn`, then maps the most-recent versions (up to ten) to
/// [`CompletionItem`] values.  Returns `None` when the cursor is not inside a
/// version field or when no cached version data is available.
///
/// # Parameters
///
/// - `dependencies` — all parsed dependencies for the current document.
/// - `position` — cursor position sent by the LSP client.
/// - `cache` — read-only cache handle.
/// - `cache_key_fn` — maps a package name to its cache lookup key.
///
/// # Returns
///
/// `Some(items)` with items ordered newest-first, or `None` when completion
/// is not applicable at the given position.
pub async fn get_completions(
    dependencies: &[Dependency],
    position: Position,
    cache: &impl ReadCache,
    cache_key_fn: impl Fn(&str) -> String,
) -> Option<Vec<CompletionItem>> {
    // Find if we're inside a version field
    let dep = dependencies
        .iter()
        .find(|d| d.version_span.contains_lsp_position(&position))?;

    let cache_key = cache_key_fn(&dep.name);
    let version_info = cache.get(&cache_key).await?;

    // Return the last 10 versions as completions
    let items: Vec<CompletionItem> = version_info
        .versions
        .iter()
        .take(10)
        .enumerate()
        .map(|(i, version)| {
            let is_latest = i == 0;
            let release_date = version_info.get_release_date(version);

            // Build detail string with version and optional release age
            let detail = match release_date {
                Some(dt) => {
                    let age = fmt_release_age(dt);
                    if is_latest {
                        format!("{version} [Latest] - {age}")
                    } else {
                        format!("{version} - {age}")
                    }
                }
                None => {
                    if is_latest {
                        format!("{version} [Latest]")
                    } else {
                        format!("Version {version}")
                    }
                }
            };

            // Build documentation with more details
            let documentation = {
                let has_content = is_latest || release_date.is_some();
                has_content.then(|| {
                    let doc = fmt::from_fn(|f| {
                        if is_latest {
                            write!(f, "**Latest stable version**\n\n")?;
                        }
                        if let Some(dt) = release_date {
                            let date_str = dt.format("%Y-%m-%d");
                            let age = fmt_release_age(dt);
                            write!(f, "Released: {date_str} ({age})")?;
                        }
                        Ok(())
                    })
                    .to_string();
                    Documentation::MarkupContent(MarkupContent {
                        kind: MarkupKind::Markdown,
                        value: doc,
                    })
                })
            };

            CompletionItem {
                label: version.clone(),
                kind: Some(CompletionItemKind::CONSTANT),
                detail: Some(detail),
                documentation,
                sort_text: Some(format!("{i:04}")), // Ensures correct ordering
                insert_text: Some(version.clone()),
                insert_text_format: Some(InsertTextFormat::PLAIN_TEXT),
                ..Default::default()
            }
        })
        .collect();

    Some(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{MemoryCache, WriteCache};
    use crate::parsers::Span;
    use crate::registries::VersionInfo;
    use chrono::Duration;
    use hashbrown::HashMap;

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

    fn format_release_age(released_at: DateTime<Utc>) -> String {
        fmt_release_age(released_at).to_string()
    }

    #[test]
    fn test_format_release_age_minutes() {
        let now = Utc::now();
        let released = now - Duration::minutes(30);
        let age = format_release_age(released);
        assert_eq!(age, "30 mins ago");
    }

    #[test]
    fn test_format_release_age_hours() {
        let now = Utc::now();
        let released = now - Duration::hours(5);
        let age = format_release_age(released);
        assert_eq!(age, "5 hours ago");
    }

    #[test]
    fn test_format_release_age_yesterday() {
        let now = Utc::now();
        let released = now - Duration::days(1);
        let age = format_release_age(released);
        assert_eq!(age, "yesterday");
    }

    #[test]
    fn test_format_release_age_days() {
        let now = Utc::now();
        let released = now - Duration::days(5);
        let age = format_release_age(released);
        assert_eq!(age, "5 days ago");
    }

    #[test]
    fn test_format_release_age_weeks() {
        let now = Utc::now();
        let released = now - Duration::days(14);
        let age = format_release_age(released);
        assert_eq!(age, "2 weeks ago");
    }

    #[test]
    fn test_format_release_age_months() {
        let now = Utc::now();
        let released = now - Duration::days(60);
        let age = format_release_age(released);
        assert_eq!(age, "2 months ago");
    }

    #[test]
    fn test_format_release_age_years() {
        let now = Utc::now();
        let released = now - Duration::days(400);
        let age = format_release_age(released);
        assert_eq!(age, "1 year ago");
    }

    #[test]
    fn test_format_release_age_just_now() {
        let now = Utc::now();
        let age = format_release_age(now);
        assert_eq!(age, "just now");
    }

    #[test]
    fn test_format_release_age_future() {
        // Simulate clock skew: release date 5 hours in the future
        let future = Utc::now() + Duration::hours(5);
        assert_eq!(format_release_age(future), "just now");

        // Also test small future offsets
        let near_future = Utc::now() + Duration::minutes(10);
        assert_eq!(format_release_age(near_future), "just now");
    }

    #[tokio::test]
    async fn test_get_completions() {
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:serde".to_string(),
                VersionInfo {
                    latest: Some("1.0.200".to_string()),
                    versions: vec![
                        "1.0.200".to_string(),
                        "1.0.199".to_string(),
                        "1.0.198".to_string(),
                    ],
                    ..Default::default()
                },
            )
            .await;

        let deps = vec![create_test_dependency("serde", "1.0.0", 5)];
        // Position inside the version field
        let position = Position {
            line: 5,
            character: 13, // Within version_start to version_end
        };

        let completions =
            get_completions(&deps, position, &cache, |name| format!("test:{name}")).await;

        assert!(completions.is_some());
        let items = completions.unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].label, "1.0.200");
        assert_eq!(items[1].label, "1.0.199");
    }

    #[tokio::test]
    async fn test_get_completions_with_release_dates() {
        let cache = MemoryCache::new();
        let now = Utc::now();
        let mut release_dates = HashMap::new();
        release_dates.insert("1.0.200".to_string(), now - Duration::days(2));
        release_dates.insert("1.0.199".to_string(), now - Duration::days(10));

        cache
            .insert(
                "test:serde".to_string(),
                VersionInfo {
                    latest: Some("1.0.200".to_string()),
                    versions: vec![
                        "1.0.200".to_string(),
                        "1.0.199".to_string(),
                        "1.0.198".to_string(),
                    ],
                    release_dates,
                    ..Default::default()
                },
            )
            .await;

        let deps = vec![create_test_dependency("serde", "1.0.0", 5)];
        let position = Position {
            line: 5,
            character: 13,
        };

        let completions =
            get_completions(&deps, position, &cache, |name| format!("test:{name}")).await;

        assert!(completions.is_some());
        let items = completions.unwrap();
        assert_eq!(items.len(), 3);

        // First item should have [Latest] and release date
        assert!(items[0].detail.as_ref().unwrap().contains("[Latest]"));
        assert!(items[0].detail.as_ref().unwrap().contains("2 days ago"));

        // Second item should have release date but not [Latest]
        assert!(!items[1].detail.as_ref().unwrap().contains("[Latest]"));
        assert!(items[1].detail.as_ref().unwrap().contains("1 week ago"));

        // Third item has no release date
        assert!(!items[2].detail.as_ref().unwrap().contains("[Latest]"));
        assert_eq!(items[2].detail.as_ref().unwrap(), "Version 1.0.198");
    }

    #[tokio::test]
    async fn test_no_completions_outside_version() {
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:serde".to_string(),
                VersionInfo {
                    latest: Some("1.0.200".to_string()),
                    versions: vec!["1.0.200".to_string()],
                    ..Default::default()
                },
            )
            .await;

        let deps = vec![create_test_dependency("serde", "1.0.0", 5)];
        // Position outside the version field
        let position = Position {
            line: 5,
            character: 0, // At the start, not in version
        };

        let completions =
            get_completions(&deps, position, &cache, |name| format!("test:{name}")).await;

        assert!(completions.is_none());
    }

    #[tokio::test]
    async fn test_no_completions_wrong_line() {
        let cache = MemoryCache::new();
        cache
            .insert(
                "test:serde".to_string(),
                VersionInfo {
                    latest: Some("1.0.200".to_string()),
                    versions: vec!["1.0.200".to_string()],
                    ..Default::default()
                },
            )
            .await;

        let deps = vec![create_test_dependency("serde", "1.0.0", 5)];
        let position = Position {
            line: 10, // Wrong line
            character: 13,
        };

        let completions =
            get_completions(&deps, position, &cache, |name| format!("test:{name}")).await;

        assert!(completions.is_none());
    }

    #[tokio::test]
    async fn test_no_completions_no_cache() {
        let cache = MemoryCache::new();
        let deps = vec![create_test_dependency("unknown", "1.0.0", 5)];
        let position = Position {
            line: 5,
            character: 13,
        };

        let completions =
            get_completions(&deps, position, &cache, |name| format!("test:{name}")).await;

        assert!(completions.is_none());
    }

    #[test]
    fn test_format_release_age_1_hour() {
        let now = Utc::now();
        let released = now - Duration::hours(1);
        let age = format_release_age(released);
        assert_eq!(age, "1 hour ago");
    }

    #[test]
    fn test_format_release_age_1_minute() {
        let now = Utc::now();
        let released = now - Duration::minutes(1);
        let age = format_release_age(released);
        assert_eq!(age, "1 min ago");
    }

    #[test]
    fn test_format_release_age_1_week() {
        let now = Utc::now();
        let released = now - Duration::days(7);
        let age = format_release_age(released);
        assert_eq!(age, "1 week ago");
    }

    #[test]
    fn test_format_release_age_1_month() {
        let now = Utc::now();
        let released = now - Duration::days(30);
        let age = format_release_age(released);
        assert_eq!(age, "1 month ago");
    }

    #[test]
    fn test_format_release_age_future_date() {
        let now = Utc::now();
        let released = now + Duration::days(5);
        let age = format_release_age(released);
        assert_eq!(age, "just now");
    }

    #[tokio::test]
    async fn test_completions_many_versions() {
        let cache = MemoryCache::new();
        let versions: Vec<String> = (0..20).map(|i| format!("1.0.{}", 20 - i)).collect();
        cache
            .insert(
                "test:serde".to_string(),
                VersionInfo {
                    latest: Some("1.0.20".to_string()),
                    versions,
                    ..Default::default()
                },
            )
            .await;

        let deps = vec![create_test_dependency("serde", "1.0.0", 5)];
        let position = Position {
            line: 5,
            character: 13,
        };

        let completions =
            get_completions(&deps, position, &cache, |name| format!("test:{name}")).await;

        assert!(completions.is_some());
        let items = completions.unwrap();
        assert_eq!(items.len(), 10);
    }
}
