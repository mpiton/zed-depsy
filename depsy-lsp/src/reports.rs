//! Vulnerability report generation
//!
//! This module handles the generation of vulnerability reports
//! in various formats (JSON, Markdown, HTML).

use core::fmt;

use serde::{Deserialize, Serialize};
use tower_lsp::lsp_types::Url;

use crate::utils::html_escape;

/// Summary of vulnerabilities grouped by severity level.
///
/// Used to provide an overview of the vulnerability scan results.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VulnerabilitySummary {
    /// Total number of vulnerabilities found.
    pub total: u32,
    /// Number of critical severity vulnerabilities.
    pub critical: u32,
    /// Number of high severity vulnerabilities.
    pub high: u32,
    /// Number of medium severity vulnerabilities.
    pub medium: u32,
    /// Number of low severity vulnerabilities.
    pub low: u32,
}

/// A single vulnerability entry in a report.
///
/// Contains all relevant information about a vulnerability affecting a package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityReportEntry {
    /// Name of the affected package.
    pub package: String,
    /// Version of the affected package.
    pub version: String,
    /// Vulnerability identifier (e.g., CVE-2021-1234, GHSA-xxxx).
    pub id: String,
    /// Severity level (critical, high, medium, low).
    pub severity: String,
    /// Human-readable description of the vulnerability.
    pub description: String,
    /// URL for more information about the vulnerability.
    pub url: Option<String>,
}

/// A transitive vulnerability report entry — same shape as
/// [`VulnerabilityReportEntry`] plus the direct dependency name that pulls
/// this vulnerability in via the lockfile graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitiveVulnerabilityReportEntry {
    /// Name of the affected transitive package.
    pub package: String,
    /// Resolved version of the affected transitive package.
    pub version: String,
    /// Vulnerability identifier (e.g., CVE-2021-1234, GHSA-xxxx).
    pub id: String,
    /// Severity level (critical, high, medium, low).
    pub severity: String,
    /// Human-readable description of the vulnerability.
    pub description: String,
    /// URL for more information about the vulnerability.
    pub url: Option<String>,
    /// Direct dependency (in the manifest) that introduces this transitive.
    pub via_direct: String,
}

/// Returns an <code>[fmt::Display] + [fmt::Debug]</code> implementation
/// which produces a Markdown-formatted vulnerability report.
///
/// Creates a human-readable report with a summary table and detailed
/// vulnerability entries grouped by package.
#[must_use = "returns a type implementing Display and Debug, which does not have any effects unless they are used"]
pub fn fmt_markdown_report(
    uri: &Url,
    summary: &VulnerabilitySummary,
    vulnerabilities: &[VulnerabilityReportEntry],
) -> impl fmt::Display + fmt::Debug {
    fmt::from_fn(move |f| {
        writeln!(
            f,
            "# Vulnerability Report\n\
             \n\
             **File**: {}",
            uri.path()
        )?;
        writeln!(f, "**Date**: {}\n", chrono::Local::now().format("%Y-%m-%d"))?;
        writeln!(
            f,
            "## Summary\n\
             \n\
             | Severity | Count |\n\
             |----------|-------|\n\
             | ⚠ Critical | {c} |\n\
             | ▲ High | {h} |\n\
             | ● Medium | {m} |\n\
             | ○ Low | {l} |\n\
             | **Total** | **{t}** |\n",
            c = summary.critical,
            h = summary.high,
            m = summary.medium,
            l = summary.low,
            t = summary.total,
        )?;

        if !vulnerabilities.is_empty() {
            writeln!(f, "## Vulnerabilities\n")?;

            let mut current_package = String::new();
            let mut current_version = String::new();
            for VulnerabilityReportEntry {
                package,
                version,
                id,
                severity,
                description,
                url,
            } in vulnerabilities
            {
                if *package != current_package || *version != current_version {
                    current_package = package.clone();
                    current_version = version.clone();
                    writeln!(f, "### {package}@{version}\n")?;
                }

                let severity_icon = match severity.as_str() {
                    "critical" => "⚠",
                    "high" => "▲",
                    "medium" => "●",
                    _ => "○",
                };

                let severity = severity.to_uppercase();
                if let Some(url) = url.as_deref() {
                    writeln!(
                        f,
                        "- **[{id}]({url})** ({severity_icon} {severity}): {description}",
                    )?;
                } else {
                    writeln!(f, "- **{id}** ({severity_icon} {severity}): {description}")?;
                }
            }
        } else {
            writeln!(
                f,
                "## No vulnerabilities found\n\
                 ✅ All dependencies are free of known security vulnerabilities."
            )?;
        }

        Ok(())
    })
}

/// Returns an <code>[fmt::Display] + [fmt::Debug]</code> implementation
/// which produces a self-contained HTML vulnerability report with inline CSS.
///
/// The rendering mirrors the CLI markdown format: a summary table, then two
/// optional sections for Direct and Transitive dependencies. When both are
/// empty a success block is rendered instead.
///
/// All interpolated values are HTML-escaped via [`crate::utils::html_escape`].
/// Advisory URLs are emitted inside `<a href>` only when they start with
/// `http://` or `https://`; other schemes render the id as plain text.
#[must_use = "returns a type implementing Display and Debug, which does not have any effects unless they are used"]
pub fn fmt_html_report(
    file: &str,
    summary: &VulnerabilitySummary,
    direct: &[VulnerabilityReportEntry],
    transitive: &[TransitiveVulnerabilityReportEntry],
) -> impl fmt::Display + fmt::Debug {
    let file_e = html_escape(file);
    let date = chrono::Local::now().format("%Y-%m-%d").to_string();

    fmt::from_fn(move |f| {
        writeln!(f, "<!DOCTYPE html>")?;
        writeln!(f, "<html lang=\"en\">")?;
        writeln!(f, "<head>")?;
        writeln!(f, "  <meta charset=\"utf-8\">")?;
        writeln!(
            f,
            "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        )?;
        writeln!(f, "  <title>Vulnerability Report — {file_e}</title>")?;
        writeln!(f, "  <style>{HTML_REPORT_STYLE}</style>")?;
        writeln!(f, "</head>")?;
        writeln!(f, "<body>")?;
        writeln!(f, "  <h1>Vulnerability Report</h1>")?;
        writeln!(
            f,
            "  <p class=\"meta\"><strong>File:</strong> {file_e}<br><strong>Date:</strong> {date}</p>"
        )?;

        writeln!(f, "  <h2>Summary</h2>")?;
        writeln!(f, "  <table class=\"summary\">")?;
        writeln!(
            f,
            "    <thead><tr><th>Severity</th><th>Count</th></tr></thead>"
        )?;
        writeln!(f, "    <tbody>")?;
        writeln!(
            f,
            "      <tr class=\"critical\"><td>Critical</td><td>{}</td></tr>",
            summary.critical
        )?;
        writeln!(
            f,
            "      <tr class=\"high\"><td>High</td><td>{}</td></tr>",
            summary.high
        )?;
        writeln!(
            f,
            "      <tr class=\"medium\"><td>Medium</td><td>{}</td></tr>",
            summary.medium
        )?;
        writeln!(
            f,
            "      <tr class=\"low\"><td>Low</td><td>{}</td></tr>",
            summary.low
        )?;
        writeln!(
            f,
            "      <tr class=\"total\"><td><strong>Total</strong></td><td><strong>{}</strong></td></tr>",
            summary.total
        )?;
        writeln!(f, "    </tbody>")?;
        writeln!(f, "  </table>")?;

        if direct.is_empty() && transitive.is_empty() {
            writeln!(f, "  <section class=\"no-vulns\">")?;
            writeln!(f, "    <h2>No vulnerabilities found</h2>")?;
            writeln!(
                f,
                "    <p>All dependencies are free of known security vulnerabilities.</p>"
            )?;
            writeln!(f, "  </section>")?;
        } else {
            if !direct.is_empty() {
                writeln!(f, "  <h2>Direct dependencies ({})</h2>", direct.len())?;
                for entry in direct {
                    write_direct_entry(f, entry)?;
                }
            }
            if !transitive.is_empty() {
                writeln!(
                    f,
                    "  <h2>Transitive dependencies ({})</h2>",
                    transitive.len()
                )?;
                for entry in transitive {
                    write_transitive_entry(f, entry)?;
                }
            }
        }

        writeln!(f, "</body>")?;
        writeln!(f, "</html>")?;
        Ok(())
    })
}

fn severity_class(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        _ => "low",
    }
}

fn write_direct_entry(f: &mut fmt::Formatter<'_>, entry: &VulnerabilityReportEntry) -> fmt::Result {
    let sev_class = severity_class(&entry.severity);
    let pkg = html_escape(&entry.package);
    let ver = html_escape(&entry.version);
    let id = html_escape(&entry.id);
    let sev = html_escape(&entry.severity);
    let desc = html_escape(&entry.description);

    writeln!(f, "  <section class=\"vuln {sev_class}\">")?;
    writeln!(f, "    <h3>{pkg}@{ver}</h3>")?;
    write!(f, "    <p>")?;
    write_id_with_optional_link(f, entry.url.as_deref(), &id)?;
    write!(f, " <span class=\"sev\">{sev}</span>: {desc}")?;
    writeln!(f, "</p>")?;
    writeln!(f, "  </section>")
}

fn write_transitive_entry(
    f: &mut fmt::Formatter<'_>,
    entry: &TransitiveVulnerabilityReportEntry,
) -> fmt::Result {
    let sev_class = severity_class(&entry.severity);
    let pkg = html_escape(&entry.package);
    let ver = html_escape(&entry.version);
    let id = html_escape(&entry.id);
    let sev = html_escape(&entry.severity);
    let desc = html_escape(&entry.description);
    let via = html_escape(&entry.via_direct);

    writeln!(f, "  <section class=\"vuln {sev_class}\">")?;
    writeln!(f, "    <h3>{pkg}@{ver} — via <code>{via}</code></h3>")?;
    write!(f, "    <p>")?;
    write_id_with_optional_link(f, entry.url.as_deref(), &id)?;
    write!(f, " <span class=\"sev\">{sev}</span>: {desc}")?;
    writeln!(f, "</p>")?;
    writeln!(f, "  </section>")
}

fn write_id_with_optional_link(
    f: &mut fmt::Formatter<'_>,
    url: Option<&str>,
    id_escaped: &str,
) -> fmt::Result {
    match url {
        Some(u) if u.starts_with("http://") || u.starts_with("https://") => {
            let u_esc = html_escape(u);
            write!(f, "<a href=\"{u_esc}\">{id_escaped}</a>")
        }
        _ => write!(f, "{id_escaped}"),
    }
}

const HTML_REPORT_STYLE: &str = "body{font-family:-apple-system,system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#222}\
h1,h2,h3{font-weight:600}\
.meta{color:#555}\
table.summary{border-collapse:collapse;margin:1rem 0}\
table.summary th,table.summary td{border:1px solid #ddd;padding:.4rem .8rem;text-align:left}\
table.summary tr.critical td{background:#ffe0e0}\
table.summary tr.high td{background:#ffe8cc}\
table.summary tr.medium td{background:#fff5cc}\
table.summary tr.low td{background:#e8f0ff}\
section.vuln{border-left:4px solid #ddd;padding:.5rem 1rem;margin:.5rem 0;background:#fafafa}\
section.vuln.critical{border-left-color:#d33}\
section.vuln.high{border-left-color:#e80}\
section.vuln.medium{border-left-color:#cc0}\
section.vuln.low{border-left-color:#38c}\
.sev{font-weight:600;text-transform:uppercase;font-size:.85em}\
code{background:#eee;padding:.1em .3em;border-radius:3px}\
a{color:#06c}\
.no-vulns{background:#e8f7e8;padding:1rem;border-radius:6px}";

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_markdown_report(
        uri: &Url,
        summary: &VulnerabilitySummary,
        vulnerabilities: &[VulnerabilityReportEntry],
    ) -> String {
        fmt_markdown_report(uri, summary, vulnerabilities).to_string()
    }

    #[test]
    fn test_generate_markdown_report_with_vulnerabilities() {
        let uri = Url::parse("file:///project/Cargo.toml").unwrap();
        let summary = VulnerabilitySummary {
            total: 2,
            critical: 1,
            high: 1,
            medium: 0,
            low: 0,
        };
        let vulnerabilities = vec![
            VulnerabilityReportEntry {
                package: "serde".to_string(),
                version: "1.0.0".to_string(),
                id: "CVE-2021-1234".to_string(),
                severity: "critical".to_string(),
                description: "Critical vulnerability".to_string(),
                url: Some("https://example.com/cve".to_string()),
            },
            VulnerabilityReportEntry {
                package: "tokio".to_string(),
                version: "1.0.0".to_string(),
                id: "CVE-2021-5678".to_string(),
                severity: "high".to_string(),
                description: "High vulnerability".to_string(),
                url: None,
            },
        ];

        let report = generate_markdown_report(&uri, &summary, &vulnerabilities);

        assert!(report.contains("# Vulnerability Report"));
        assert!(report.contains("**File**: /project/Cargo.toml"));
        assert!(report.contains("| ⚠ Critical | 1 |"));
        assert!(report.contains("| ▲ High | 1 |"));
        assert!(report.contains("### serde@1.0.0"));
        assert!(report.contains("### tokio@1.0.0"));
        assert!(report.contains("CVE-2021-1234"));
        assert!(report.contains("CVE-2021-5678"));
    }

    #[test]
    fn test_generate_markdown_report_same_package_different_versions() {
        let uri = Url::parse("file:///project/Cargo.toml").unwrap();
        let summary = VulnerabilitySummary {
            total: 2,
            critical: 1,
            high: 1,
            medium: 0,
            low: 0,
        };
        let vulnerabilities = vec![
            VulnerabilityReportEntry {
                package: "serde".to_string(),
                version: "1.0.0".to_string(),
                id: "CVE-2021-1111".to_string(),
                severity: "critical".to_string(),
                description: "Old version vulnerability".to_string(),
                url: None,
            },
            VulnerabilityReportEntry {
                package: "serde".to_string(),
                version: "2.0.0".to_string(),
                id: "CVE-2021-2222".to_string(),
                severity: "high".to_string(),
                description: "New version vulnerability".to_string(),
                url: None,
            },
        ];

        let report = generate_markdown_report(&uri, &summary, &vulnerabilities);

        assert!(report.contains("### serde@1.0.0"));
        assert!(report.contains("### serde@2.0.0"));
        assert!(report.contains("CVE-2021-1111"));
        assert!(report.contains("CVE-2021-2222"));
    }

    #[test]
    fn test_generate_markdown_report_no_vulnerabilities() {
        let uri = Url::parse("file:///project/Cargo.toml").unwrap();
        let summary = VulnerabilitySummary::default();
        let vulnerabilities = vec![];

        let report = generate_markdown_report(&uri, &summary, &vulnerabilities);

        assert!(report.contains("# Vulnerability Report"));
        assert!(report.contains("## No vulnerabilities found"));
        assert!(report.contains("✅ All dependencies are free of known security vulnerabilities."));
    }

    fn generate_html_report(
        file: &str,
        summary: &VulnerabilitySummary,
        direct: &[VulnerabilityReportEntry],
        transitive: &[TransitiveVulnerabilityReportEntry],
    ) -> String {
        fmt_html_report(file, summary, direct, transitive).to_string()
    }

    #[test]
    fn test_fmt_html_report_no_vulnerabilities() {
        let summary = VulnerabilitySummary::default();
        let report = generate_html_report("/project/Cargo.toml", &summary, &[], &[]);

        assert!(report.starts_with("<!DOCTYPE html>"));
        assert!(report.contains("<title>Vulnerability Report"));
        assert!(report.contains("<h1>Vulnerability Report</h1>"));
        assert!(report.contains("<strong>File:</strong> /project/Cargo.toml"));
        assert!(report.contains("No vulnerabilities found"));
        assert!(!report.contains("<h2>Direct dependencies"));
        assert!(!report.contains("<h2>Transitive dependencies"));
        assert!(report.trim_end().ends_with("</html>"));
    }

    #[test]
    fn test_fmt_html_report_with_vulnerabilities() {
        let summary = VulnerabilitySummary {
            total: 2,
            critical: 1,
            high: 1,
            medium: 0,
            low: 0,
        };
        let direct = vec![VulnerabilityReportEntry {
            package: "serde".to_string(),
            version: "1.0.0".to_string(),
            id: "CVE-2021-1234".to_string(),
            severity: "critical".to_string(),
            description: "Critical vulnerability".to_string(),
            url: Some("https://example.com/cve".to_string()),
        }];
        let transitive = vec![TransitiveVulnerabilityReportEntry {
            package: "scheduler".to_string(),
            version: "0.20.0".to_string(),
            id: "CVE-2021-5678".to_string(),
            severity: "high".to_string(),
            description: "High vulnerability".to_string(),
            url: None,
            via_direct: "react".to_string(),
        }];

        let report = generate_html_report("/project/package.json", &summary, &direct, &transitive);

        assert!(report.contains("<h2>Direct dependencies (1)</h2>"));
        assert!(report.contains("<h2>Transitive dependencies (1)</h2>"));
        assert!(report.contains("<section class=\"vuln critical\">"));
        assert!(report.contains("<h3>serde@1.0.0</h3>"));
        assert!(report.contains("<a href=\"https://example.com/cve\">CVE-2021-1234</a>"));
        assert!(report.contains("<span class=\"sev\">critical</span>"));
        assert!(report.contains("<section class=\"vuln high\">"));
        assert!(report.contains("<h3>scheduler@0.20.0 — via <code>react</code></h3>"));
        assert!(report.contains("CVE-2021-5678"));
        assert!(!report.contains("href=\"CVE-2021-5678"));
        assert!(report.contains("<tr class=\"critical\"><td>Critical</td><td>1</td></tr>"));
        assert!(report.contains("<tr class=\"high\"><td>High</td><td>1</td></tr>"));
    }

    #[test]
    fn test_fmt_html_report_escapes_hostile_content() {
        let summary = VulnerabilitySummary {
            total: 1,
            critical: 1,
            high: 0,
            medium: 0,
            low: 0,
        };
        let direct = vec![VulnerabilityReportEntry {
            package: "pkg<script>".to_string(),
            version: "1.0".to_string(),
            id: "CVE-XSS-1".to_string(),
            severity: "critical".to_string(),
            description: "<script>alert('x')</script>".to_string(),
            url: Some("https://example.com/\"onmouseover=\"alert(1)".to_string()),
        }];

        let report = generate_html_report("/project/<a>.toml", &summary, &direct, &[]);

        assert!(
            !report.contains("<script>"),
            "expected <script> to be escaped, got:\n{report}"
        );
        assert!(report.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"));
        assert!(report.contains("pkg&lt;script&gt;"));
        assert!(report.contains("/project/&lt;a&gt;.toml"));
        assert!(!report.contains("\"onmouseover"));
        assert!(report.contains("&quot;onmouseover"));
    }

    #[test]
    fn test_fmt_html_report_rejects_non_http_url() {
        let summary = VulnerabilitySummary {
            total: 1,
            critical: 1,
            high: 0,
            medium: 0,
            low: 0,
        };
        let direct = vec![VulnerabilityReportEntry {
            package: "pkg".to_string(),
            version: "1.0".to_string(),
            id: "CVE-EVIL".to_string(),
            severity: "critical".to_string(),
            description: "desc".to_string(),
            url: Some("javascript:alert(1)".to_string()),
        }];

        let report = generate_html_report("/project/Cargo.toml", &summary, &direct, &[]);

        assert!(!report.contains("href=\"javascript"));
        assert!(!report.contains("<a href"));
        assert!(report.contains("CVE-EVIL"));
    }
}
