//! # Maven Central Registry Client
//!
//! Fetches version and metadata information for Java packages from
//! [Maven Central](https://repo1.maven.org/maven2) (or a configured mirror).
//!
//! ## Strategy
//!
//! 1. `GET {base_url}/{groupPath}/{artifactId}/maven-metadata.xml` → version list.
//! 2. Best-effort: `GET {base_url}/{groupPath}/{artifactId}/{latest}/{artifactId}-{latest}.pom`
//!    to enrich `VersionInfo` with description, homepage, repository, and license.
//!
//! The second request is non-blocking: on failure the registry returns a partial
//! `VersionInfo` rather than an error.
//!
//! ## Coordinates
//!
//! `package_name` uses the Maven convention `groupId:artifactId` (e.g.
//! `org.slf4j:slf4j-api`). The `groupId` is converted to a path by replacing
//! `.` with `/`.

use std::sync::Arc;

use quick_xml::events::Event;
use quick_xml::reader::Reader;
use reqwest::Client;

use crate::config::MavenRegistryConfig;

use super::{Registry, VersionInfo};

/// Client for Maven Central (or a compatible Maven repository mirror).
pub struct MavenCentralRegistry {
    client: Arc<Client>,
    base_url: String,
}

impl MavenCentralRegistry {
    pub fn with_client(client: Arc<Client>) -> Self {
        Self {
            client,
            base_url: "https://repo1.maven.org/maven2".to_string(),
        }
    }

    pub fn with_client_and_config(client: Arc<Client>, config: &MavenRegistryConfig) -> Self {
        let trimmed = config.url.trim_end_matches('/').to_string();
        Self {
            client,
            base_url: trimmed,
        }
    }

    fn coord_path(package_name: &str) -> anyhow::Result<(String, String)> {
        let (group, artifact) = package_name.split_once(':').ok_or_else(|| {
            anyhow::anyhow!(
                "Invalid Maven coordinate '{package_name}' (expected 'groupId:artifactId')"
            )
        })?;
        if group.is_empty() || artifact.is_empty() {
            anyhow::bail!(
                "Invalid Maven coordinate '{package_name}' (groupId or artifactId empty)"
            );
        }
        let group_path = group.replace('.', "/");
        Ok((group_path, artifact.to_string()))
    }
}

impl Registry for MavenCentralRegistry {
    async fn get_version_info(&self, package_name: &str) -> anyhow::Result<VersionInfo> {
        let (group_path, artifact) = Self::coord_path(package_name)?;

        // Step 1: maven-metadata.xml
        let base = &self.base_url;
        let metadata_url = format!("{base}/{group_path}/{artifact}/maven-metadata.xml");
        let resp = self.client.get(&metadata_url).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "Maven metadata fetch for '{package_name}' failed: HTTP {}",
                resp.status()
            );
        }
        let metadata_body = resp.text().await?;
        let (latest, latest_release, versions) = parse_metadata_xml(&metadata_body)
            .ok_or_else(|| anyhow::anyhow!("Invalid Maven metadata XML for '{package_name}'"))?;

        // Prefer <release> (Maven guarantees a stable release), then fall back to
        // the highest version that is not a prerelease. `<latest>` is intentionally
        // NOT used as a stable fallback because it tracks the most recently published
        // artifact — frequently a SNAPSHOT or milestone.
        let latest_stable =
            latest_release.or_else(|| versions.iter().find(|v| !is_prerelease(v)).cloned());
        let latest_prerelease = versions.iter().find(|v| is_prerelease(v)).cloned();
        // `latest` is accepted as-is; we only use it if it differs from our picks.
        let _ = latest;

        // Step 2: best-effort POM fetch for metadata (description, license, ...)
        let (description, homepage, repository, license) = match &latest_stable {
            Some(v) => {
                let pom_url = format!("{base}/{group_path}/{artifact}/{v}/{artifact}-{v}.pom");
                match self.client.get(&pom_url).send().await {
                    Ok(r) if r.status().is_success() => match r.text().await {
                        Ok(body) => parse_pom_metadata(&body),
                        Err(e) => {
                            tracing::debug!(
                                "Maven POM text read failed for {package_name}@{v}: {e}"
                            );
                            (None, None, None, None)
                        }
                    },
                    Ok(r) => {
                        tracing::debug!(
                            "Maven POM fetch for {package_name}@{v} returned HTTP {}",
                            r.status()
                        );
                        (None, None, None, None)
                    }
                    Err(e) => {
                        tracing::debug!("Maven POM fetch for {package_name}@{v} failed: {e}");
                        (None, None, None, None)
                    }
                }
            }
            None => (None, None, None, None),
        };

        Ok(VersionInfo {
            latest: latest_stable,
            latest_prerelease,
            versions,
            description,
            homepage,
            repository,
            license,
            vulnerabilities: vec![],
            deprecated: false,
            yanked: false,
            yanked_versions: vec![],
            release_dates: hashbrown::HashMap::new(),
            transitive_vulnerabilities: vec![],
        })
    }

    fn http_client(&self) -> Arc<Client> {
        self.client.clone()
    }
}

/// Parse `maven-metadata.xml` → (latest, release, versions[] in descending order).
/// `versions` preserves document order reversed (newest first as Maven writes them last).
pub(crate) fn parse_metadata_xml(
    content: &str,
) -> Option<(Option<String>, Option<String>, Vec<String>)> {
    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);

    let mut latest: Option<String> = None;
    let mut release: Option<String> = None;
    let mut versions: Vec<String> = Vec::new();

    let mut stack: Vec<Vec<u8>> = Vec::new();

    loop {
        match reader.read_event() {
            Err(_) => return None,
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => stack.push(e.name().as_ref().to_vec()),
            Ok(Event::End(_)) => {
                stack.pop();
            }
            Ok(Event::Text(e)) => {
                let text = match e.decode() {
                    Ok(s) => s.into_owned(),
                    Err(_) => continue,
                };
                // Path checks: metadata > versioning > latest | release
                // Path: metadata > versioning > versions > version
                let len = stack.len();
                if len >= 3 && stack[len - 3] == b"metadata" && stack[len - 2] == b"versioning" {
                    match stack[len - 1].as_slice() {
                        b"latest" => latest = Some(text),
                        b"release" => release = Some(text),
                        _ => {}
                    }
                } else if len >= 4
                    && stack[len - 4] == b"metadata"
                    && stack[len - 3] == b"versioning"
                    && stack[len - 2] == b"versions"
                    && stack[len - 1] == b"version"
                {
                    versions.push(text);
                }
            }
            _ => {}
        }
    }

    // Newest-first ordering: Maven writes versions in ascending order.
    versions.reverse();

    Some((latest, release, versions))
}

/// Parse a minimal subset of a pom.xml to extract presentation metadata.
pub(crate) fn parse_pom_metadata(
    content: &str,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);

    let mut description: Option<String> = None;
    let mut homepage: Option<String> = None;
    let mut repository: Option<String> = None;
    let mut licenses: Vec<String> = Vec::new();

    let mut stack: Vec<Vec<u8>> = Vec::new();

    loop {
        match reader.read_event() {
            Err(_) => break,
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => stack.push(e.name().as_ref().to_vec()),
            Ok(Event::End(_)) => {
                stack.pop();
            }
            Ok(Event::Text(e)) => {
                let text = match e.decode() {
                    Ok(s) => s.into_owned(),
                    Err(_) => continue,
                };
                let len = stack.len();
                // project > description
                if len == 2 && stack[0] == b"project" && stack[1] == b"description" {
                    description = Some(text);
                    continue;
                }
                // project > url
                if len == 2 && stack[0] == b"project" && stack[1] == b"url" {
                    homepage = Some(text);
                    continue;
                }
                // project > scm > url
                if len == 3 && stack[0] == b"project" && stack[1] == b"scm" && stack[2] == b"url" {
                    repository = Some(text);
                    continue;
                }
                // project > licenses > license > name
                if len == 4
                    && stack[0] == b"project"
                    && stack[1] == b"licenses"
                    && stack[2] == b"license"
                    && stack[3] == b"name"
                {
                    licenses.push(text);
                }
            }
            _ => {}
        }
    }

    let license = if licenses.is_empty() {
        None
    } else {
        Some(licenses.join(", "))
    };
    (description, homepage, repository, license)
}

/// Classify a Maven version string as a prerelease / snapshot.
///
/// Recognizes the conventional Maven qualifiers written with either a `-` or `.`
/// separator: `-SNAPSHOT`, `-alpha`, `-beta`, `-rc`, `-milestone`, and the
/// `M<digit>` milestone pattern with either separator (`5.3.0-M1`, `5.0.0.M1`).
/// The `m` check is deliberately narrow — it must be followed by a digit to
/// avoid false positives on versions like `1.0-metrics` or `2.4-mixed`.
fn is_prerelease(version: &str) -> bool {
    let v = version.to_ascii_lowercase();
    for qualifier in ["snapshot", "alpha", "beta", "rc", "milestone"] {
        if v.contains(&format!("-{qualifier}")) || v.contains(&format!(".{qualifier}")) {
            return true;
        }
    }
    // Maven milestone convention: `-M<digits>` or `.M<digits>` (e.g. `-M1`, `.M1`, `-M23`).
    for marker in ["-m", ".m"] {
        if let Some(idx) = v.find(marker) {
            let rest = &v[idx + marker.len()..];
            if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coord_path_ok() {
        let (g, a) = MavenCentralRegistry::coord_path("org.slf4j:slf4j-api").unwrap();
        assert_eq!(g, "org/slf4j");
        assert_eq!(a, "slf4j-api");
    }

    #[test]
    fn test_coord_path_invalid() {
        assert!(MavenCentralRegistry::coord_path("no-colon").is_err());
        assert!(MavenCentralRegistry::coord_path(":empty").is_err());
        assert!(MavenCentralRegistry::coord_path("empty:").is_err());
    }

    #[test]
    fn test_parse_metadata_xml_basic() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>org.slf4j</groupId>
  <artifactId>slf4j-api</artifactId>
  <versioning>
    <latest>2.0.9</latest>
    <release>2.0.9</release>
    <versions>
      <version>1.7.30</version>
      <version>2.0.0</version>
      <version>2.0.9</version>
    </versions>
  </versioning>
</metadata>
"#;
        let (latest, release, versions) = parse_metadata_xml(xml).expect("parse ok");
        assert_eq!(latest.as_deref(), Some("2.0.9"));
        assert_eq!(release.as_deref(), Some("2.0.9"));
        // Newest first
        assert_eq!(versions, vec!["2.0.9", "2.0.0", "1.7.30"]);
    }

    #[test]
    fn test_parse_pom_extracts_description_and_license() {
        let pom = r#"<?xml version="1.0"?>
<project>
    <description>Structured logging API</description>
    <url>https://example.com</url>
    <scm>
        <url>https://github.com/example/example</url>
    </scm>
    <licenses>
        <license>
            <name>Apache-2.0</name>
        </license>
    </licenses>
</project>
"#;
        let (description, homepage, repository, license) = parse_pom_metadata(pom);
        assert_eq!(description.as_deref(), Some("Structured logging API"));
        assert_eq!(homepage.as_deref(), Some("https://example.com"));
        assert_eq!(
            repository.as_deref(),
            Some("https://github.com/example/example")
        );
        assert_eq!(license.as_deref(), Some("Apache-2.0"));
    }

    #[test]
    fn test_parse_pom_missing_license_returns_none() {
        let pom = "<project><description>no license</description></project>";
        let (_description, _homepage, _repository, license) = parse_pom_metadata(pom);
        assert_eq!(license, None);
    }

    #[test]
    fn test_parse_pom_multiple_licenses_joined() {
        let pom = r#"<project>
    <licenses>
        <license><name>Apache-2.0</name></license>
        <license><name>MIT</name></license>
    </licenses>
</project>"#;
        let (_, _, _, license) = parse_pom_metadata(pom);
        assert_eq!(license.as_deref(), Some("Apache-2.0, MIT"));
    }

    #[test]
    fn test_is_prerelease() {
        assert!(is_prerelease("1.0-SNAPSHOT"));
        assert!(is_prerelease("1.0-alpha-1"));
        assert!(is_prerelease("2.0-rc1"));
        assert!(is_prerelease("5.3.0-M1"));
        assert!(is_prerelease("5.0.0.Alpha1"));
        assert!(is_prerelease("3.0.0.Beta2"));
        assert!(!is_prerelease("1.0.0"));
        assert!(!is_prerelease("2.5.1"));
        // `-m` alone (no digit) must NOT classify as milestone.
        assert!(!is_prerelease("1.0-metrics"));
        assert!(!is_prerelease("2.4-mixed"));
    }
}
