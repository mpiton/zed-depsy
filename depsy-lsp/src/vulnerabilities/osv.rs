//! OSV.dev API client for vulnerability data
//!
//! OSV (Open Source Vulnerabilities) provides a unified API for querying
//! vulnerability data across multiple ecosystems.

use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::VulnerabilityQuery;
use crate::registries::{Vulnerability, VulnerabilitySeverity};

const OSV_API_BASE: &str = "https://api.osv.dev/v1";
const RUSTSEC_ADVISORY_LOOKUP_CONCURRENCY: usize = 5;

/// Maximum length for an OSV advisory ID. Real RUSTSEC IDs are 16 characters
/// (`RUSTSEC-YYYY-NNNN`); 64 is generous head-room for related schemes.
const MAX_ADVISORY_ID_LEN: usize = 64;

/// Whitelist sanity check for advisory IDs returned by OSV.
///
/// `check_rustsec_unmaintained` interpolates the ID directly into a URL and
/// uses it as a cache key, so we constrain the alphabet up-front.
/// Accepts only ASCII alphanumerics and the `-` separator.
fn is_valid_advisory_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ADVISORY_ID_LEN
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Result of a vulnerability query
#[derive(Debug, Clone, Default)]
pub struct QueryResult {
    pub vulnerabilities: Vec<Vulnerability>,
    pub deprecated: bool,
}

/// OSV.dev API client
///
/// Holds two caches because positive and negative OSV results have different
/// freshness needs: a real RUSTSEC entry is stable for a long time (hours),
/// but a 404 might just mean OSV has not yet ingested a brand-new advisory,
/// so we cache it for a much shorter window controlled by
/// `AdvisoryCacheConfig::negative_ttl_secs`.
pub struct OsvClient {
    client: Arc<Client>,
    base_url: String,
    /// Cache used for `Found` advisory entries (long TTL).
    advisory_cache: Arc<dyn crate::cache::advisory::AdvisoryWriteCache>,
    /// Cache used for `NotFound` advisory entries (short TTL).
    negative_cache: Arc<dyn crate::cache::advisory::AdvisoryWriteCache>,
}

impl OsvClient {
    pub fn new() -> anyhow::Result<Self> {
        let null: Arc<dyn crate::cache::advisory::AdvisoryWriteCache> =
            Arc::new(crate::cache::advisory::NullAdvisoryCache);
        Self::new_with_caches(Arc::clone(&null), null)
    }

    /// Backwards-compatible constructor: uses the same cache for positive
    /// and negative entries. Prefer [`OsvClient::new_with_caches`] when the
    /// caller has separate positive/negative caches with different TTLs.
    pub fn new_with_cache(
        advisory_cache: Arc<dyn crate::cache::advisory::AdvisoryWriteCache>,
    ) -> anyhow::Result<Self> {
        Self::new_with_caches(Arc::clone(&advisory_cache), advisory_cache)
    }

    /// Build a client with explicit positive and negative caches.
    pub fn new_with_caches(
        positive_cache: Arc<dyn crate::cache::advisory::AdvisoryWriteCache>,
        negative_cache: Arc<dyn crate::cache::advisory::AdvisoryWriteCache>,
    ) -> anyhow::Result<Self> {
        let client = Client::builder()
            .user_agent("depsy-lsp (https://github.com/mathieu/zed-depsy)")
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            client: Arc::new(client),
            base_url: OSV_API_BASE.to_string(),
            advisory_cache: positive_cache,
            negative_cache,
        })
    }

    /// Infallible constructor that reuses an already-built `reqwest::Client`
    /// (typically the LSP's shared HTTP client created via
    /// `create_shared_client`). Avoids a second TLS/builder-init step that
    /// could fail or panic at runtime — the caller has proven `reqwest`
    /// works on this platform by virtue of holding a `Client` already.
    ///
    /// Note: drops the OSV-specific 30 s timeout customisation; the shared
    /// client's default timeout applies. OSV requests are short-lived in
    /// practice, so this is acceptable.
    pub fn with_shared_client_and_caches(
        client: Arc<Client>,
        positive_cache: Arc<dyn crate::cache::advisory::AdvisoryWriteCache>,
        negative_cache: Arc<dyn crate::cache::advisory::AdvisoryWriteCache>,
    ) -> Self {
        Self {
            client,
            base_url: OSV_API_BASE.to_string(),
            advisory_cache: positive_cache,
            negative_cache,
        }
    }

    /// Build a client pointing at a custom OSV endpoint (no advisory cache).
    ///
    /// Used at runtime by the standalone scanner (`OSV_ENDPOINT` env var) and
    /// by tests to point the client at a mock HTTP server. Returns
    /// `Err` if `reqwest` cannot build a `Client` (rare TLS/cert issue) —
    /// previously this fell back to `reqwest::Client::new()`, but that is
    /// itself `Client::builder().build().expect(...)` and panics under the
    /// same conditions, so the fallback was an illusion.
    pub fn with_endpoint(endpoint: String) -> anyhow::Result<Self> {
        let client = Client::builder().timeout(Duration::from_secs(30)).build()?;
        let null: Arc<dyn crate::cache::advisory::AdvisoryWriteCache> =
            Arc::new(crate::cache::advisory::NullAdvisoryCache);
        Ok(Self {
            base_url: endpoint,
            client: Arc::new(client),
            advisory_cache: Arc::clone(&null),
            negative_cache: null,
        })
    }

    /// Test-only constructor: explicit endpoint **and** advisory cache.
    ///
    /// Gated to `#[cfg(test)]` so production code paths cannot accidentally
    /// inject a `NullAdvisoryCache` here. Runtime callers that need cache
    /// injection should use [`OsvClient::new_with_cache`] instead.
    ///
    /// Reuses `advisory_cache` for both the positive and negative layers;
    /// tests that need to assert separate behaviour should use
    /// [`OsvClient::with_endpoint_and_caches`] instead.
    #[cfg(test)]
    pub fn with_endpoint_and_cache(
        endpoint: String,
        advisory_cache: Arc<dyn crate::cache::advisory::AdvisoryWriteCache>,
    ) -> Self {
        Self::with_endpoint_and_caches(endpoint, Arc::clone(&advisory_cache), advisory_cache)
    }

    /// Test-only constructor: explicit endpoint, positive cache, and
    /// negative cache. Mirrors [`OsvClient::new_with_caches`] but lets the
    /// caller pin the URL to a wiremock server.
    #[cfg(test)]
    pub fn with_endpoint_and_caches(
        endpoint: String,
        positive_cache: Arc<dyn crate::cache::advisory::AdvisoryWriteCache>,
        negative_cache: Arc<dyn crate::cache::advisory::AdvisoryWriteCache>,
    ) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self {
            base_url: endpoint,
            client: Arc::new(client),
            advisory_cache: positive_cache,
            negative_cache,
        }
    }

    /// Accessor used by integration tests to verify positive cache state.
    #[cfg(test)]
    pub fn advisory_cache(&self) -> &Arc<dyn crate::cache::advisory::AdvisoryWriteCache> {
        &self.advisory_cache
    }

    /// Accessor used by integration tests to verify negative cache state.
    #[cfg(test)]
    pub fn negative_cache(&self) -> &Arc<dyn crate::cache::advisory::AdvisoryWriteCache> {
        &self.negative_cache
    }

    fn convert_vulnerability(osv: &OsvVulnerability) -> Vulnerability {
        let id = osv
            .aliases
            .as_ref()
            .and_then(|a| a.iter().find(|id| id.starts_with("CVE-")))
            .cloned()
            .unwrap_or_else(|| osv.id.clone());

        let severity = osv
            .severity
            .as_ref()
            .and_then(|s| s.first())
            .map(|s| parse_cvss_severity(&s.score))
            .unwrap_or(VulnerabilitySeverity::Medium);

        let description = osv
            .summary
            .clone()
            .or_else(|| osv.details.clone())
            .unwrap_or_else(|| format!("Vulnerability {}", osv.id));

        let url = osv.references.as_ref().and_then(|refs| {
            refs.iter()
                .find(|r| r._ref_type == "ADVISORY" || r._ref_type == "WEB")
                .map(|r| r.url.clone())
        });

        Vulnerability {
            id,
            severity,
            description,
            url,
        }
    }
}

impl Default for OsvClient {
    fn default() -> Self {
        Self::new().expect("Failed to create OsvClient")
    }
}

fn parse_cvss_severity(score: &str) -> VulnerabilitySeverity {
    if let Ok(score) = score.parse::<f64>() {
        return match score {
            s if s >= 9.0 => VulnerabilitySeverity::Critical,
            s if s >= 7.0 => VulnerabilitySeverity::High,
            s if s >= 4.0 => VulnerabilitySeverity::Medium,
            _ => VulnerabilitySeverity::Low,
        };
    }

    if score.starts_with("CVSS:") {
        return VulnerabilitySeverity::Medium;
    }

    VulnerabilitySeverity::Medium
}

impl OsvClient {
    pub async fn query_batch(
        &self,
        queries: &[VulnerabilityQuery],
    ) -> anyhow::Result<Vec<QueryResult>> {
        if queries.is_empty() {
            return Ok(vec![]);
        }

        let request = OsvBatchRequest {
            queries: queries
                .iter()
                .map(|q| OsvQueryRequest {
                    package: OsvPackage {
                        name: q.package_name.clone(),
                        ecosystem: q.ecosystem.as_osv_str().to_string(),
                    },
                    version: Some(q.version.clone()),
                })
                .collect(),
        };

        let url = format!("{}/querybatch", self.base_url);
        let response = self.client.post(&url).json(&request).send().await?;

        if !response.status().is_success() {
            anyhow::bail!("OSV API batch error: {}", response.status());
        }

        let batch_response: OsvBatchResponse = response.json().await?;

        let mut results = Vec::new();

        for r in &batch_response.results {
            let vulnerabilities = r
                .vulns
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(Self::convert_vulnerability)
                .collect();

            let rustsec_ids: Vec<String> = r
                .vulns
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .filter(|v| v.id.starts_with("RUSTSEC-"))
                .map(|v| v.id.clone())
                .collect();

            let has_unmaintained = self.check_rustsec_unmaintained(&rustsec_ids).await;

            results.push(QueryResult {
                vulnerabilities,
                deprecated: has_unmaintained,
            });
        }

        Ok(results)
    }

    pub(crate) async fn check_rustsec_unmaintained(&self, ids: &[String]) -> bool {
        if ids.is_empty() {
            return false;
        }

        tracing::debug!(
            "Checking {} RUSTSEC advisories for unmaintained status",
            ids.len()
        );

        let positive_cache = Arc::clone(&self.advisory_cache);
        let negative_cache = Arc::clone(&self.negative_cache);
        let results: Vec<bool> = stream::iter(ids.iter().cloned())
            .map(|id| {
                let url = format!("{}/vulns/{id}", self.base_url);
                let client = Arc::clone(&self.client);
                let positive_cache = Arc::clone(&positive_cache);
                let negative_cache = Arc::clone(&negative_cache);

                async move {
                    if !is_valid_advisory_id(&id) {
                        tracing::warn!("Skipping advisory with unexpected ID format: {:?}", id);
                        return false;
                    }

                    // Positive cache wins over negative for `Found` entries.
                    // We deliberately do NOT short-circuit on `NotFound` from
                    // the positive cache: pre-split builds wrote 404s into
                    // the same SQLite layer with the long positive TTL, so a
                    // user upgrading would otherwise be stuck with 24-h-stale
                    // 404 rows that never get a chance to retry. Falling
                    // through lets the short-TTL negative cache handle the
                    // 404 path; if the network now returns 200, the
                    // subsequent `positive_cache.insert` (UPSERT) overwrites
                    // the stale row.
                    if let Some(cached) = positive_cache.get(&id).await
                        && let crate::cache::advisory::AdvisoryKind::Found { unmaintained, .. } =
                            cached.kind
                    {
                        return unmaintained;
                    }
                    if let Some(cached) = negative_cache.get(&id).await
                        && matches!(cached.kind, crate::cache::advisory::AdvisoryKind::NotFound)
                    {
                        return false;
                    }

                    let response = match client.get(&url).send().await {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("Failed to fetch advisory {}: {}", id, e);
                            return false;
                        }
                    };

                    if response.status().as_u16() == 404 {
                        // 404s land in the negative cache so they expire on
                        // the shorter `negative_ttl_secs` schedule.
                        negative_cache
                            .insert(crate::cache::advisory::CachedAdvisory {
                                id: id.clone(),
                                kind: crate::cache::advisory::AdvisoryKind::NotFound,
                                fetched_at: std::time::SystemTime::now(),
                            })
                            .await;
                        return false;
                    }

                    if !response.status().is_success() {
                        tracing::warn!(
                            "OSV /vulns/{} returned {}, not caching",
                            id,
                            response.status()
                        );
                        return false;
                    }

                    let details: Option<OsvVulnerabilityDetails> = match response.json().await {
                        Ok(d) => d,
                        Err(e) => {
                            tracing::warn!("Failed to parse advisory {}: {}", id, e);
                            return false;
                        }
                    };

                    let summary = details.as_ref().and_then(|v| v.summary.clone());

                    let is_unmaintained = details.as_ref().is_some_and(|v| {
                        let summary_match = v.summary.as_ref().is_some_and(|s| {
                            let lower = s.to_lowercase();
                            lower.contains("maintained") || lower.contains("deprecated")
                        });
                        let informational_match = v.affected.as_ref().is_some_and(|affected| {
                            affected.iter().any(|a| {
                                a.database_specific.as_ref().is_some_and(|db| {
                                    db.informational
                                        .as_ref()
                                        .is_some_and(|i| i == "unmaintained")
                                })
                            })
                        });
                        summary_match || informational_match
                    });

                    positive_cache
                        .insert(crate::cache::advisory::CachedAdvisory {
                            id: id.clone(),
                            kind: crate::cache::advisory::AdvisoryKind::Found {
                                summary,
                                unmaintained: is_unmaintained,
                            },
                            fetched_at: std::time::SystemTime::now(),
                        })
                        .await;

                    if is_unmaintained {
                        tracing::info!("Advisory {} indicates unmaintained package", id,);
                    }

                    is_unmaintained
                }
            })
            .buffer_unordered(RUSTSEC_ADVISORY_LOOKUP_CONCURRENCY)
            .collect()
            .await;

        results.into_iter().any(std::convert::identity)
    }
}

#[derive(Debug, Serialize)]
struct OsvQueryRequest {
    package: OsvPackage,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

#[derive(Debug, Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvQueryRequest>,
}

#[derive(Debug, Deserialize)]
struct OsvQueryResponse {
    vulns: Option<Vec<OsvVulnerability>>,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvQueryResponse>,
}

#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    id: String,
    summary: Option<String>,
    details: Option<String>,
    severity: Option<Vec<OsvSeverity>>,
    references: Option<Vec<OsvReference>>,
    aliases: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    _type: String,
    score: String,
}

#[derive(Debug, Deserialize)]
struct OsvReference {
    #[serde(rename = "type")]
    _ref_type: String,
    url: String,
}

#[derive(Debug, Deserialize)]
struct OsvVulnerabilityDetails {
    summary: Option<String>,
    affected: Option<Vec<OsvAffected>>,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    database_specific: Option<OsvDatabaseSpecific>,
}

#[derive(Debug, Deserialize)]
struct OsvDatabaseSpecific {
    informational: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use crate::vulnerabilities::Ecosystem;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_counting_osv_server(
        active_requests: Arc<AtomicUsize>,
        max_seen: Arc<AtomicUsize>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("counting test server should bind");
        let addr = listener
            .local_addr()
            .expect("counting test server should have local address");

        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _peer)) = listener.accept().await else {
                    break;
                };
                let active_requests = Arc::clone(&active_requests);
                let max_seen = Arc::clone(&max_seen);

                tokio::spawn(async move {
                    let current = active_requests.fetch_add(1, Ordering::SeqCst) + 1;
                    max_seen.fetch_max(current, Ordering::SeqCst);

                    let mut buffer = [0_u8; 2048];
                    let _ = socket.read(&mut buffer).await;

                    tokio::time::sleep(Duration::from_millis(50)).await;

                    let body =
                        r#"{"id":"RUSTSEC-2099-0001","summary":"ordinary advisory","affected":[]}"#;
                    let body_len = body.len();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {body_len}\r\nconnection: close\r\n\r\n{body}"
                    );
                    let _ = socket.write_all(response.as_bytes()).await;

                    active_requests.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });

        format!("http://{addr}")
    }

    #[test]
    fn is_valid_advisory_id_accepts_canonical_rustsec_format() {
        assert!(is_valid_advisory_id("RUSTSEC-2020-0036"));
        assert!(is_valid_advisory_id("RUSTSEC-2099-9999"));
        // Non-RUSTSEC alphanumerics + `-` are also fine; OSV exposes
        // GHSA / CVE / OSV IDs through the same endpoint.
        assert!(is_valid_advisory_id("GHSA-xxxx-yyyy-zzzz"));
        assert!(is_valid_advisory_id("CVE-2024-0001"));
    }

    #[test]
    fn is_valid_advisory_id_rejects_dangerous_characters() {
        // Empty string is rejected.
        assert!(!is_valid_advisory_id(""));
        // Path traversal attempts.
        assert!(!is_valid_advisory_id("../etc/passwd"));
        assert!(!is_valid_advisory_id("RUSTSEC/2020/0036"));
        // URL-injection attempts.
        assert!(!is_valid_advisory_id("RUSTSEC-2020-0036?evil=1"));
        assert!(!is_valid_advisory_id("RUSTSEC-2020-0036#frag"));
        // Whitespace and control chars.
        assert!(!is_valid_advisory_id("RUSTSEC-2020 0036"));
        assert!(!is_valid_advisory_id("RUSTSEC-2020-0036\n"));
        // Unicode is rejected — OSV IDs are ASCII.
        assert!(!is_valid_advisory_id("RUSTSEC-é"));
    }

    #[test]
    fn is_valid_advisory_id_rejects_oversized_ids() {
        let long = "A".repeat(65);
        assert!(!is_valid_advisory_id(&long));
        let just_at_limit = "A".repeat(64);
        assert!(is_valid_advisory_id(&just_at_limit));
    }

    #[test]
    fn test_parse_cvss_severity() {
        assert_eq!(parse_cvss_severity("9.8"), VulnerabilitySeverity::Critical);
        assert_eq!(parse_cvss_severity("9.0"), VulnerabilitySeverity::Critical);
        assert_eq!(parse_cvss_severity("7.5"), VulnerabilitySeverity::High);
        assert_eq!(parse_cvss_severity("5.0"), VulnerabilitySeverity::Medium);
        assert_eq!(parse_cvss_severity("3.0"), VulnerabilitySeverity::Low);
        assert_eq!(parse_cvss_severity("0.0"), VulnerabilitySeverity::Low);
        assert_eq!(
            parse_cvss_severity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            VulnerabilitySeverity::Medium
        );
    }

    #[test]
    fn test_ecosystem_osv_str() {
        assert_eq!(Ecosystem::CratesIo.as_osv_str(), "crates.io");
        assert_eq!(Ecosystem::Npm.as_osv_str(), "npm");
        assert_eq!(Ecosystem::PyPI.as_osv_str(), "PyPI");
        assert_eq!(Ecosystem::Go.as_osv_str(), "Go");
        assert_eq!(Ecosystem::Packagist.as_osv_str(), "Packagist");
        assert_eq!(Ecosystem::Pub.as_osv_str(), "Pub");
        assert_eq!(Ecosystem::NuGet.as_osv_str(), "NuGet");
    }

    #[test]
    fn test_convert_vulnerability() {
        let osv = OsvVulnerability {
            id: "GHSA-xxxx-xxxx-xxxx".to_string(),
            summary: Some("Test vulnerability".to_string()),
            details: None,
            severity: Some(vec![OsvSeverity {
                _type: "CVSS_V3".to_string(),
                score: "7.5".to_string(),
            }]),
            references: Some(vec![OsvReference {
                _ref_type: "ADVISORY".to_string(),
                url: "https://example.com/advisory".to_string(),
            }]),
            aliases: Some(vec!["CVE-2021-12345".to_string()]),
        };

        let vuln = OsvClient::convert_vulnerability(&osv);

        assert_eq!(vuln.id, "CVE-2021-12345");
        assert_eq!(vuln.severity, VulnerabilitySeverity::High);
        assert_eq!(vuln.description, "Test vulnerability");
        assert_eq!(vuln.url, Some("https://example.com/advisory".to_string()));
    }

    #[test]
    fn test_unmaintained_detection() {
        let rustsec_vuln = OsvVulnerability {
            id: "RUSTSEC-2025-0057".to_string(),
            summary: Some("fxhash - no longer maintained".to_string()),
            details: None,
            severity: None,
            references: None,
            aliases: None,
        };

        let is_unmaintained = rustsec_vuln.id.starts_with("RUSTSEC")
            && rustsec_vuln.summary.as_ref().is_some_and(|s| {
                s.to_lowercase().contains("maintained") || s.to_lowercase().contains("deprecated")
            });

        assert!(is_unmaintained);

        let normal_vuln = OsvVulnerability {
            id: "CVE-2024-1234".to_string(),
            summary: Some("Buffer overflow vulnerability".to_string()),
            details: None,
            severity: None,
            references: None,
            aliases: None,
        };

        let is_not_unmaintained = normal_vuln.id.starts_with("RUSTSEC")
            && normal_vuln.summary.as_ref().is_some_and(|s| {
                s.to_lowercase().contains("maintained") || s.to_lowercase().contains("deprecated")
            });

        assert!(!is_not_unmaintained);
    }

    #[tokio::test]
    async fn test_fxhash_deprecated_detection() {
        let client = OsvClient::new().unwrap();

        let query = VulnerabilityQuery {
            ecosystem: crate::vulnerabilities::Ecosystem::CratesIo,
            package_name: "fxhash".to_string(),
            version: "0.2.1".to_string(),
        };

        let results = client.query_batch(&[query]).await.unwrap();

        assert!(!results.is_empty());

        let result = &results[0];
        assert!(!result.vulnerabilities.is_empty());
        assert!(result.deprecated, "fxhash should be marked as deprecated");

        let vuln = &result.vulnerabilities[0];
        assert!(vuln.id.starts_with("RUSTSEC"));
    }

    #[tokio::test]
    async fn test_osv_client_with_endpoint_uses_custom_url() {
        let client = OsvClient::with_endpoint("http://127.0.0.1:1".to_string())
            .expect("with_endpoint builds in test");
        // Port 1 is not listening; a real query must error, proving the client
        // actually attempted to reach the custom URL (and not fallen back to
        // api.osv.dev).
        let query = VulnerabilityQuery {
            ecosystem: Ecosystem::CratesIo,
            package_name: "serde".to_string(),
            version: "1.0.0".to_string(),
        };
        let result = client.query_batch(&[query]).await;
        assert!(
            result.is_err(),
            "query to unreachable endpoint should error, got {result:?}"
        );
    }

    use crate::cache::advisory::{AdvisoryReadCache, AdvisoryWriteCache, NullAdvisoryCache};

    #[tokio::test]
    async fn with_endpoint_accepts_advisory_cache() {
        let cache: Arc<dyn AdvisoryWriteCache> = Arc::new(NullAdvisoryCache);
        let client =
            OsvClient::with_endpoint_and_cache("http://example.invalid".to_string(), cache);
        // Smoke-test: cache is reachable through the public accessor.
        assert!(
            client
                .advisory_cache()
                .get("RUSTSEC-2020-0036")
                .await
                .is_none()
        );
    }

    use std::time::SystemTime;

    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use crate::cache::advisory::{AdvisoryKind, CachedAdvisory, MemoryAdvisoryCache};

    fn sample_response_body() -> serde_json::Value {
        serde_json::json!({
            "summary": "test crate is unmaintained",
            "affected": [{
                "database_specific": {
                    "informational": "unmaintained"
                }
            }]
        })
    }

    #[tokio::test]
    async fn cache_hit_skips_http_for_known_advisory() {
        let server = MockServer::start().await;
        let counter = Arc::new(AtomicUsize::new(0));
        {
            let counter = Arc::clone(&counter);
            Mock::given(method("GET"))
                .and(path("/vulns/RUSTSEC-2020-0036"))
                .respond_with(move |_req: &wiremock::Request| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    ResponseTemplate::new(200).set_body_json(sample_response_body())
                })
                .mount(&server)
                .await;
        }

        let cache: Arc<dyn AdvisoryWriteCache> = Arc::new(MemoryAdvisoryCache::new());
        // Pre-populate the cache so the first call hits the L1 layer.
        cache
            .insert(CachedAdvisory {
                id: "RUSTSEC-2020-0036".to_string(),
                kind: AdvisoryKind::Found {
                    summary: Some("cached".to_string()),
                    unmaintained: true,
                },
                fetched_at: SystemTime::now(),
            })
            .await;

        let client = OsvClient::with_endpoint_and_cache(server.uri(), Arc::clone(&cache));
        let result = client
            .check_rustsec_unmaintained(&["RUSTSEC-2020-0036".to_string()])
            .await;

        assert!(
            result,
            "cached advisory marked unmaintained must short-circuit"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 0, "no HTTP call expected");
    }

    #[tokio::test]
    async fn first_call_populates_cache_and_second_call_skips_http() {
        let server = MockServer::start().await;
        let counter = Arc::new(AtomicUsize::new(0));
        {
            let counter = Arc::clone(&counter);
            Mock::given(method("GET"))
                .and(path("/vulns/RUSTSEC-2020-0036"))
                .respond_with(move |_req: &wiremock::Request| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    ResponseTemplate::new(200).set_body_json(sample_response_body())
                })
                .mount(&server)
                .await;
        }

        let cache: Arc<dyn AdvisoryWriteCache> = Arc::new(MemoryAdvisoryCache::new());
        let client = OsvClient::with_endpoint_and_cache(server.uri(), Arc::clone(&cache));

        let first = client
            .check_rustsec_unmaintained(&["RUSTSEC-2020-0036".to_string()])
            .await;
        let second = client
            .check_rustsec_unmaintained(&["RUSTSEC-2020-0036".to_string()])
            .await;

        assert!(first);
        assert!(second);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "second call should be cached"
        );
        let cached = cache.get("RUSTSEC-2020-0036").await.expect("entry stored");
        assert!(matches!(
            cached.kind,
            AdvisoryKind::Found {
                unmaintained: true,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn http_404_is_negatively_cached() {
        let server = MockServer::start().await;
        let counter = Arc::new(AtomicUsize::new(0));
        {
            let counter = Arc::clone(&counter);
            Mock::given(method("GET"))
                .and(path("/vulns/RUSTSEC-9999-0001"))
                .respond_with(move |_req: &wiremock::Request| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    ResponseTemplate::new(404)
                })
                .mount(&server)
                .await;
        }

        let cache: Arc<dyn AdvisoryWriteCache> = Arc::new(MemoryAdvisoryCache::new());
        let client = OsvClient::with_endpoint_and_cache(server.uri(), Arc::clone(&cache));

        let first = client
            .check_rustsec_unmaintained(&["RUSTSEC-9999-0001".to_string()])
            .await;
        let second = client
            .check_rustsec_unmaintained(&["RUSTSEC-9999-0001".to_string()])
            .await;

        assert!(!first);
        assert!(!second);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        let cached = cache
            .get("RUSTSEC-9999-0001")
            .await
            .expect("negative cached");
        assert_eq!(cached.kind, AdvisoryKind::NotFound);
    }

    #[tokio::test]
    async fn http_404_lands_on_negative_cache_only() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/vulns/RUSTSEC-9999-0001"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let positive: Arc<dyn AdvisoryWriteCache> = Arc::new(MemoryAdvisoryCache::new());
        let negative: Arc<dyn AdvisoryWriteCache> = Arc::new(MemoryAdvisoryCache::new());
        let client = OsvClient::with_endpoint_and_caches(
            server.uri(),
            Arc::clone(&positive),
            Arc::clone(&negative),
        );

        let _ = client
            .check_rustsec_unmaintained(&["RUSTSEC-9999-0001".to_string()])
            .await;

        assert!(
            positive.get("RUSTSEC-9999-0001").await.is_none(),
            "404 must NOT land on the positive cache"
        );
        let cached = negative
            .get("RUSTSEC-9999-0001")
            .await
            .expect("404 should land on negative cache");
        assert_eq!(cached.kind, AdvisoryKind::NotFound);
    }

    #[tokio::test]
    async fn http_200_lands_on_positive_cache_only() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/vulns/RUSTSEC-2020-0036"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sample_response_body()))
            .mount(&server)
            .await;

        let positive: Arc<dyn AdvisoryWriteCache> = Arc::new(MemoryAdvisoryCache::new());
        let negative: Arc<dyn AdvisoryWriteCache> = Arc::new(MemoryAdvisoryCache::new());
        let client = OsvClient::with_endpoint_and_caches(
            server.uri(),
            Arc::clone(&positive),
            Arc::clone(&negative),
        );

        let _ = client
            .check_rustsec_unmaintained(&["RUSTSEC-2020-0036".to_string()])
            .await;

        let cached = positive
            .get("RUSTSEC-2020-0036")
            .await
            .expect("200 should land on positive cache");
        assert!(matches!(cached.kind, AdvisoryKind::Found { .. }));
        assert!(
            negative.get("RUSTSEC-2020-0036").await.is_none(),
            "200 must NOT land on the negative cache"
        );
    }

    /// Confirm `negative_from_config` produces a memory-only hybrid that
    /// honours `negative_ttl_secs` instead of `ttl_secs`.
    #[tokio::test]
    async fn negative_from_config_uses_negative_ttl() {
        // ttl_secs would keep the entry alive a long time; negative_ttl_secs
        // is short. After the short TTL expires, the entry must be gone.
        let config = crate::config::AdvisoryCacheConfig {
            enabled: true,
            ttl_secs: 86_400,
            negative_ttl_secs: 0,
            db_path: None,
        };
        let hybrid = crate::cache::HybridAdvisoryCache::negative_from_config(&config);
        hybrid
            .insert(CachedAdvisory {
                id: "RUSTSEC-9999-0001".to_string(),
                kind: AdvisoryKind::NotFound,
                fetched_at: SystemTime::now(),
            })
            .await;
        // ttl=0 expires immediately on read.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        assert!(hybrid.get("RUSTSEC-9999-0001").await.is_none());
    }

    /// Regression: pre-split builds wrote 404s to the positive cache. After
    /// the split, those rows linger for the full positive TTL (24 h). A
    /// `NotFound` returned from the *positive* cache must therefore NOT be
    /// treated as authoritative; the lookup must fall through so the
    /// short-TTL negative cache or the network can refresh the answer.
    #[tokio::test]
    async fn positive_cache_not_found_falls_through_to_network() {
        let server = MockServer::start().await;
        let hits = Arc::new(AtomicUsize::new(0));
        {
            let hits = Arc::clone(&hits);
            Mock::given(method("GET"))
                .and(path("/vulns/RUSTSEC-2020-0036"))
                .respond_with(move |_req: &wiremock::Request| {
                    hits.fetch_add(1, Ordering::SeqCst);
                    ResponseTemplate::new(200).set_body_json(sample_response_body())
                })
                .mount(&server)
                .await;
        }

        let positive: Arc<dyn AdvisoryWriteCache> = Arc::new(MemoryAdvisoryCache::new());
        let negative: Arc<dyn AdvisoryWriteCache> = Arc::new(MemoryAdvisoryCache::new());

        // Pre-seed the positive cache with a stale `NotFound` (as a pre-split
        // build would have done for a 404). The new lookup logic must not
        // short-circuit on it.
        positive
            .insert(CachedAdvisory {
                id: "RUSTSEC-2020-0036".to_string(),
                kind: AdvisoryKind::NotFound,
                fetched_at: SystemTime::now(),
            })
            .await;

        let client = OsvClient::with_endpoint_and_caches(
            server.uri(),
            Arc::clone(&positive),
            Arc::clone(&negative),
        );

        let _ = client
            .check_rustsec_unmaintained(&["RUSTSEC-2020-0036".to_string()])
            .await;

        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "stale NotFound on positive cache must not short-circuit the network call"
        );
        // The fresh 200 must overwrite the stale row via UPSERT semantics.
        let cached = positive
            .get("RUSTSEC-2020-0036")
            .await
            .expect("positive cache must hold the refreshed Found entry");
        assert!(matches!(cached.kind, AdvisoryKind::Found { .. }));
    }

    #[tokio::test]
    async fn http_500_is_not_cached_and_retries() {
        let server = MockServer::start().await;
        let counter = Arc::new(AtomicUsize::new(0));
        {
            let counter = Arc::clone(&counter);
            Mock::given(method("GET"))
                .and(path("/vulns/RUSTSEC-2020-0036"))
                .respond_with(move |_req: &wiremock::Request| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    ResponseTemplate::new(500)
                })
                .mount(&server)
                .await;
        }

        let cache: Arc<dyn AdvisoryWriteCache> = Arc::new(MemoryAdvisoryCache::new());
        let client = OsvClient::with_endpoint_and_cache(server.uri(), Arc::clone(&cache));

        let _ = client
            .check_rustsec_unmaintained(&["RUSTSEC-2020-0036".to_string()])
            .await;
        let _ = client
            .check_rustsec_unmaintained(&["RUSTSEC-2020-0036".to_string()])
            .await;

        assert_eq!(counter.load(Ordering::SeqCst), 2, "no caching on 5xx");
        assert!(cache.get("RUSTSEC-2020-0036").await.is_none());
    }

    #[tokio::test]
    async fn test_rustsec_advisory_lookup_limits_concurrency() {
        const EXPECTED_LIMIT: usize = RUSTSEC_ADVISORY_LOOKUP_CONCURRENCY;

        let active_requests = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let endpoint =
            spawn_counting_osv_server(Arc::clone(&active_requests), Arc::clone(&max_seen)).await;
        let client = OsvClient::with_endpoint(endpoint).expect("with_endpoint builds in test");
        let ids: Vec<String> = (0..(EXPECTED_LIMIT * 2 + 3))
            .map(|index| format!("RUSTSEC-2099-{index:04}"))
            .collect();

        let deprecated = client.check_rustsec_unmaintained(&ids).await;

        assert!(
            !deprecated,
            "test advisories should not be marked as unmaintained"
        );
        assert!(
            max_seen.load(Ordering::SeqCst) <= EXPECTED_LIMIT,
            "expected at most {EXPECTED_LIMIT} concurrent advisory lookups, saw {}",
            max_seen.load(Ordering::SeqCst)
        );
    }

    #[test]
    fn test_normalize_version_strips_operators_for_osv() {
        use super::super::normalize_version_for_osv;

        // These are real-world version strings from Python pyproject.toml
        assert_eq!(normalize_version_for_osv(">=1.23.0"), "1.23.0");
        assert_eq!(normalize_version_for_osv("==2.0.0"), "2.0.0");
        assert_eq!(normalize_version_for_osv("~=4.0"), "4.0");
        // Cargo/npm style
        assert_eq!(normalize_version_for_osv("^1.0.27"), "1.0.27");
    }

    #[tokio::test]
    async fn test_version_normalization_prevents_false_positives() {
        use super::super::normalize_version_for_osv;

        // urllib3 1.26.0 should NOT have GHSA-m5vv-6r4h-3vj9 (only affects <1.16.1)
        let raw_version = ">=1.26.0";
        let normalized = normalize_version_for_osv(raw_version);
        assert_eq!(normalized, "1.26.0");

        let client = OsvClient::new().unwrap();
        let query = VulnerabilityQuery {
            ecosystem: crate::vulnerabilities::Ecosystem::PyPI,
            package_name: "urllib3".to_string(),
            version: normalized,
        };

        let results = client.query_batch(&[query]).await.unwrap();
        assert!(!results.is_empty());

        let result = &results[0];
        // Verify the specific false-positive vulnerability is NOT present
        let has_false_positive = result.vulnerabilities.iter().any(|v| {
            v.id.contains("GHSA-m5vv-6r4h-3vj9") || v.description.contains("GHSA-m5vv-6r4h-3vj9")
        });
        assert!(
            !has_false_positive,
            "urllib3 1.26.0 should NOT have GHSA-m5vv-6r4h-3vj9 (only affects <1.16.1)"
        );
    }
}
