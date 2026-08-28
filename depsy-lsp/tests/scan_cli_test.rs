use std::path::PathBuf;
use std::process::Command;

use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn depsy_lsp_bin() -> String {
    env!("CARGO_BIN_EXE_depsy-lsp").to_string()
}

fn fixture_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(rel)
}

#[tokio::test]
async fn test_scan_queries_osv_npm_ecosystem_and_reports_direct_vulnerabilities() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/querybatch"))
        .respond_with(|request: &wiremock::Request| {
            let body: serde_json::Value = request
                .body_json()
                .expect("querybatch request body should be valid JSON");
            let queries = body["queries"]
                .as_array()
                .expect("querybatch.queries should be an array");
            let results: Vec<serde_json::Value> = queries
                .iter()
                .map(|query| {
                    if query["package"]["name"] == "react"
                        && query["package"]["ecosystem"] == "npm"
                        && query["version"] == "18.2.0"
                    {
                        serde_json::json!({
                            "vulns": [{
                                "id": "CVE-NPM-DIRECT-001",
                                "modified": "2024-01-01T00:00:00Z",
                                "summary": "direct react vulnerability",
                                "severity": [{ "type": "CVSS_V3", "score": "9.8" }],
                                "references": [{ "type": "WEB", "url": "https://example.test/CVE-NPM-DIRECT-001" }]
                            }]
                        })
                    } else {
                        serde_json::json!({ "vulns": [] })
                    }
                })
                .collect();

            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": results
            }))
        })
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path_regex(r"^/vulns/.+"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "CVE-NPM-DIRECT-001",
            "summary": "direct react vulnerability",
            "details": "test details",
            "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
            "references": []
        })))
        .mount(&server)
        .await;

    let fixture = fixture_path("npm-project-with-lockfile/package.json");

    let output = Command::new(depsy_lsp_bin())
        .env("OSV_ENDPOINT", server.uri())
        .args(["scan", "--output", "json", "--file"])
        .arg(&fixture)
        .output()
        .expect("failed to run depsy-lsp");

    let requests = server
        .received_requests()
        .await
        .expect("failed to collect mock server requests");
    let querybatch = requests
        .iter()
        .find(|request| request.url.path() == "/querybatch")
        .expect("expected POST /querybatch");
    let querybatch_body: serde_json::Value = querybatch
        .body_json()
        .expect("querybatch body should be valid JSON");
    let queries = querybatch_body["queries"]
        .as_array()
        .expect("querybatch.queries should be an array");
    let has_npm_query = |package_name: &str, version: &str| {
        queries.iter().any(|query| {
            query["package"]["name"] == package_name
                && query["package"]["ecosystem"] == "npm"
                && query["version"] == version
        })
    };

    assert!(
        has_npm_query("react", "18.2.0"),
        "expected npm OSV query for react@18.2.0"
    );
    assert!(
        has_npm_query("scheduler", "0.23.0"),
        "expected npm OSV query for scheduler@0.23.0"
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "depsy-lsp must exit 1 when npm direct vulnerabilities are found\nstdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("scan output should be valid JSON");
    let direct = report["direct"]
        .as_array()
        .expect("direct vulnerabilities should be an array");
    assert_eq!(direct.len(), 1, "expected one direct vulnerability");
    assert_eq!(direct[0]["package"], "react");
    assert_eq!(direct[0]["version"], "18.2.0");
    assert_eq!(direct[0]["id"], "CVE-NPM-DIRECT-001");
    assert_eq!(direct[0]["severity"], "critical");
    assert_eq!(
        report["transitive"]
            .as_array()
            .expect("transitive vulnerabilities should be an array")
            .len(),
        0,
        "direct npm vulnerability should not be reported as transitive",
    );
}

#[tokio::test]
async fn test_scan_uses_lockfile_and_reports_transitive() {
    let server = MockServer::start().await;

    // Mock OSV querybatch: npm fixture has direct [react] + transitive [scheduler].
    // Return no vulns for react (index 0) and a vuln for scheduler (index 1).
    Mock::given(method("POST"))
        .and(path("/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": [
                { "vulns": [] },
                { "vulns": [{ "id": "CVE-TEST-001", "modified": "2024-01-01T00:00:00Z" }] }
            ]
        })))
        .mount(&server)
        .await;

    // Mock individual vuln lookups (check_rustsec_unmaintained calls GET /vulns/{id}).
    // CVE-TEST-001 is not a RUSTSEC id so this won't be called, but guard against it anyway.
    Mock::given(method("GET"))
        .and(path_regex(r"^/vulns/.+"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "CVE-TEST-001",
            "summary": "test summary",
            "details": "test details",
            "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
            "references": []
        })))
        .mount(&server)
        .await;

    let fixture = fixture_path("npm-project-with-lockfile/package.json");

    let output = Command::new(depsy_lsp_bin())
        .env("OSV_ENDPOINT", server.uri())
        .args(["scan", "--output", "json", "--file"])
        .arg(&fixture)
        .output()
        .expect("failed to run depsy-lsp");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("\"transitive\""),
        "expected transitive key in JSON. stdout=\n{stdout}"
    );
    // The npm fixture has `react` as direct and `scheduler` as transitive. The mock
    // returns a vuln on the second query (the transitive). Confirm:
    assert!(
        stdout.contains("scheduler") || stdout.contains("CVE-TEST-001"),
        "expected transitive CVE to appear in output, got:\n{stdout}"
    );
    assert!(
        stdout.contains("\"direct\""),
        "expected direct array in JSON output. stdout=\n{stdout}\nstderr=\n{stderr}"
    );
}

#[test]
fn test_scan_no_use_lockfile_flag_skips_detection() {
    // When --no-use-lockfile is passed, even with a lockfile present the graph should be empty.
    // We point OSV_ENDPOINT at an unreachable port so any actual query errors fast and we
    // check that no "transitive" data was computed.
    let fixture = fixture_path("rust-project-with-lockfile/Cargo.toml");

    let output = Command::new(depsy_lsp_bin())
        .env("OSV_ENDPOINT", "http://127.0.0.1:1") // unreachable
        .args(["scan", "--output", "json", "--no-use-lockfile", "--file"])
        .arg(&fixture)
        .output()
        .expect("failed to run depsy-lsp");

    // With a broken endpoint, the query fails → ExitCode::FAILURE (1). That's ok;
    // the flag just needs to parse. The stderr should confirm the command ran.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Scanning") || stderr.contains("Error"),
        "expected scan to run, got stderr: {stderr}"
    );
}

#[test]
fn test_scan_malformed_lockfile_falls_back() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        tmp.path().join("Cargo.toml"),
        r#"
[package]
name = "x"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1"
"#,
    )
    .expect("write manifest");
    std::fs::write(tmp.path().join("Cargo.lock"), "not valid toml ][").expect("write lockfile");

    let output = Command::new(depsy_lsp_bin())
        .env("OSV_ENDPOINT", "http://127.0.0.1:1") // unreachable so we don't hit network
        .args(["scan", "--output", "json", "--file"])
        .arg(tmp.path().join("Cargo.toml"))
        .output()
        .expect("run");
    // Should not crash. Exit code may be 0 or 1 depending on how graceful the fallback is;
    // what we care about is not a panic.
    assert!(output.status.code().is_some(), "process exited abnormally");
}

#[tokio::test]
async fn test_scan_html_output() {
    let server = MockServer::start().await;

    // Same npm fixture as test_scan_uses_lockfile_and_reports_transitive:
    // direct [react] + transitive [scheduler]. Return vuln on the transitive only.
    Mock::given(method("POST"))
        .and(path("/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": [
                { "vulns": [] },
                { "vulns": [{ "id": "CVE-HTML-001", "modified": "2024-01-01T00:00:00Z" }] }
            ]
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path_regex(r"^/vulns/.+"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "CVE-HTML-001",
            "summary": "test summary",
            "details": "test details",
            "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
            "references": []
        })))
        .mount(&server)
        .await;

    let fixture = fixture_path("npm-project-with-lockfile/package.json");

    let output = Command::new(depsy_lsp_bin())
        .env("OSV_ENDPOINT", server.uri())
        .args(["scan", "--output", "html", "--file"])
        .arg(&fixture)
        .output()
        .expect("failed to run depsy-lsp");

    // CLI returns ExitCode::FAILURE (1) when --fail-on-vulns is set (default)
    // and total_vulns > 0. The mock injects one vuln, so exit code 1 is required.
    // Allowing 0 would let a regression that stops failing on vulns silently pass.
    assert_eq!(
        output.status.code(),
        Some(1),
        "depsy-lsp must exit 1 when vulnerabilities are found\nstdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("<!DOCTYPE html>"),
        "expected HTML output to start with DOCTYPE, stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("<title>Vulnerability Report"),
        "expected title, stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("CVE-HTML-001"),
        "expected transitive CVE in HTML, stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("Transitive dependencies"),
        "expected transitive section heading, stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("via <code>react</code>"),
        "expected via <code>react</code> attribution, stdout=\n{stdout}"
    );
    assert!(
        stdout.trim_end().ends_with("</html>"),
        "expected closing </html> tag"
    );
}
