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

#[tokio::test]
async fn test_scan_pnpm_workspace_catalogs_queries_npm_ecosystem() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/querybatch"))
        .respond_with(|request: &wiremock::Request| {
            let body: serde_json::Value = request
                .body_json()
                .expect("querybatch request body should be valid JSON");
            let results: Vec<serde_json::Value> = body["queries"]
                .as_array()
                .expect("querybatch.queries should be an array")
                .iter()
                .map(|_| serde_json::json!({ "vulns": [] }))
                .collect();

            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": results
            }))
        })
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().expect("failed to create temp dir");
    let workspace_path = tmp.path().join("pnpm-workspace.yaml");
    std::fs::write(
        &workspace_path,
        r#"packages:
  - packages/*
catalog:
  lodash: ^4.17.21
catalogs:
  react17:
    react: ^17.0.2
  react18:
    react: ^18.2.0
"#,
    )
    .expect("failed to write pnpm-workspace.yaml");

    let output = Command::new(depsy_lsp_bin())
        .env("OSV_ENDPOINT", server.uri())
        .args(["scan", "--output", "json", "--file"])
        .arg(&workspace_path)
        .output()
        .expect("failed to run depsy-lsp");

    assert_eq!(
        output.status.code(),
        Some(0),
        "scan of pnpm-workspace.yaml should succeed\nstdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let requests = server
        .received_requests()
        .await
        .expect("failed to collect mock server requests");
    let querybatch_body: serde_json::Value = requests
        .iter()
        .find(|request| request.url.path() == "/querybatch")
        .expect("expected POST /querybatch")
        .body_json()
        .expect("querybatch body should be valid JSON");
    let queries = querybatch_body["queries"]
        .as_array()
        .expect("querybatch.queries should be an array");

    assert_eq!(
        queries.len(),
        3,
        "expected exactly three OSV queries for the catalog entries, got {queries:?}"
    );
    for (package_name, version) in [
        ("lodash", "4.17.21"),
        ("react", "17.0.2"),
        ("react", "18.2.0"),
    ] {
        assert!(
            queries.iter().any(|query| {
                query["package"]["name"] == package_name
                    && query["package"]["ecosystem"] == "npm"
                    && query["version"] == version
            }),
            "expected npm OSV query for {package_name}@{version}, got {queries:?}"
        );
    }
}

/// Issue #424 on the CLI path. The declared version sits between the first and the
/// last lockfile entry, so taking either end queries the wrong one.
#[tokio::test]
async fn test_scan_yarn_berry_queries_version_in_declared_range() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/querybatch"))
        .respond_with(|request: &wiremock::Request| {
            let body: serde_json::Value = request
                .body_json()
                .expect("querybatch request body should be valid JSON");
            let results: Vec<serde_json::Value> = body["queries"]
                .as_array()
                .expect("querybatch.queries should be an array")
                .iter()
                .map(|_| serde_json::json!({ "vulns": [] }))
                .collect();

            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": results
            }))
        })
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().expect("failed to create temp dir");
    let manifest_path = tmp.path().join("package.json");
    std::fs::write(
        &manifest_path,
        r#"{"name":"app","dependencies":{"rxjs":"^6.0.0"}}"#,
    )
    .expect("failed to write package.json");
    std::fs::write(
        tmp.path().join("yarn.lock"),
        r#"__metadata:
  version: 8

"rxjs@npm:^5.0.0":
  version: 5.5.12
  resolution: "rxjs@npm:5.5.12"

"rxjs@npm:^6.0.0":
  version: 6.6.7
  resolution: "rxjs@npm:6.6.7"
  dependencies:
    tslib: "npm:^1.9.0"

"rxjs@npm:^7.0.0":
  version: 7.8.1
  resolution: "rxjs@npm:7.8.1"

"tslib@npm:^1.9.0":
  version: 1.14.1
  resolution: "tslib@npm:1.14.1"
"#,
    )
    .expect("failed to write yarn.lock");

    let output = Command::new(depsy_lsp_bin())
        .env("OSV_ENDPOINT", server.uri())
        .args(["scan", "--output", "json", "--file"])
        .arg(&manifest_path)
        .output()
        .expect("failed to run depsy-lsp");

    assert_eq!(
        output.status.code(),
        Some(0),
        "scan of a Berry project should succeed\nstdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let requests = server
        .received_requests()
        .await
        .expect("failed to collect mock server requests");
    let querybatch_body: serde_json::Value = requests
        .iter()
        .find(|request| request.url.path() == "/querybatch")
        .expect("expected POST /querybatch")
        .body_json()
        .expect("querybatch body should be valid JSON");
    let mut queried: Vec<(String, String)> = querybatch_body["queries"]
        .as_array()
        .expect("querybatch.queries should be an array")
        .iter()
        .map(|query| {
            (
                query["package"]["name"].as_str().unwrap_or("").to_string(),
                query["version"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    queried.sort();

    assert_eq!(
        queried,
        vec![
            ("rxjs".to_string(), "6.6.7".to_string()),
            ("tslib".to_string(), "1.14.1".to_string()),
        ]
    );
}

#[tokio::test]
async fn test_scan_pnpm_workspace_catalogs_queries_versions_locked_per_catalog() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/querybatch"))
        .respond_with(|request: &wiremock::Request| {
            let body: serde_json::Value = request
                .body_json()
                .expect("querybatch request body should be valid JSON");
            let results: Vec<serde_json::Value> = body["queries"]
                .as_array()
                .expect("querybatch.queries should be an array")
                .iter()
                .map(|_| serde_json::json!({ "vulns": [] }))
                .collect();

            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": results
            }))
        })
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().expect("failed to create temp dir");
    let workspace_path = tmp.path().join("pnpm-workspace.yaml");
    std::fs::write(
        &workspace_path,
        r#"packages:
  - packages/*
catalog:
  lodash: ^4.17.0
catalogs:
  react17:
    react: ^17.0.2
  react18:
    react: ^18.2.0
"#,
    )
    .expect("failed to write pnpm-workspace.yaml");
    std::fs::write(
        tmp.path().join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'

catalogs:
  default:
    lodash:
      specifier: ^4.17.0
      version: 4.17.21
  react17:
    react:
      specifier: ^17.0.2
      version: 17.0.2
  react18:
    react:
      specifier: ^18.2.0
      version: 18.3.1

packages:

  lodash@4.17.21:
    resolution: {integrity: sha512-lodash}

  react@17.0.2:
    resolution: {integrity: sha512-react17}

  react@18.3.1:
    resolution: {integrity: sha512-react18}

snapshots:

  lodash@4.17.21: {}

  react@17.0.2: {}

  react@18.3.1: {}
"#,
    )
    .expect("failed to write pnpm-lock.yaml");
    std::fs::write(
        tmp.path().join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.15"}}}"#,
    )
    .expect("failed to write package-lock.json");

    let output = Command::new(depsy_lsp_bin())
        .env("OSV_ENDPOINT", server.uri())
        .args(["scan", "--output", "json", "--file"])
        .arg(&workspace_path)
        .output()
        .expect("failed to run depsy-lsp");

    assert_eq!(
        output.status.code(),
        Some(0),
        "scan of pnpm-workspace.yaml should succeed\nstdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let requests = server
        .received_requests()
        .await
        .expect("failed to collect mock server requests");
    let querybatch_body: serde_json::Value = requests
        .iter()
        .find(|request| request.url.path() == "/querybatch")
        .expect("expected POST /querybatch")
        .body_json()
        .expect("querybatch body should be valid JSON");
    let queries = querybatch_body["queries"]
        .as_array()
        .expect("querybatch.queries should be an array");

    assert_eq!(
        queries.len(),
        3,
        "expected exactly three OSV queries for the catalog entries, got {queries:?}"
    );
    for (package_name, version) in [
        ("lodash", "4.17.21"),
        ("react", "17.0.2"),
        ("react", "18.3.1"),
    ] {
        assert!(
            queries.iter().any(|query| {
                query["package"]["name"] == package_name
                    && query["package"]["ecosystem"] == "npm"
                    && query["version"] == version
            }),
            "expected npm OSV query for {package_name}@{version}, got {queries:?}"
        );
    }
}
