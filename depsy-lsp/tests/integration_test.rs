//! Integration tests for depsy-lsp

use depsy_lsp::cache::{MemoryCache, ReadCache, WriteCache};
use depsy_lsp::file_types::FileType;
use depsy_lsp::parsers::Parser;
use depsy_lsp::parsers::cargo::CargoParser;
use depsy_lsp::parsers::npm::NpmParser;
use depsy_lsp::providers::inlay_hints::create_inlay_hint;
use depsy_lsp::registries::VersionInfo;

/// Test parsing a realistic Cargo.toml file
#[test]
fn test_parse_realistic_cargo_toml() {
    let content = r#"
[package]
name = "my-awesome-app"
version = "0.1.0"
edition = "2024"
license = "MIT"

[dependencies]
tokio = { version = "1.35", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
anyhow = "1"
thiserror = "2"
tracing = "0.1"

[dev-dependencies]
tokio-test = "0.4"
criterion = { version = "0.5", features = ["html_reports"] }

[build-dependencies]
cc = "1.0"
"#;

    let parser = CargoParser::new();
    let deps = parser.parse(content);

    // Should find all dependencies
    assert_eq!(deps.len(), 10);

    // Check regular dependencies
    let tokio = deps.iter().find(|d| d.name == "tokio").unwrap();
    assert_eq!(tokio.version, "1.35");
    assert!(!tokio.dev);

    let serde_json = deps.iter().find(|d| d.name == "serde_json").unwrap();
    assert_eq!(serde_json.version, "1.0");

    // Check dev dependencies
    let tokio_test = deps.iter().find(|d| d.name == "tokio-test").unwrap();
    assert!(tokio_test.dev);

    let criterion = deps.iter().find(|d| d.name == "criterion").unwrap();
    assert!(criterion.dev);
    assert_eq!(criterion.version, "0.5");

    // Check build dependencies (treated as regular for now)
    let cc = deps.iter().find(|d| d.name == "cc").unwrap();
    assert_eq!(cc.version, "1.0");
}

/// Test parsing a realistic package.json file
#[test]
fn test_parse_realistic_package_json() {
    let content = r#"{
  "name": "my-react-app",
  "version": "1.0.0",
  "description": "A sample React application",
  "main": "index.js",
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "axios": "^1.6.0",
    "@tanstack/react-query": "^5.0.0",
    "lodash": "^4.17.21"
  },
  "devDependencies": {
    "@types/react": "^18.2.0",
    "@types/react-dom": "^18.2.0",
    "typescript": "^5.3.0",
    "@testing-library/react": "^14.0.0",
    "prettier": "^3.1.0"
  },
  "peerDependencies": {
    "react": ">=16.8.0"
  }
}"#;

    let parser = NpmParser::new();
    let deps = parser.parse(content);

    // Should find all dependencies
    assert_eq!(deps.len(), 11);

    // Check regular dependencies
    let react = deps
        .iter()
        .find(|d| d.name == "react" && !d.optional)
        .unwrap();
    assert_eq!(react.version, "^18.2.0");
    assert!(!react.dev);

    // Check scoped packages
    let react_query = deps
        .iter()
        .find(|d| d.name == "@tanstack/react-query")
        .unwrap();
    assert_eq!(react_query.version, "^5.0.0");

    // Check dev dependencies
    let typescript = deps.iter().find(|d| d.name == "typescript").unwrap();
    assert!(typescript.dev);
    assert_eq!(typescript.version, "^5.3.0");

    // Check peer dependencies (marked as optional)
    let peer_react = deps
        .iter()
        .find(|d| d.name == "react" && d.optional)
        .unwrap();
    assert_eq!(peer_react.version, ">=16.8.0");
}

/// Test cache integration
#[tokio::test]
async fn test_cache_integration() {
    let cache = MemoryCache::new();

    // Insert some version info
    let serde_info = VersionInfo {
        latest: Some("1.0.200".to_string()),
        latest_prerelease: None,
        versions: vec!["1.0.200".to_string(), "1.0.199".to_string()],
        description: Some("A serialization framework".to_string()),
        homepage: None,
        repository: Some("https://github.com/serde-rs/serde".to_string()),
        license: Some("MIT OR Apache-2.0".to_string()),
        vulnerabilities: vec![],
        deprecated: false,
        yanked: false,
        yanked_versions: vec![],
        release_dates: Default::default(),
        transitive_vulnerabilities: vec![],
    };

    cache
        .insert("crates:serde".to_string(), serde_info.clone())
        .await;

    // Retrieve and verify
    let retrieved = cache.get("crates:serde").await.unwrap();
    assert_eq!(retrieved.latest, Some("1.0.200".to_string()));
    assert_eq!(retrieved.license, Some("MIT OR Apache-2.0".to_string()));

    // Test cache miss
    assert!(cache.get("crates:nonexistent").await.is_none());
}

/// Test inlay hint generation with various scenarios
#[test]
fn test_inlay_hint_generation() {
    use depsy_lsp::parsers::{Dependency, Span};

    // Up-to-date dependency
    let dep_up_to_date = Dependency {
        name: "serde".to_string(),
        version: "1.0.200".to_string(),
        name_span: Span {
            line: 5,
            line_start: 0,
            line_end: 5,
        },
        version_span: Span {
            line: 5,
            line_start: 9,
            line_end: 18,
        },
        dev: false,
        optional: false,
        registry: None,
        resolved_version: None,
        has_additional_version_constraints: false,
    };

    let info_up_to_date = VersionInfo {
        latest: Some("1.0.200".to_string()),
        ..Default::default()
    };

    let hint = create_inlay_hint(&dep_up_to_date, Some(&info_up_to_date), FileType::Cargo);
    match hint.label {
        tower_lsp::lsp_types::InlayHintLabel::String(s) => {
            assert!(s.contains("✓"), "Expected checkmark for up-to-date dep");
        }
        _ => panic!("Expected string label"),
    }

    // Outdated dependency
    let dep_outdated = Dependency {
        name: "tokio".to_string(),
        version: "1.0.0".to_string(),
        name_span: Span {
            line: 6,
            line_start: 0,
            line_end: 5,
        },
        version_span: Span {
            line: 6,
            line_start: 9,
            line_end: 16,
        },
        dev: false,
        optional: false,
        registry: None,
        resolved_version: None,
        has_additional_version_constraints: false,
    };

    let info_outdated = VersionInfo {
        latest: Some("1.35.0".to_string()),
        ..Default::default()
    };

    let hint = create_inlay_hint(&dep_outdated, Some(&info_outdated), FileType::Cargo);
    match hint.label {
        tower_lsp::lsp_types::InlayHintLabel::String(s) => {
            assert!(s.contains("->"), "Expected arrow for outdated dep");
            assert!(s.contains("1.35.0"), "Expected latest version in hint");
        }
        _ => panic!("Expected string label"),
    }

    // Unknown version (no info) - shows ? Unknown with troubleshooting tooltip
    let hint = create_inlay_hint(&dep_outdated, None, FileType::Cargo);
    match hint.label {
        tower_lsp::lsp_types::InlayHintLabel::String(s) => {
            assert!(
                s.contains("? Unknown"),
                "Expected question mark for unknown/error status"
            );
        }
        _ => panic!("Expected string label"),
    }
}

/// Test parsing dependencies with various version specifiers
#[test]
fn test_version_specifier_parsing() {
    let cargo_content = r#"
[dependencies]
caret = "^1.0"
tilde = "~1.0.0"
exact = "=1.0.0"
range = ">=1.0, <2.0"
wildcard = "1.*"
"#;

    let parser = CargoParser::new();
    let deps = parser.parse(cargo_content);

    assert_eq!(deps.len(), 5);
    assert_eq!(
        deps.iter().find(|d| d.name == "caret").unwrap().version,
        "^1.0"
    );
    assert_eq!(
        deps.iter().find(|d| d.name == "tilde").unwrap().version,
        "~1.0.0"
    );
    assert_eq!(
        deps.iter().find(|d| d.name == "exact").unwrap().version,
        "=1.0.0"
    );
    assert_eq!(
        deps.iter().find(|d| d.name == "range").unwrap().version,
        ">=1.0, <2.0"
    );
    assert_eq!(
        deps.iter().find(|d| d.name == "wildcard").unwrap().version,
        "1.*"
    );
}

/// Test parsing npm packages with various version formats
#[test]
fn test_npm_version_formats() {
    let content = r#"{
  "dependencies": {
    "caret": "^1.0.0",
    "tilde": "~1.0.0",
    "range": ">=1.0.0 <2.0.0",
    "hyphen": "1.0.0 - 2.0.0",
    "exact": "1.0.0",
    "latest": "*",
    "tag": "latest"
  }
}"#;

    let parser = NpmParser::new();
    let deps = parser.parse(content);

    assert_eq!(deps.len(), 7);
    assert_eq!(
        deps.iter().find(|d| d.name == "caret").unwrap().version,
        "^1.0.0"
    );
    assert_eq!(
        deps.iter().find(|d| d.name == "range").unwrap().version,
        ">=1.0.0 <2.0.0"
    );
    assert_eq!(
        deps.iter().find(|d| d.name == "latest").unwrap().version,
        "*"
    );
    assert_eq!(
        deps.iter().find(|d| d.name == "tag").unwrap().version,
        "latest"
    );
}

/// Test that positions are correctly tracked
#[test]
fn test_dependency_positions() {
    let content = r#"[dependencies]
serde = "1.0.0"
tokio = { version = "1.35" }
"#;

    let parser = CargoParser::new();
    let deps = parser.parse(content);

    // serde should be on line 1 (0-indexed)
    let serde = deps.iter().find(|d| d.name == "serde").unwrap();
    assert_eq!(serde.name_span.line, 1);
    assert_eq!(serde.version_span.line, 1);

    // tokio should be on line 2
    let tokio = deps.iter().find(|d| d.name == "tokio").unwrap();
    assert_eq!(tokio.name_span.line, 2);
    assert_eq!(tokio.version_span.line, 2);
}

/// Integration test: Maven pom.xml detection + parse + cache key generation
#[test]
fn test_maven_pom_detection_parse_and_cache_key() {
    use depsy_lsp::parsers::maven::MavenParser;
    use tower_lsp::lsp_types::Url;

    let uri = Url::parse("file:///project/pom.xml").unwrap();
    assert_eq!(FileType::detect(&uri), Some(FileType::Maven));

    let pom = r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>app</artifactId>
    <version>1.0.0</version>
    <properties>
        <slf4j.version>2.0.9</slf4j.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-api</artifactId>
            <version>${slf4j.version}</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
"#;

    let parser = MavenParser::new();
    let deps = parser.parse(pom);
    assert_eq!(deps.len(), 2);

    let slf4j = deps
        .iter()
        .find(|d| d.name == "org.slf4j:slf4j-api")
        .expect("slf4j-api should be parsed");
    assert_eq!(
        slf4j.effective_version(),
        "2.0.9",
        "property must be substituted"
    );
    assert!(!slf4j.dev);

    let junit = deps
        .iter()
        .find(|d| d.name == "junit:junit")
        .expect("junit should be parsed");
    assert!(junit.dev, "test scope must be treated as dev");

    assert_eq!(
        FileType::Maven.cache_key(&slf4j.name),
        "maven:org.slf4j:slf4j-api"
    );
}
