//! End-to-end coverage for `LockfileResolver` trait + dispatch helpers.
//! For each ecosystem, materialize a synthetic manifest+lockfile pair under
//! a tempdir, run the helper, and assert that `dep.resolved_version` is set.

use std::path::Path;

use depsy_lsp::file_types::FileType;
use depsy_lsp::parsers::Dependency;
use depsy_lsp::parsers::Span;
use depsy_lsp::parsers::lockfile_resolver::{resolve_versions_from_lockfile, select_resolver};

fn dep(name: &str, version: &str) -> Dependency {
    Dependency {
        name: name.to_string(),
        version: version.to_string(),
        name_span: Span {
            line: 0,
            line_start: 0,
            line_end: 0,
        },
        version_span: Span {
            line: 0,
            line_start: 0,
            line_end: 0,
        },
        dev: false,
        optional: false,
        registry: None,
        resolved_version: None,
        has_additional_version_constraints: false,
    }
}

async fn run_resolver(
    file_type: FileType,
    manifest_path: &Path,
    manifest_content: &str,
    deps: &mut [Dependency],
) {
    let resolver = select_resolver(file_type, manifest_path, manifest_content)
        .await
        .expect("resolver should be selected");
    let _arc = resolve_versions_from_lockfile(deps, resolver, manifest_path).await;
}

#[tokio::test]
async fn cargo_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = tmp.path().join("Cargo.toml");
    std::fs::write(
        &manifest,
        r#"[package]
name = "demo"
version = "0.1.0"
[dependencies]
serde = "1"
"#,
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("Cargo.lock"),
        r#"
[[package]]
name = "serde"
version = "1.0.230"
"#,
    )
    .unwrap();
    let mut deps = vec![dep("serde", "1")];
    run_resolver(
        FileType::Cargo,
        &manifest,
        &std::fs::read_to_string(&manifest).unwrap(),
        &mut deps,
    )
    .await;
    assert_eq!(deps[0].resolved_version, Some("1.0.230".to_string()));
}

#[tokio::test]
async fn npm_end_to_end_package_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = tmp.path().join("package.json");
    std::fs::write(&manifest, r#"{"name":"demo","version":"0.0.1"}"#).unwrap();
    std::fs::write(
        tmp.path().join("package-lock.json"),
        r#"{
          "name":"demo","version":"0.0.1","lockfileVersion":3,
          "packages":{
            "":{"name":"demo","version":"0.0.1"},
            "node_modules/lodash":{"version":"4.17.21"}
          }
        }"#,
    )
    .unwrap();
    let mut deps = vec![dep("lodash", "^4.0.0")];
    run_resolver(
        FileType::Npm,
        &manifest,
        &std::fs::read_to_string(&manifest).unwrap(),
        &mut deps,
    )
    .await;
    assert_eq!(deps[0].resolved_version, Some("4.17.21".to_string()));
}

#[tokio::test]
async fn python_end_to_end_poetry() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = tmp.path().join("pyproject.toml");
    std::fs::write(&manifest, "[tool.poetry]\nname='demo'\nversion='0.1.0'\n").unwrap();
    std::fs::write(
        tmp.path().join("poetry.lock"),
        r#"
[[package]]
name = "Some-Package"
version = "1.2.3"
"#,
    )
    .unwrap();
    let mut deps = vec![dep("some.package", "*")];
    run_resolver(
        FileType::Python,
        &manifest,
        &std::fs::read_to_string(&manifest).unwrap(),
        &mut deps,
    )
    .await;
    assert_eq!(deps[0].resolved_version, Some("1.2.3".to_string()));
}

#[tokio::test]
async fn go_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = tmp.path().join("go.mod");
    std::fs::write(&manifest, "module example.com/demo\n").unwrap();
    std::fs::write(
        tmp.path().join("go.sum"),
        "github.com/foo/bar v1.0.0 h1:hash=\n",
    )
    .unwrap();
    let mut deps = vec![dep("github.com/foo/bar", "v1.0.0")];
    run_resolver(
        FileType::Go,
        &manifest,
        &std::fs::read_to_string(&manifest).unwrap(),
        &mut deps,
    )
    .await;
    assert_eq!(deps[0].resolved_version, Some("v1.0.0".to_string()));
}

#[tokio::test]
async fn php_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = tmp.path().join("composer.json");
    std::fs::write(&manifest, "{}").unwrap();
    std::fs::write(
        tmp.path().join("composer.lock"),
        r#"{"packages":[{"name":"vendor/pkg","version":"1.0.0"}]}"#,
    )
    .unwrap();
    let mut deps = vec![dep("VENDOR/PKG", "*")];
    run_resolver(
        FileType::Php,
        &manifest,
        &std::fs::read_to_string(&manifest).unwrap(),
        &mut deps,
    )
    .await;
    assert_eq!(deps[0].resolved_version, Some("1.0.0".to_string()));
}

#[tokio::test]
async fn dart_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = tmp.path().join("pubspec.yaml");
    std::fs::write(&manifest, "name: demo\nversion: 0.1.0\n").unwrap();
    std::fs::write(
        tmp.path().join("pubspec.lock"),
        r#"packages:
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dev"
    source: hosted
    version: "1.2.0"
"#,
    )
    .unwrap();
    let mut deps = vec![dep("http", "^1.0.0")];
    run_resolver(
        FileType::Dart,
        &manifest,
        &std::fs::read_to_string(&manifest).unwrap(),
        &mut deps,
    )
    .await;
    assert_eq!(deps[0].resolved_version, Some("1.2.0".to_string()));
}

#[tokio::test]
async fn csharp_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = tmp.path().join("Demo.csproj");
    std::fs::write(&manifest, "<Project></Project>").unwrap();
    std::fs::write(
        tmp.path().join("packages.lock.json"),
        r#"{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"13.0.3"}}}}"#,
    )
    .unwrap();
    let mut deps = vec![dep("newtonsoft.json", "*")];
    run_resolver(
        FileType::Csharp,
        &manifest,
        &std::fs::read_to_string(&manifest).unwrap(),
        &mut deps,
    )
    .await;
    assert_eq!(deps[0].resolved_version, Some("13.0.3".to_string()));
}

#[tokio::test]
async fn ruby_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = tmp.path().join("Gemfile");
    std::fs::write(&manifest, "source 'https://rubygems.org'\ngem 'rails'\n").unwrap();
    std::fs::write(
        tmp.path().join("Gemfile.lock"),
        r#"GEM
  remote: https://rubygems.org/
  specs:
    rails (7.1.0)

PLATFORMS
  ruby

DEPENDENCIES
  rails

BUNDLED WITH
   2.4.0
"#,
    )
    .unwrap();
    let mut deps = vec![dep("rails", "*")];
    run_resolver(
        FileType::Ruby,
        &manifest,
        &std::fs::read_to_string(&manifest).unwrap(),
        &mut deps,
    )
    .await;
    assert_eq!(deps[0].resolved_version, Some("7.1.0".to_string()));
}

#[tokio::test]
async fn maven_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = tmp.path().join("pom.xml");
    std::fs::write(&manifest, "<project></project>").unwrap();
    let resolver = select_resolver(FileType::Maven, &manifest, "<project></project>").await;
    assert!(resolver.is_none(), "Maven not supported");
}
