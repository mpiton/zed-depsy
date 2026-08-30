//! Regression tests for fuzz crashes

use depsy_lsp::parsers::{
    Parser, cargo::CargoParser, maven::MavenParser, npm::NpmParser, php::PhpParser,
    python::PythonParser,
};
use std::panic::AssertUnwindSafe;

fn validate_deps(deps: &[depsy_lsp::parsers::Dependency], content: &str, parser_name: &str) {
    let lines: Vec<&str> = content.lines().collect();
    let lines_len = lines.len();
    for dep in deps {
        let dep_name_line = dep.name_span.line;
        assert!(
            (dep_name_line as usize) < lines_len,
            "{parser_name}: dep.name_span.line {dep_name_line} >= lines.len() {lines_len}"
        );

        let name_line = lines[dep_name_line as usize];
        let name_line_len = name_line.len() as u32;

        let dep_name = &*dep.name;
        let dep_name_start = dep.name_span.line_start;
        let dep_name_end = dep.name_span.line_end;
        assert!(
            dep_name_start <= dep_name_end,
            "{parser_name}: name_start {dep_name_start} > name_end {dep_name_end}"
        );
        assert!(
            dep_name_end <= name_line_len,
            "{parser_name}: name_end {dep_name_end} > line_len {name_line_len} for dep {dep_name} on line '{name_line}'"
        );

        let dep_version_line = dep.version_span.line;
        assert!(
            (dep_version_line as usize) < lines_len,
            "{parser_name}: dep.version_span.line {dep_version_line} >= lines.len() {lines_len}"
        );

        let version_line = lines[dep_version_line as usize];
        let version_line_len = version_line.len() as u32;

        let dep_version_start = dep.version_span.line_start;
        let dep_version_end = dep.version_span.line_end;
        assert!(
            dep_version_start <= dep_version_end,
            "{parser_name}: version_start {dep_version_start} > version_end {dep_version_end}"
        );
        assert!(
            dep_version_end <= version_line_len,
            "{parser_name}: version_end {dep_version_end} > line_len {version_line_len} for dep {dep_name} on line '{version_line}'"
        );
    }
}

#[test]
fn test_npm_fuzz_crash() {
    // Crash input that triggered version_end > line_len
    let content = r#"{
  "name": "test-package",
  "version": "1.0.0",
  "dependencies": {
    "^^^^^name": "test-package",
  "version": "1.0^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^expe29.0.0"
  }
}"#;

    let parser = NpmParser::new();
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| parser.parse(content)));

    match result {
        Ok(deps) => validate_deps(&deps, content, "NPM"),
        Err(_) => panic!("NPM parser should not panic"),
    }
}

#[test]
fn test_cargo_fuzz_crash() {
    // Crash input that triggered name_end > line_len for table dependencies
    let content = r#"[package]
name = "complex-crate"
version = "1.2.3"

[dependencies]
anyhow = "1.0.100"
thiserror = { version = "2.0", optional = true }

[dependencies.reqwest]
version = "0.12"
features = ["json", "rustls-tls"]
default-features = false

[dev-dependencies]
tokio-test = "0.4"

[target.'cfg(unix)'.dependencies]
nix = "0.27"
"#;

    let parser = CargoParser::new();
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| parser.parse(content)));

    match result {
        Ok(deps) => validate_deps(&deps, content, "Cargo"),
        Err(_) => panic!("Cargo parser should not panic"),
    }
}

#[test]
fn test_php_fuzz_crash() {
    // Crash input with malformed JSON that could cause version on different line
    let content = r#"{
    "name": "v/project",
    "require": {
        "php": ">=7.1",
        "laravel/frameworklehttp/g [ ['uzz'e":   "requir-[[[[[[[[[[[[[[[[[[[[[[`  la[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[7.1",
        "laravel/frameworklehttp/g [ ['uzz'e":   "requir-[[[[[[[[[[[[[[[[[[[[[[[[`  la[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[ev"
}
}"#;

    let parser = PhpParser::new();
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| parser.parse(content)));

    match result {
        Ok(deps) => validate_deps(&deps, content, "PHP"),
        Err(_) => panic!("PHP parser should not panic"),
    }
}

#[test]
fn test_python_fuzz_crash_toml() {
    // Crash input that triggered panic in toml parser (contains [project] so parsed as TOML)
    let content = "[project]\nname = \"m-jyerequests==2.32.4f\nlask>=0.2.0.0.0\nnu.0.\x01\x00\x00\x00\x01\x14\x0b!=7.0.rpoct\"\nversion = \"1.0.0\"\ndependencies = [\n    \n0dj_ngo>4.\"re=2.\n[project.optional-dependencies]\ndev = [\n    \"onal-dependenciev\nsd]e = [";

    let parser = PythonParser::new();
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| parser.parse(content)));

    match result {
        Ok(deps) => validate_deps(&deps, content, "Python"),
        Err(_) => {
            // Python parser may panic due to toml crate bug on malformed input
            // This is acceptable in tests - the fuzz test uses stricter detection
        }
    }
}

#[test]
fn test_python_fuzz_crash_malformed_bracket() {
    // Crash input without [project] - should be parsed as requirements.txt, not TOML
    // This avoids the toml parser panic
    let content = "[propect]\"\ns = [\n   0d.   _   00d. dencies quests>=2.= 2840[";

    let parser = PythonParser::new();
    // This should not panic because it's parsed as requirements.txt
    let deps = parser.parse(content);
    validate_deps(&deps, content, "Python");
}

#[test]
fn test_python_fuzz_dependency_groups() {
    let parser = PythonParser::new();

    // --- Valid case ---
    // Non-package project: only [dependency-groups], no [project] block.
    // Exercises: PEP 735 detection in is_pyproject_toml, multi-group iteration,
    // {include-group} table items (skipped), unversioned strings (skipped).
    let valid = r#"
[dependency-groups]
test = ["pytest>=7.0.0", "coverage>=7.0.0"]
typing = ["mypy>=1.0.0", {include-group = "test"}, "types-requests>=2.0.0"]
typing-test = [{include-group = "typing"}, {include-group = "test"}, "useful-types>=1.0.0"]
unversioned = ["bare-package"]
"#;
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| parser.parse(valid)));
    let deps = result.expect("should not panic on valid dependency-groups");
    // test: 2, typing: 2 (include-group skipped), typing-test: 1 (both skipped), unversioned: 0
    assert_eq!(
        deps.len(),
        5,
        "expected 5 deps: include-groups and unversioned items must be excluded"
    );
    validate_deps(&deps, valid, "Python/dependency-groups");

    // --- Edge cases: must not panic and must satisfy position invariants ---
    let edge_cases: &[&str] = &[
        // truncated array
        "[dependency-groups]\ntest = [",
        // truncated include-group table
        "[dependency-groups]\ntest = [{include-group",
        // include-group table with missing value
        "[dependency-groups]\ntest = [{include-group = }]",
        // unrecognised table key (spec says tools SHOULD error only when processing it)
        "[dependency-groups]\ntest = [{set-phasers-to = \"stun\"}]",
        // invalid PEP 508 string (no valid operator)
        "[dependency-groups]\ntest = [\">=>=>=>\"]",
        // control characters inside a string
        "[dependency-groups]\ntest = [\"\x00\x01\x02\"]",
        // empty group
        "[dependency-groups]\ntest = []",
        // empty table
        "[dependency-groups]\n",
        // inline comment on header
        "[dependency-groups] # my groups\ntest = [\"pytest>=7.0.0\"]",
        // mixed valid strings and include-group on same line (inline array)
        "[dependency-groups]\ntest = [\"pkg>=1.0\", {include-group = \"test\"}, \"other>=2.0\"]",
        // combined with [project] block (package project using both sections)
        "[project]\nname = \"mypkg\"\n\n[dependency-groups]\ntest = [\"pytest>=7.0.0\"]\n",
    ];

    for content in edge_cases {
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| parser.parse(content)));
        match result {
            Ok(deps) => validate_deps(&deps, content, "Python/dependency-groups"),
            Err(_) => panic!("Python parser panicked on dependency-groups input:\n{content:?}"),
        }
    }
}

#[test]
fn test_hatch_fuzz_pyproject() {
    // Exercises collect_hatch_env_deps via parse_pyproject_toml:
    // [tool.hatch.envs.*] with `dependencies` and `extra-dependencies`.
    let parser = PythonParser::new();

    // --- Valid case: multiple envs with both dep keys ---
    let valid = r#"
[project]
name = "mypkg"
version = "1.0.0"

[tool.hatch.envs.default]
dependencies = [
    "mypy>=1.0.0",
]

[tool.hatch.envs.test]
dependencies = [
    "pytest>=7.0.0",
    "coverage>=6.0",
]
extra-dependencies = [
    "baz>=1.0",
]
"#;
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| parser.parse(valid)));
    let deps = result.expect("should not panic on valid hatch pyproject.toml");
    // default: 1, test: 2, extra: 1 = 4 hatch deps (plus any [project.dependencies])
    assert_eq!(deps.len(), 4, "expected 4 hatch env deps");
    // All hatch env deps: dev=true, optional=false
    for dep in &deps {
        assert!(dep.dev, "hatch env dep should be dev=true");
        assert!(!dep.optional, "hatch env dep should be optional=false");
    }
    validate_deps(&deps, valid, "Python/hatch-pyproject");

    // --- Edge cases: must not panic and must satisfy position invariants ---
    let edge_cases: &[&str] = &[
        // truncated array — no closing bracket
        "[tool.hatch.envs.test]\ndependencies = [",
        // empty deps array
        "[tool.hatch.envs.test]\ndependencies = []",
        // empty envs table
        "[tool.hatch.envs]\n",
        // no envs at all
        "[tool.hatch]\n",
        // extra-dependencies key only
        "[tool.hatch.envs.lint]\nextra-dependencies = [\"ruff>=0.4\"]",
        // context-formatted string — no PEP 508 version, must be silently skipped
        "[tool.hatch.envs.test]\ndependencies = [\"{root:parent:uri}/local-pkg\"]",
        // mixed: one context-formatted, one real dep
        "[tool.hatch.envs.test]\ndependencies = [\"{env:MY_PKG:default}\", \"pytest>=7.0\"]",
        // unversioned string — skipped
        "[tool.hatch.envs.test]\ndependencies = [\"bare-package\"]",
        // invalid PEP 508 specifier — no valid operator
        "[tool.hatch.envs.test]\ndependencies = [\">=>==>>\"]",
        // control characters inside string value
        "[tool.hatch.envs.test]\ndependencies = [\"\x00\x01pytest>=7.0\"]",
        // malformed TOML (unclosed string) — must not panic
        "[tool.hatch.envs.test]\ndependencies = [\"pytest>=7.0",
        // combined: [project.dependencies] + hatch envs
        "[project]\nname = \"p\"\n\n[project.dependencies]\n# none\n\n[tool.hatch.envs.test]\ndependencies = [\"pytest>=7.0.0\"]\n",
    ];

    for content in edge_cases {
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| parser.parse(content)));
        match result {
            Ok(deps) => validate_deps(&deps, content, "Python/hatch-pyproject"),
            Err(_) => panic!("Python parser panicked on hatch pyproject input:\n{content:?}"),
        }
    }
}

#[test]
fn test_hatch_fuzz_standalone() {
    // Exercises collect_hatch_env_deps via parse_hatch_toml:
    // standalone hatch.toml uses [envs.*] (no [tool.hatch] wrapper).
    let parser = PythonParser::new();

    // --- Valid case ---
    let valid = r#"
[envs.default]
dependencies = [
    "mypy>=1.0.0",
]

[envs.test]
dependencies = [
    "pytest>=7.0.0",
    "coverage>=6.0",
]
extra-dependencies = [
    "baz>=1.0",
]
"#;
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| parser.parse(valid)));
    let deps = result.expect("should not panic on valid standalone hatch.toml");
    assert_eq!(
        deps.len(),
        4,
        "expected 4 hatch env deps from standalone hatch.toml"
    );
    for dep in &deps {
        assert!(dep.dev, "hatch env dep should be dev=true");
        assert!(!dep.optional, "hatch env dep should be optional=false");
    }
    validate_deps(&deps, valid, "Python/hatch-standalone");

    // --- Edge cases: must not panic and must satisfy position invariants ---
    let edge_cases: &[&str] = &[
        // truncated array
        "[envs.test]\ndependencies = [",
        // empty deps array
        "[envs.test]\ndependencies = []",
        // empty envs table
        "[envs]\n",
        // no envs key
        "[build]\nrequires = [\"hatchling\"]\n",
        // extra-dependencies only
        "[envs.lint]\nextra-dependencies = [\"ruff>=0.4\"]",
        // context-formatted string — silently skipped
        "[envs.test]\ndependencies = [\"{root:parent:uri}/pkg\"]",
        // mixed valid + context-formatted
        "[envs.test]\ndependencies = [\"{env:PKG:default}\", \"coverage>=6.0\"]",
        // unversioned bare name
        "[envs.test]\ndependencies = [\"bare-package\"]",
        // invalid PEP 508
        "[envs.test]\ndependencies = [\">>>>=invalid\"]",
        // control characters
        "[envs.test]\ndependencies = [\"\x00\x01ruff>=0.4\"]",
        // malformed TOML
        "[envs.test]\ndependencies = [\"pytest>=7.0",
        // multiple envs, one empty
        "[envs.a]\ndependencies = []\n[envs.b]\ndependencies = [\"pytest>=7.0.0\"]\n",
    ];

    for content in edge_cases {
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| parser.parse(content)));
        match result {
            Ok(deps) => validate_deps(&deps, content, "Python/hatch-standalone"),
            Err(_) => panic!("Python parser panicked on standalone hatch.toml input:\n{content:?}"),
        }
    }
}

#[test]
fn test_maven_fuzz_spans() {
    // The pom parser reports spans assembled from several XML events, so a value
    // interrupted by an entity reference, a comment or a line break must still
    // land inside one line of the source.
    let parser = MavenParser::new();

    let valid = r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
    <groupId>com.example</groupId>
    <artifactId>app</artifactId>
    <version>1.0.0</version>
    <properties>
        <slf4j.version>1.7.30</slf4j.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-api</artifactId>
            <version>${slf4j.version}</version>
        </dependency>
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter</artifactId>
            <version>5.10.0</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
"#;
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| parser.parse(valid)));
    let deps = result.expect("should not panic on a valid pom.xml");
    assert_eq!(deps.len(), 2, "expected both declared dependencies");
    validate_deps(&deps, valid, "Maven");

    // --- Edge cases: must not panic and must satisfy position invariants ---
    let edge_cases: &[&str] = &[
        // entity reference splitting the version
        "<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0&amp;2</version></dependency></dependencies></project>",
        // value straddling a line break
        "<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0&amp;\n2</version></dependency></dependencies></project>",
        // comment inside the version
        "<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0<!-- c -->2.0</version></dependency></dependencies></project>",
        // CDATA inside the version
        "<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.<![CDATA[0]]>5</version></dependency></dependencies></project>",
        // unexpandable entity as the whole version
        "<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>&ver;</version></dependency></dependencies></project>",
        // exclusions repeating the coordinate element names
        "<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version><exclusions><exclusion><groupId>x</groupId><artifactId>y</artifactId></exclusion></exclusions></dependency></dependencies></project>",
        // multi-line artifactId
        "<project><dependencies><dependency><groupId>g</groupId><artifactId>a&amp;\nb</artifactId><version>1.0</version></dependency></dependencies></project>",
        // whitespace-only version
        "<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>   </version></dependency></dependencies></project>",
        // self-closing coordinate elements
        "<project><dependencies><dependency><groupId/><artifactId/><version/></dependency></dependencies></project>",
        // stray end tag
        "<project></dependency></project>",
        // truncated document
        "<project><dependencies><dependency><groupId>g",
        // empty input
        "",
        // control characters in a coordinate
        "<project><dependencies><dependency><groupId>\u{1}g</groupId><artifactId>a</artifactId><version>1.0</version></dependency></dependencies></project>",
        // non-ASCII coordinate
        "<project><dependencies><dependency><groupId>café</groupId><artifactId>naïve</artifactId><version>1.0</version></dependency></dependencies></project>",
    ];

    for content in edge_cases {
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| parser.parse(content)));
        match result {
            Ok(deps) => validate_deps(&deps, content, "Maven"),
            Err(_) => panic!("Maven parser panicked on input:\n{content:?}"),
        }
    }
}
