//! Benchmark suite for depsy-lsp
//!
//! Run with: `cargo bench --bench benchmarks`
//! View report: `open target/criterion/report/index.html`

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use depsy_lsp::cache::sqlite::SqliteCacheConfig;
use depsy_lsp::cache::{MemoryCache, ReadCache, SqliteCache, WriteCache};
use depsy_lsp::parsers::Parser;
use depsy_lsp::parsers::cargo::CargoParser;
use depsy_lsp::parsers::csharp::CsharpParser;
use depsy_lsp::parsers::dart::DartParser;
use depsy_lsp::parsers::go::GoParser;
use depsy_lsp::parsers::npm::NpmParser;
use depsy_lsp::parsers::php::PhpParser;
use depsy_lsp::parsers::python::PythonParser;
use depsy_lsp::parsers::ruby::RubyParser;
use depsy_lsp::registries::VersionInfo;
use depsy_lsp::registries::version_utils::{
    is_prerelease_dart, is_prerelease_go, is_prerelease_npm, is_prerelease_nuget,
    is_prerelease_php, is_prerelease_python, is_prerelease_rust,
};

// =============================================================================
// Test Data Generation
// =============================================================================

fn generate_cargo_toml(dep_count: usize) -> String {
    let mut content = String::from(
        r#"[package]
name = "test-project"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    );

    let deps = [
        ("serde", "1.0"),
        ("tokio", "1.0"),
        ("reqwest", "0.12"),
        ("anyhow", "1.0"),
        ("thiserror", "2.0"),
        ("tracing", "0.1"),
        ("dashmap", "6.1"),
        ("chrono", "0.4"),
        ("semver", "1.0"),
        ("toml", "0.9"),
        ("serde_json", "1.0"),
        ("futures", "0.3"),
        ("clap", "4.5"),
        ("tower-lsp", "0.20"),
        ("rusqlite", "0.38"),
        ("r2d2", "0.8"),
        ("dirs", "6"),
        ("serde_yaml", "0.9"),
        ("taplo", "0.14"),
        ("regex", "1.0"),
    ];

    for i in 0..dep_count {
        let (name, version) = deps[i % deps.len()];
        let suffix = if i >= deps.len() {
            format!("-{}", i / deps.len())
        } else {
            String::new()
        };
        content.push_str(&format!("{name}{suffix} = \"{version}\"\n"));
    }

    content
}

fn generate_package_json(dep_count: usize) -> String {
    let deps = [
        ("express", "^4.18.0"),
        ("react", "^18.2.0"),
        ("typescript", "^5.0.0"),
        ("@types/node", "^20.0.0"),
        ("lodash", "^4.17.0"),
        ("axios", "^1.6.0"),
        ("webpack", "^5.90.0"),
        ("eslint", "^8.56.0"),
        ("prettier", "^3.2.0"),
        ("jest", "^29.7.0"),
        ("@babel/core", "^7.23.0"),
        ("dotenv", "^16.4.0"),
        ("uuid", "^9.0.0"),
        ("moment", "^2.30.0"),
        ("commander", "^12.0.0"),
        ("chalk", "^5.3.0"),
        ("inquirer", "^9.2.0"),
        ("ora", "^8.0.0"),
        ("glob", "^10.3.0"),
        ("fs-extra", "^11.2.0"),
    ];

    let mut dep_str = String::new();
    for i in 0..dep_count {
        let (name, version) = deps[i % deps.len()];
        let suffix = if i >= deps.len() {
            format!("-{}", i / deps.len())
        } else {
            String::new()
        };
        if i > 0 {
            dep_str.push_str(",\n    ");
        }
        dep_str.push_str(&format!("\"{name}{suffix}\": \"{version}\""));
    }

    format!(
        r#"{{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {{
    {dep_str}
  }}
}}"#
    )
}

fn generate_requirements_txt(dep_count: usize) -> String {
    let deps = [
        ("requests", "==2.31.0"),
        ("flask", ">=2.3.0"),
        ("django", "~=4.2"),
        ("numpy", ">=1.26.0"),
        ("pandas", ">=2.1.0"),
        ("pytest", ">=7.4.0"),
        ("black", ">=24.1.0"),
        ("mypy", ">=1.8.0"),
        ("fastapi", ">=0.109.0"),
        ("uvicorn", ">=0.27.0"),
        ("sqlalchemy", ">=2.0.0"),
        ("celery", ">=5.3.0"),
        ("redis", ">=5.0.0"),
        ("boto3", ">=1.34.0"),
        ("httpx", ">=0.26.0"),
        ("pydantic", ">=2.5.0"),
        ("aiohttp", ">=3.9.0"),
        ("pillow", ">=10.2.0"),
        ("cryptography", ">=42.0.0"),
        ("python-dotenv", ">=1.0.0"),
    ];

    let mut content = String::new();
    for i in 0..dep_count {
        let (name, version) = deps[i % deps.len()];
        let suffix = if i >= deps.len() {
            format!("-{}", i / deps.len())
        } else {
            String::new()
        };
        content.push_str(&format!("{name}{suffix}{version}\n"));
    }

    content
}

fn generate_go_mod(dep_count: usize) -> String {
    let deps = [
        ("github.com/gin-gonic/gin", "v1.9.1"),
        ("github.com/spf13/cobra", "v1.8.0"),
        ("github.com/spf13/viper", "v1.18.2"),
        ("go.uber.org/zap", "v1.26.0"),
        ("github.com/stretchr/testify", "v1.8.4"),
        ("github.com/gorilla/mux", "v1.8.1"),
        ("google.golang.org/grpc", "v1.61.0"),
        ("github.com/go-redis/redis/v8", "v8.11.5"),
        ("gorm.io/gorm", "v1.25.6"),
        ("github.com/sirupsen/logrus", "v1.9.3"),
    ];

    let mut content = String::from(
        r#"module example.com/test

go 1.21

require (
"#,
    );

    for i in 0..dep_count {
        let (path, version) = deps[i % deps.len()];
        let suffix = if i >= deps.len() {
            format!("{}", i / deps.len())
        } else {
            String::new()
        };
        content.push_str(&format!("\t{path}{suffix} {version}\n"));
    }

    content.push_str(")\n");
    content
}

fn generate_composer_json(dep_count: usize) -> String {
    let deps = [
        ("laravel/framework", "^10.0"),
        ("symfony/console", "^6.4"),
        ("guzzlehttp/guzzle", "^7.8"),
        ("monolog/monolog", "^3.5"),
        ("doctrine/orm", "^2.17"),
        ("phpunit/phpunit", "^10.5"),
        ("league/flysystem", "^3.23"),
        ("aws/aws-sdk-php", "^3.298"),
        ("predis/predis", "^2.2"),
        ("ramsey/uuid", "^4.7"),
    ];

    let mut dep_str = String::new();
    for i in 0..dep_count {
        let (name, version) = deps[i % deps.len()];
        let suffix = if i >= deps.len() {
            format!("-{}", i / deps.len())
        } else {
            String::new()
        };
        if i > 0 {
            dep_str.push_str(",\n    ");
        }
        dep_str.push_str(&format!("\"{name}{suffix}\": \"{version}\""));
    }

    format!(
        r#"{{
  "name": "test/project",
  "require": {{
    {dep_str}
  }}
}}"#
    )
}

fn generate_csproj(dep_count: usize) -> String {
    let deps = [
        ("Newtonsoft.Json", "13.0.3"),
        ("Microsoft.Extensions.Logging", "8.0.0"),
        ("AutoMapper", "12.0.1"),
        ("Dapper", "2.1.28"),
        ("Serilog", "3.1.1"),
        ("FluentValidation", "11.9.0"),
        ("MediatR", "12.2.0"),
        ("Polly", "8.2.1"),
        ("StackExchange.Redis", "2.7.10"),
        ("Swashbuckle.AspNetCore", "6.5.0"),
    ];

    let mut pkg_refs = String::new();
    for i in 0..dep_count {
        let (name, version) = deps[i % deps.len()];
        let suffix = if i >= deps.len() {
            format!("{}", i / deps.len())
        } else {
            String::new()
        };
        pkg_refs.push_str(&format!(
            "    <PackageReference Include=\"{name}{suffix}\" Version=\"{version}\" />\n"
        ));
    }

    format!(
        r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
{pkg_refs}  </ItemGroup>
</Project>"#
    )
}

fn generate_pubspec_yaml(dep_count: usize) -> String {
    let deps = [
        ("flutter", "sdk: flutter"),
        ("http", "^1.2.0"),
        ("provider", "^6.1.1"),
        ("shared_preferences", "^2.2.2"),
        ("dio", "^5.4.0"),
        ("get_it", "^7.6.7"),
        ("bloc", "^8.1.3"),
        ("equatable", "^2.0.5"),
        ("json_annotation", "^4.8.1"),
        ("intl", "^0.19.0"),
    ];

    let mut content = String::from(
        r#"name: test_project
version: 1.0.0

environment:
  sdk: ">=3.0.0 <4.0.0"

dependencies:
"#,
    );

    for i in 0..dep_count {
        let (name, version) = deps[i % deps.len()];
        if name == "flutter" {
            continue;
        }
        let suffix = if i >= deps.len() {
            format!("_{}", i / deps.len())
        } else {
            String::new()
        };
        content.push_str(&format!("  {name}{suffix}: {version}\n"));
    }

    content
}

fn generate_gemfile(dep_count: usize) -> String {
    let deps = [
        ("rails", "~> 7.1.0"),
        ("pg", "~> 1.5"),
        ("puma", "~> 6.4"),
        ("redis", "~> 5.0"),
        ("sidekiq", "~> 7.2"),
        ("devise", "~> 4.9"),
        ("pundit", "~> 2.3"),
        ("ransack", "~> 4.1"),
        ("pagy", "~> 6.4"),
        ("rspec-rails", "~> 6.1"),
    ];

    let mut content = String::from("source 'https://rubygems.org'\n\n");

    for i in 0..dep_count {
        let (name, version) = deps[i % deps.len()];
        let suffix = if i >= deps.len() {
            format!("-{}", i / deps.len())
        } else {
            String::new()
        };
        content.push_str(&format!("gem '{name}{suffix}', '{version}'\n"));
    }

    content
}

fn create_version_info() -> VersionInfo {
    VersionInfo {
        latest: Some("1.0.0".to_string()),
        latest_prerelease: Some("2.0.0-beta.1".to_string()),
        versions: vec![
            "0.1.0".to_string(),
            "0.2.0".to_string(),
            "0.3.0".to_string(),
            "1.0.0".to_string(),
            "2.0.0-beta.1".to_string(),
        ],
        description: Some("A test package".to_string()),
        homepage: Some("https://example.com".to_string()),
        repository: Some("https://github.com/test/test".to_string()),
        license: Some("MIT".to_string()),
        vulnerabilities: vec![],
        deprecated: false,
        yanked: false,
        yanked_versions: vec!["0.1.0".to_string(), "0.2.0".to_string()],
        release_dates: Default::default(),
        transitive_vulnerabilities: vec![],
    }
}

// =============================================================================
// Parsing Benchmarks
// =============================================================================

fn bench_parsers(c: &mut Criterion) {
    let mut group = c.benchmark_group("parsers");

    for dep_count in [10, 50, 100] {
        // Cargo.toml
        let cargo_content = generate_cargo_toml(dep_count);
        let cargo_parser = CargoParser::new();
        group.bench_with_input(
            BenchmarkId::new("cargo_toml", dep_count),
            &cargo_content,
            |b, content| {
                b.iter(|| cargo_parser.parse(black_box(content)));
            },
        );

        // package.json
        let npm_content = generate_package_json(dep_count);
        let npm_parser = NpmParser::new();
        group.bench_with_input(
            BenchmarkId::new("package_json", dep_count),
            &npm_content,
            |b, content| {
                b.iter(|| npm_parser.parse(black_box(content)));
            },
        );

        // requirements.txt
        let python_content = generate_requirements_txt(dep_count);
        let python_parser = PythonParser::new();
        group.bench_with_input(
            BenchmarkId::new("requirements_txt", dep_count),
            &python_content,
            |b, content| {
                b.iter(|| python_parser.parse(black_box(content)));
            },
        );

        // go.mod
        let go_content = generate_go_mod(dep_count);
        let go_parser = GoParser::new();
        group.bench_with_input(
            BenchmarkId::new("go_mod", dep_count),
            &go_content,
            |b, content| {
                b.iter(|| go_parser.parse(black_box(content)));
            },
        );

        // composer.json
        let php_content = generate_composer_json(dep_count);
        let php_parser = PhpParser::new();
        group.bench_with_input(
            BenchmarkId::new("composer_json", dep_count),
            &php_content,
            |b, content| {
                b.iter(|| php_parser.parse(black_box(content)));
            },
        );

        // .csproj
        let csharp_content = generate_csproj(dep_count);
        let csharp_parser = CsharpParser::new();
        group.bench_with_input(
            BenchmarkId::new("csproj", dep_count),
            &csharp_content,
            |b, content| {
                b.iter(|| csharp_parser.parse(black_box(content)));
            },
        );

        // pubspec.yaml
        let dart_content = generate_pubspec_yaml(dep_count);
        let dart_parser = DartParser::new();
        group.bench_with_input(
            BenchmarkId::new("pubspec_yaml", dep_count),
            &dart_content,
            |b, content| {
                b.iter(|| dart_parser.parse(black_box(content)));
            },
        );

        // Gemfile
        let ruby_content = generate_gemfile(dep_count);
        let ruby_parser = RubyParser::new();
        group.bench_with_input(
            BenchmarkId::new("gemfile", dep_count),
            &ruby_content,
            |b, content| {
                b.iter(|| ruby_parser.parse(black_box(content)));
            },
        );
    }

    group.finish();
}

// =============================================================================
// Cache Benchmarks
// =============================================================================

fn bench_memory_cache(c: &mut Criterion) {
    use tokio::runtime::Runtime;

    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("cache/memory");

    for entry_count in [100, 1000, 10000] {
        let cache = MemoryCache::new();

        // Pre-populate cache
        for i in 0..entry_count {
            let info = create_version_info();
            rt.block_on(cache.insert(format!("package_{i}"), info));
        }

        // Use a key guaranteed to exist for the current parameter set so the
        // benchmark always exercises the hit path (`package_500` is missing
        // when `entry_count == 100`).
        let hit_key = format!("package_{}", entry_count / 2);

        group.bench_with_input(
            BenchmarkId::new("get_hit", entry_count),
            &cache,
            |b, cache| {
                b.iter(|| {
                    black_box(rt.block_on(cache.get(&hit_key)));
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("get_miss", entry_count),
            &cache,
            |b, cache| {
                b.iter(|| {
                    black_box(rt.block_on(cache.get("nonexistent_package")));
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("insert", entry_count),
            &cache,
            |b, cache| {
                let mut i = entry_count;
                b.iter(|| {
                    rt.block_on(cache.insert(format!("new_package_{i}"), create_version_info()));
                    i += 1;
                });
            },
        );
    }

    group.finish();
}

fn bench_sqlite_cache(c: &mut Criterion) {
    use std::path::PathBuf;
    use tokio::runtime::Runtime;

    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("cache/sqlite");

    // Use a temporary file for benchmarks since in_memory() is cfg(test) only
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join("depsy_bench_cache.db");

    // Clean up any existing benchmark database
    let _ = std::fs::remove_file(&db_path);

    let config = SqliteCacheConfig::default();
    let cache = SqliteCache::with_path_and_config(db_path.clone(), config)
        .expect("Failed to create SQLite cache for benchmarks");

    for entry_count in [100, 1000] {
        // Clear and pre-populate cache
        rt.block_on(cache.clear());
        for i in 0..entry_count {
            let info = create_version_info();
            rt.block_on(cache.insert(format!("package_{i}"), info));
        }

        // Use a key guaranteed to exist for the current parameter set so the
        // benchmark always exercises the hit path.
        let hit_key = format!("package_{}", entry_count / 2);

        group.bench_with_input(
            BenchmarkId::new("get_hit", entry_count),
            &entry_count,
            |b, _| {
                b.iter(|| {
                    black_box(rt.block_on(cache.get(&hit_key)));
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("get_miss", entry_count),
            &entry_count,
            |b, _| {
                b.iter(|| {
                    black_box(rt.block_on(cache.get("nonexistent_package")));
                });
            },
        );

        let mut insert_counter = entry_count;
        group.bench_with_input(
            BenchmarkId::new("insert", entry_count),
            &entry_count,
            |b, _| {
                b.iter(|| {
                    rt.block_on(cache.insert(
                        format!("new_package_{insert_counter}"),
                        create_version_info(),
                    ));
                    insert_counter += 1;
                });
            },
        );
    }

    group.finish();

    // Clean up
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(PathBuf::from(format!("{}-wal", db_path.display())));
    let _ = std::fs::remove_file(PathBuf::from(format!("{}-shm", db_path.display())));
}

// =============================================================================
// Version Utils Benchmarks
// =============================================================================

fn bench_prerelease_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("version_utils/is_prerelease");

    let versions = vec![
        "1.0.0",
        "2.0.0-alpha.1",
        "3.0.0-beta",
        "4.0.0-rc.1",
        "5.0.0",
        "1.0.0-canary.123",
        "2.0.0.dev1",
        "3.0.0-preview",
        "4.0.0a1",
        "5.0.0b2",
    ];

    group.bench_function("rust", |b| {
        b.iter(|| {
            for v in &versions {
                black_box(is_prerelease_rust(v));
            }
        });
    });

    group.bench_function("npm", |b| {
        b.iter(|| {
            for v in &versions {
                black_box(is_prerelease_npm(v));
            }
        });
    });

    group.bench_function("python", |b| {
        b.iter(|| {
            for v in &versions {
                black_box(is_prerelease_python(v));
            }
        });
    });

    group.bench_function("go", |b| {
        b.iter(|| {
            for v in &versions {
                black_box(is_prerelease_go(v));
            }
        });
    });

    group.bench_function("php", |b| {
        b.iter(|| {
            for v in &versions {
                black_box(is_prerelease_php(v));
            }
        });
    });

    group.bench_function("dart", |b| {
        b.iter(|| {
            for v in &versions {
                black_box(is_prerelease_dart(v));
            }
        });
    });

    group.bench_function("nuget", |b| {
        b.iter(|| {
            for v in &versions {
                black_box(is_prerelease_nuget(v));
            }
        });
    });

    group.finish();
}

fn bench_version_info(c: &mut Criterion) {
    let mut group = c.benchmark_group("version_info");

    let info = VersionInfo {
        yanked_versions: (0..100).map(|i| format!("1.0.{i}")).collect(),
        ..Default::default()
    };

    group.bench_function("is_version_yanked_hit", |b| {
        b.iter(|| {
            black_box(info.is_version_yanked("1.0.50"));
        });
    });

    group.bench_function("is_version_yanked_miss", |b| {
        b.iter(|| {
            black_box(info.is_version_yanked("2.0.0"));
        });
    });

    group.bench_function("is_version_yanked_with_prefix", |b| {
        b.iter(|| {
            black_box(info.is_version_yanked("^1.0.50"));
        });
    });

    group.finish();
}

// =============================================================================
// Criterion Configuration
// =============================================================================

criterion_group!(
    benches,
    bench_parsers,
    bench_memory_cache,
    bench_sqlite_cache,
    bench_prerelease_detection,
    bench_version_info,
);

criterion_main!(benches);
