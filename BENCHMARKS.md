# Benchmarks

This project uses [Criterion](https://github.com/bheisler/criterion.rs) for benchmarking.

## Running Benchmarks

### All Benchmarks

```bash
cargo bench --package depsy-lsp --bench benchmarks
```

### Specific Benchmark Group

```bash
# Parser benchmarks only
cargo bench --package depsy-lsp --bench benchmarks -- parsers

# Cache benchmarks only
cargo bench --package depsy-lsp --bench benchmarks -- cache

# Version utils benchmarks only
cargo bench --package depsy-lsp --bench benchmarks -- version
```

### Save Baseline for Comparison

```bash
# Save current results as baseline
cargo bench --package depsy-lsp --bench benchmarks -- --save-baseline main

# Compare against saved baseline
cargo bench --package depsy-lsp --bench benchmarks -- --baseline main
```

### Using the Helper Script

```bash
./run-benchmarks.sh              # Run all benchmarks
./run-benchmarks.sh parsers      # Run parser benchmarks only
./run-benchmarks.sh --baseline   # Save results as baseline
./run-benchmarks.sh --compare    # Compare against baseline
```

## Benchmark Suites

### Parsing Benchmarks (`parsers`)

Measures parsing performance for all supported dependency file formats at different scales (10, 50, 100 dependencies).

| Benchmark | Description |
|-----------|-------------|
| `cargo_toml/{N}` | Parse Cargo.toml with N dependencies |
| `package_json/{N}` | Parse package.json with N dependencies |
| `requirements_txt/{N}` | Parse requirements.txt with N dependencies |
| `go_mod/{N}` | Parse go.mod with N dependencies |
| `composer_json/{N}` | Parse composer.json with N dependencies |
| `csproj/{N}` | Parse .csproj (NuGet) with N dependencies |
| `pubspec_yaml/{N}` | Parse pubspec.yaml (Dart) with N dependencies |
| `gemfile/{N}` | Parse Gemfile (Ruby) with N dependencies |

### Cache Benchmarks (`cache`)

Measures cache operations at different entry counts (100, 1000, 10000 for memory; 100, 1000 for SQLite).

| Benchmark | Description |
|-----------|-------------|
| `cache/memory/get_hit/{N}` | Memory cache hit with N entries |
| `cache/memory/get_miss/{N}` | Memory cache miss with N entries |
| `cache/memory/insert/{N}` | Memory cache insert with N entries |
| `cache/sqlite/get_hit/{N}` | SQLite cache hit with N entries |
| `cache/sqlite/get_miss/{N}` | SQLite cache miss with N entries |
| `cache/sqlite/insert/{N}` | SQLite cache insert with N entries |

### Version Utils Benchmarks (`version_utils`)

Measures prerelease detection performance across all supported ecosystems.

| Benchmark | Description |
|-----------|-------------|
| `is_prerelease/rust` | Rust prerelease detection (10 versions) |
| `is_prerelease/npm` | npm prerelease detection (10 versions) |
| `is_prerelease/python` | Python prerelease detection (10 versions) |
| `is_prerelease/go` | Go prerelease detection (10 versions) |
| `is_prerelease/php` | PHP prerelease detection (10 versions) |
| `is_prerelease/dart` | Dart prerelease detection (10 versions) |
| `is_prerelease/nuget` | NuGet prerelease detection (10 versions) |

### VersionInfo Benchmarks (`version_info`)

Measures operations on the `VersionInfo` struct.

| Benchmark | Description |
|-----------|-------------|
| `is_version_yanked_hit` | Yanked check with hit (100 yanked versions) |
| `is_version_yanked_miss` | Yanked check with miss (100 yanked versions) |
| `is_version_yanked_with_prefix` | Yanked check with version prefix (^, ~) |

## Performance Targets

Based on typical usage patterns:

| Operation | Target | Rationale |
|-----------|--------|-----------|
| Parse 50-dep Cargo.toml | <5ms | Should be instant for user |
| Parse 100-dep package.json | <10ms | Larger files still fast |
| Memory cache hit | <1µs | HashMap lookup is O(1) |
| Memory cache miss | <1µs | HashMap lookup is O(1) |
| SQLite cache hit | <500µs | Connection pool + query |
| SQLite cache miss | <500µs | Connection pool + query |
| Prerelease detection (10 versions) | <1µs | Simple string operations |

## Viewing Results

After running benchmarks, HTML reports are generated at:

```
target/criterion/report/index.html
```

Reports include:
- Performance distribution plots
- Comparison with previous runs
- Statistical analysis
- Regression detection

## CI Integration

Benchmarks can be integrated into CI workflows. See `.github/workflows/benchmarks.yml` for an example configuration that:
- Runs benchmarks on push/PR to main
- Stores results as artifacts
- Compares against baseline

## References

- [Criterion.rs documentation](https://bheisler.github.io/criterion.rs/book/index.html)
- [Benchmarking best practices](https://nnethercote.github.io/perf-book/)
