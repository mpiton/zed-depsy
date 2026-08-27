# Performance Profiling

This document describes how to profile depsy-lsp using cargo-flamegraph to identify performance bottlenecks and validate optimizations.

## Installation

Install flamegraph globally:

```bash
cargo install flamegraph
```

On Linux, you also need `perf`:

```bash
# Ubuntu/Debian
sudo apt-get install linux-tools-common linux-tools-generic

# Fedora
sudo dnf install perf
```

## CLI Profiling Commands

The LSP binary includes built-in profiling commands that can be used standalone or with flamegraph:

### Profile Parse Operations

Profile the parsing of dependency files:

```bash
# Direct execution (outputs timing info)
./target/release/depsy-lsp profile-parse \
    --file tests/fixtures/cargo_50_deps.toml \
    --iterations 1000

# With flamegraph
flamegraph -o flamegraph-parse.svg -- \
    ./target/release/depsy-lsp profile-parse \
    --file tests/fixtures/cargo_50_deps.toml \
    --iterations 1000
```

### Profile Registry Requests

Profile fetching package info from registries:

```bash
# Direct execution
./target/release/depsy-lsp profile-registry \
    --registry npm \
    --packages "lodash,express,react,axios" \
    --iterations 5

# Supported registries: crates, npm, pypi, go, packagist, pub-dev, nuget, rubygems
```

### Profile Full Workflow

Profile the complete document processing workflow (parse + registry + vulnerabilities):

```bash
./target/release/depsy-lsp profile-full \
    --file tests/fixtures/package_100_deps.json \
    --iterations 5
```

## Profiling Scripts

Convenience scripts are provided in the `scripts/` directory:

```bash
# Profile parsing operations
./scripts/profile-parse.sh tests/fixtures/cargo_50_deps.toml 1000

# Profile registry requests
./scripts/profile-registry.sh npm "lodash,express,react" 5

# Profile full workflow
./scripts/profile-full.sh tests/fixtures/package_100_deps.json 5
```

These scripts automatically:
- Build the release binary
- Generate flame graphs as SVG files
- Open the flame graph in your browser (on Linux/macOS)

## Test Fixtures

Pre-built test fixtures are provided for consistent profiling:

| File | Description |
|------|-------------|
| `tests/fixtures/cargo_50_deps.toml` | Cargo.toml with 50 dependencies |
| `tests/fixtures/package_100_deps.json` | package.json with 100 dependencies |

## Reading Flame Graphs

Flame graphs visualize where CPU time is spent:

- **Width**: Represents time spent in that function
- **Height**: Represents call stack depth
- **Color**: Differentiates function calls (no semantic meaning)

### What to Look For

1. **Wide boxes**: Functions consuming significant CPU time
2. **Repeated patterns**: Code paths called frequently
3. **Deep stacks**: Functions with many nested calls

### Common Bottlenecks

Based on typical LSP workloads:

| Area | Typical Bottleneck | Mitigation |
|------|-------------------|------------|
| Parsing | Regex/TOML parsing | Use faster parsers, cache AST |
| HTTP | Network I/O | Parallel requests, connection pooling |
| Version comparison | Semver parsing | Memoization, native parsing |
| Cache | SQLite I/O | In-memory cache, batch queries |
| JSON | Serde deserialization | Streaming, partial parsing |

## Expected Performance

Baseline performance targets for the LSP:

| Operation | Target | Notes |
|-----------|--------|-------|
| Parse 50-dep Cargo.toml | <10ms | Should feel instant |
| Parse 100-dep package.json | <15ms | Larger files still fast |
| Fetch 10 packages (parallel) | <2s | Network-bound |
| Vulnerability check (batch) | <1s | Single API call |

## CI Workflow

A GitHub Actions workflow is available for manual profiling runs:

1. Go to **Actions** > **Performance Profiling**
2. Click **Run workflow**
3. Select profile type and iterations
4. View results in the workflow summary

Note: Flame graphs are not generated in CI due to container limitations with `perf`. Use the profiling scripts locally for flame graph generation.

## Best Practices

### Before Optimizing

1. **Profile first**: Measure before optimizing
2. **Use realistic workloads**: Profile actual usage patterns
3. **Multiple runs**: Run profile 3-5 times for consistency
4. **Compare baselines**: Always compare to baseline metrics

### During Optimization

1. **Focus on hot spots**: Optimize widest boxes in flame graph
2. **One change at a time**: Measure impact of each change
3. **Re-profile after**: Verify improvement with new flame graph

### After Optimization

1. **Document results**: Note performance improvements
2. **Update baselines**: Keep current metrics
3. **Watch for regressions**: Profile after major changes

## Troubleshooting

### "perf not found" Error

Install perf for your Linux distribution (see Installation section).

### "Permission denied" on perf

You may need to adjust perf permissions:

```bash
# Temporary (current session)
sudo sysctl -w kernel.perf_event_paranoid=-1

# Or run flamegraph with sudo
sudo flamegraph -o output.svg -- ./target/release/depsy-lsp ...
```

### Flame graph is mostly "unknown"

Build with debug symbols:

```bash
CARGO_PROFILE_RELEASE_DEBUG=true cargo build --release --package depsy-lsp
```

## References

- [cargo-flamegraph](https://github.com/flamegraph-rs/flamegraph)
- [Flame Graphs by Brendan Gregg](https://www.brendangregg.com/flamegraphs.html)
- [The Rust Performance Book](https://nnethercote.github.io/perf-book/)
