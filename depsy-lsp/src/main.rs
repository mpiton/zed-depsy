use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use clap::{Parser, Subcommand, ValueEnum};
use tower_lsp::{LspService, Server};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use depsy_lsp::backend::DepsyBackend;

#[derive(Parser)]
#[command(name = "depsy-lsp")]
#[command(about = "Language server for dependency management", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RegistryType {
    Crates,
    Npm,
    Pypi,
    Go,
    Packagist,
    PubDev,
    Nuget,
    Rubygems,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum OutputFormat {
    #[default]
    Summary,
    Json,
    Markdown,
    Html,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the LSP server (default behavior)
    Lsp,
    /// Scan a file for vulnerabilities and exit with code 1 if found
    Scan {
        /// Path to the dependency file to scan
        #[arg(short, long)]
        file: PathBuf,

        /// Output format: summary, json, markdown, or html
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Summary)]
        output: OutputFormat,

        /// Minimum severity level to report (low, medium, high, critical)
        #[arg(short, long, default_value = "low")]
        min_severity: String,

        /// Exit with code 1 if vulnerabilities are found
        #[arg(long, default_value = "true")]
        fail_on_vulns: bool,

        /// Disable lockfile-based scanning (enabled by default).
        #[arg(long = "no-use-lockfile", action = clap::ArgAction::SetTrue)]
        no_use_lockfile: bool,
    },
    /// Profile dependency file parsing (for use with cargo-flamegraph)
    ProfileParse {
        /// Path to the dependency file to parse
        #[arg(short, long)]
        file: PathBuf,

        /// Number of iterations (for meaningful profiling, must be >= 1)
        #[arg(short, long, default_value = "1000", value_parser = clap::value_parser!(u32).range(1..))]
        iterations: u32,
    },
    /// Profile registry requests (for use with cargo-flamegraph)
    ProfileRegistry {
        /// Registry type to profile
        #[arg(short, long)]
        registry: RegistryType,

        /// Packages to fetch (comma-separated)
        #[arg(short, long)]
        packages: String,

        /// Number of iterations (1-100, to prevent excessive network requests)
        #[arg(short, long, default_value = "10", value_parser = clap::value_parser!(u32).range(1..=100))]
        iterations: u32,

        /// Enable verbose output (may affect timing accuracy)
        #[arg(short, long)]
        verbose: bool,
    },
    /// Profile full document processing workflow (for use with cargo-flamegraph)
    ProfileFull {
        /// Path to the dependency file to process
        #[arg(short, long)]
        file: PathBuf,

        /// Number of iterations (1-100, to prevent excessive network requests)
        #[arg(short, long, default_value = "10", value_parser = clap::value_parser!(u32).range(1..=100))]
        iterations: u32,

        /// Enable verbose output (may affect timing accuracy)
        #[arg(short, long)]
        verbose: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(std::io::stderr),
        )
        .init();

    match cli.command {
        Some(Commands::Scan {
            file,
            output,
            min_severity,
            fail_on_vulns,
            no_use_lockfile,
        }) => run_scan(file, output, min_severity, fail_on_vulns, !no_use_lockfile).await,
        Some(Commands::ProfileParse { file, iterations }) => {
            run_profile_parse(file, iterations).await
        }
        Some(Commands::ProfileRegistry {
            registry,
            packages,
            iterations,
            verbose,
        }) => run_profile_registry(registry, packages, iterations, verbose).await,
        Some(Commands::ProfileFull {
            file,
            iterations,
            verbose,
        }) => run_profile_full(file, iterations, verbose).await,
        Some(Commands::Lsp) | None => {
            run_lsp().await;
            ExitCode::SUCCESS
        }
    }
}

async fn run_lsp() {
    tracing::info!("Starting Depsy LSP server");

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(DepsyBackend::new);
    Server::new(stdin, stdout, socket).serve(service).await;
}

fn print_markdown_entry(
    package: &str,
    version: &str,
    id: &str,
    severity: &str,
    description: &str,
    url: Option<&str>,
    via: Option<&str>,
) {
    let icon = match severity {
        "critical" => "⚠",
        "high" => "▲",
        "medium" => "●",
        _ => "○",
    };
    match via {
        Some(parent) => println!("### {package}@{version} — via `{parent}`\n"),
        None => println!("### {package}@{version}\n"),
    }
    let sev_upper = severity.to_uppercase();
    if let Some(url) = url {
        println!("- **[{id}]({url})** ({icon} {sev_upper}): {description}\n");
    } else {
        println!("- **{id}** ({icon} {sev_upper}): {description}\n");
    }
}

fn canonical_name(eco: depsy_lsp::vulnerabilities::Ecosystem, name: &str) -> String {
    use depsy_lsp::parsers::{
        composer_lock::normalize_composer_name, gemfile_lock::normalize_gem_name,
        python_lock::normalize_python_name,
    };
    use depsy_lsp::vulnerabilities::Ecosystem;
    match eco {
        Ecosystem::PyPI => normalize_python_name(name),
        Ecosystem::Packagist => normalize_composer_name(name),
        Ecosystem::RubyGems => normalize_gem_name(name),
        _ => name.to_string(),
    }
}

async fn run_scan(
    file: PathBuf,
    output: OutputFormat,
    min_severity: String,
    fail_on_vulns: bool,
    use_lockfile: bool,
) -> ExitCode {
    use depsy_lsp::parsers::{
        Parser, cargo::CargoParser, cargo_lock, composer_lock, csharp::CsharpParser,
        dart::DartParser, gemfile_lock, go::GoParser, lockfile_graph::LockfileGraph,
        lockfile_graph::LockfilePackage, lockfile_graph::read_lockfile_capped, maven::MavenParser,
        npm::NpmParser, npm_lock, php::PhpParser, pnpm_workspace, python::PythonParser,
        python_lock, ruby::RubyParser,
    };
    use depsy_lsp::registries::VulnerabilitySeverity;
    use depsy_lsp::reports::{
        TransitiveVulnerabilityReportEntry, VulnerabilityReportEntry, VulnerabilitySummary,
        fmt_html_report,
    };
    use depsy_lsp::vulnerabilities::{
        Ecosystem, VulnerabilityQuery, normalize_version_for_osv, osv::OsvClient,
    };
    use hashbrown::{HashMap, HashSet};

    fn inc_sev(
        sev: depsy_lsp::registries::VulnerabilitySeverity,
        total: &mut u32,
        crit: &mut u32,
        high: &mut u32,
        med: &mut u32,
        low: &mut u32,
    ) {
        use depsy_lsp::registries::VulnerabilitySeverity;
        *total += 1;
        match sev {
            VulnerabilitySeverity::Critical => *crit += 1,
            VulnerabilitySeverity::High => *high += 1,
            VulnerabilitySeverity::Medium => *med += 1,
            VulnerabilitySeverity::Low => *low += 1,
        }
    }

    // Read file (capped at 50 MiB to prevent hostile large inputs)
    let content = match read_lockfile_capped(&file).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading file: {e}");
            return ExitCode::FAILURE;
        }
    };

    let file_name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");

    // Detect file type and parse
    let (dependencies, ecosystem) = if file_name == "Cargo.toml" {
        (CargoParser::new().parse(&content), Ecosystem::CratesIo)
    } else if file_name == "package.json" {
        let dependencies = NpmParser::new().parse(&content);
        let workspace_content = pnpm_workspace::read_pnpm_workspace_for_package(&file).await;
        (
            pnpm_workspace::resolve_catalog_references(dependencies, workspace_content.as_deref()),
            Ecosystem::Npm,
        )
    } else if file_name == "requirements.txt" || file_name == "pyproject.toml" {
        (PythonParser::new().parse(&content), Ecosystem::PyPI)
    } else if file_name == "go.mod" {
        (GoParser::new().parse(&content), Ecosystem::Go)
    } else if file_name == "composer.json" {
        (PhpParser::new().parse(&content), Ecosystem::Packagist)
    } else if file_name == "pubspec.yaml" {
        (DartParser::new().parse(&content), Ecosystem::Pub)
    } else if file_name.ends_with(".csproj") {
        (CsharpParser::new().parse(&content), Ecosystem::NuGet)
    } else if file_name == "Gemfile" {
        (RubyParser::new().parse(&content), Ecosystem::RubyGems)
    } else if file_name == "pom.xml" {
        (MavenParser::new().parse(&content), Ecosystem::Maven)
    } else {
        eprintln!("Unsupported file type: {file_name}");
        return ExitCode::FAILURE;
    };

    if dependencies.is_empty() {
        println!("No dependencies found in {}", file.display());
        return ExitCode::SUCCESS;
    }

    // Detect lockfile and build graph.
    // For Cargo, we keep the lock content to build a disambiguated version_map separately.
    let mut lockfile_graph = LockfileGraph::default();
    let mut cargo_lock_content: Option<String> = None;
    if use_lockfile {
        match ecosystem {
            Ecosystem::CratesIo => {
                if let Some(path) = cargo_lock::find_cargo_lock(&file).await
                    && let Ok(lock_content) = read_lockfile_capped(&path).await
                {
                    lockfile_graph = cargo_lock::parse_cargo_lock_graph(&lock_content);
                    cargo_lock_content = Some(lock_content);
                }
            }
            Ecosystem::Npm => {
                if let Some((path, kind)) = npm_lock::find_npm_lockfile(&file).await
                    && let Ok(lock_content) = read_lockfile_capped(&path).await
                {
                    lockfile_graph = match kind {
                        npm_lock::NpmLockfileType::PackageLock => {
                            npm_lock::parse_package_lock_graph(&lock_content)
                        }
                        npm_lock::NpmLockfileType::YarnLock => {
                            npm_lock::parse_yarn_lock_graph(&lock_content)
                        }
                        npm_lock::NpmLockfileType::PnpmLock => {
                            npm_lock::parse_pnpm_lock_graph(&lock_content)
                        }
                        npm_lock::NpmLockfileType::BunLock => LockfileGraph::default(),
                    };
                }
            }
            Ecosystem::PyPI => {
                let hint = python_lock::detect_python_tool(&content);
                if let Some((path, kind)) = python_lock::find_python_lockfile(&file, hint).await
                    && let Ok(lock_content) = read_lockfile_capped(&path).await
                {
                    lockfile_graph = match kind {
                        python_lock::PythonLockfileType::PoetryLock => {
                            python_lock::parse_poetry_lock_graph(&lock_content)
                        }
                        python_lock::PythonLockfileType::UvLock => {
                            python_lock::parse_uv_lock_graph(&lock_content)
                        }
                        python_lock::PythonLockfileType::PipfileLock => {
                            python_lock::parse_pipfile_lock_graph(&lock_content)
                        }
                        python_lock::PythonLockfileType::PdmLock => LockfileGraph::default(),
                    };
                }
            }
            Ecosystem::Packagist => {
                if let Some(path) = composer_lock::find_composer_lock(&file).await
                    && let Ok(lock_content) = read_lockfile_capped(&path).await
                {
                    lockfile_graph = composer_lock::parse_composer_lock_graph(&lock_content);
                }
            }
            Ecosystem::RubyGems => {
                if let Some(path) = gemfile_lock::find_gemfile_lock(&file).await
                    && let Ok(lock_content) = read_lockfile_capped(&path).await
                {
                    lockfile_graph = gemfile_lock::parse_gemfile_lock_graph(&lock_content);
                }
            }
            _ => {} // Go/Pub/NuGet/Maven — no graph parser in this PR
        }
    }

    // Populate resolved_version on direct deps.
    // For Cargo, use parse_cargo_lock (HashMap) which correctly disambiguates multi-version
    // crates via the root package's dep list.  For other ecosystems, derive from the graph.
    let version_map: HashMap<String, String> = if let Some(ref lock_content) = cargo_lock_content {
        let root_name = depsy_lsp::parsers::cargo::cargo_root_package_name(&content);
        cargo_lock::parse_cargo_lock(lock_content, root_name.as_deref())
    } else {
        lockfile_graph
            .packages
            .iter()
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect()
    };

    let mut dependencies = dependencies;
    for dep in dependencies.iter_mut() {
        let key = canonical_name(ecosystem, &dep.name);
        if let Some(v) = version_map.get(&key) {
            dep.resolved_version = Some(v.clone());
        }
    }

    // Flag graph's root packages (matching manifest deps)
    let direct_names: HashSet<String> = dependencies
        .iter()
        .map(|d| canonical_name(ecosystem, &d.name))
        .collect();
    for pkg in lockfile_graph.packages.iter_mut() {
        if direct_names.contains(&pkg.name) {
            pkg.is_root = true;
        }
    }

    // Extract transitives (packages in the lockfile but not in the manifest)
    let direct_names_vec: Vec<String> = dependencies
        .iter()
        .map(|d| canonical_name(ecosystem, &d.name))
        .collect();
    let normalized_to_raw: HashMap<String, String> = dependencies
        .iter()
        .map(|d| (canonical_name(ecosystem, &d.name), d.name.clone()))
        .collect();
    let transitives: Vec<LockfilePackage> = lockfile_graph
        .transitives_only(&direct_names_vec)
        .into_iter()
        .cloned()
        .collect();

    // Build queries: direct first, then transitive. Remember the split index.
    let mut queries: Vec<VulnerabilityQuery> = dependencies
        .iter()
        .map(|dep| VulnerabilityQuery {
            ecosystem,
            package_name: dep.name.clone(),
            version: normalize_version_for_osv(dep.effective_version()),
        })
        .collect();
    let direct_count = queries.len();
    for t in &transitives {
        queries.push(VulnerabilityQuery {
            ecosystem,
            package_name: t.name.clone(),
            version: normalize_version_for_osv(&t.version),
        });
    }

    eprintln!(
        "Scanning {direct_count} direct + {} transitive dependencies in {}...",
        transitives.len(),
        file.display()
    );

    // Allow tests to inject a custom OSV endpoint
    let osv_client = match std::env::var("OSV_ENDPOINT") {
        Ok(url) => match OsvClient::with_endpoint(url) {
            Ok(client) => client,
            Err(e) => {
                eprintln!("Error building OSV client for OSV_ENDPOINT: {e}");
                return ExitCode::FAILURE;
            }
        },
        Err(_) => OsvClient::default(),
    };
    let results = match osv_client.query_batch(&queries).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error querying OSV.dev: {e}");
            return ExitCode::FAILURE;
        }
    };

    let (direct_results, transitive_results) = results.split_at(direct_count);

    // Parse minimum severity using shared method
    let min_sev = VulnerabilitySeverity::from_str_loose(&min_severity);

    let mut total_vulns = 0u32;
    let mut critical_count = 0u32;
    let mut high_count = 0u32;
    let mut medium_count = 0u32;
    let mut low_count = 0u32;
    let mut direct_details: Vec<VulnerabilityReportEntry> = Vec::new();
    let mut transitive_details: Vec<TransitiveVulnerabilityReportEntry> = Vec::new();

    for (dep, result) in dependencies.iter().zip(direct_results.iter()) {
        for vuln in &result.vulnerabilities {
            if !vuln.severity.meets_threshold(&min_sev) {
                continue;
            }
            inc_sev(
                vuln.severity,
                &mut total_vulns,
                &mut critical_count,
                &mut high_count,
                &mut medium_count,
                &mut low_count,
            );
            direct_details.push(VulnerabilityReportEntry {
                package: dep.name.clone(),
                version: dep.effective_version().to_string(),
                id: vuln.id.clone(),
                severity: vuln.severity.as_str().to_string(),
                description: vuln.description.clone(),
                url: vuln.url.clone(),
            });
        }
    }

    let inverse = lockfile_graph.reverse_index(&direct_names_vec);

    for (pkg, result) in transitives.iter().zip(transitive_results.iter()) {
        for vuln in &result.vulnerabilities {
            if !vuln.severity.meets_threshold(&min_sev) {
                continue;
            }
            inc_sev(
                vuln.severity,
                &mut total_vulns,
                &mut critical_count,
                &mut high_count,
                &mut medium_count,
                &mut low_count,
            );

            let via_direct = inverse
                .get(&pkg.name)
                .and_then(|parents| parents.first())
                .and_then(|n| normalized_to_raw.get(n))
                .cloned()
                .unwrap_or_else(|| "(unknown)".to_string());

            transitive_details.push(TransitiveVulnerabilityReportEntry {
                package: pkg.name.clone(),
                version: pkg.version.clone(),
                id: vuln.id.clone(),
                severity: vuln.severity.as_str().to_string(),
                description: vuln.description.clone(),
                url: vuln.url.clone(),
                via_direct,
            });
        }
    }

    // Output results
    let summary = VulnerabilitySummary {
        total: total_vulns,
        critical: critical_count,
        high: high_count,
        medium: medium_count,
        low: low_count,
    };
    match output {
        OutputFormat::Json => {
            let combined: Vec<serde_json::Value> = direct_details
                .iter()
                .filter_map(|e| serde_json::to_value(e).ok())
                .chain(
                    transitive_details
                        .iter()
                        .filter_map(|e| serde_json::to_value(e).ok()),
                )
                .collect();
            let report = serde_json::json!({
                "file": file.display().to_string(),
                "summary": &summary,
                "direct": &direct_details,
                "transitive": &transitive_details,
                "vulnerabilities": combined,
            });
            match serde_json::to_string_pretty(&report) {
                Ok(json) => println!("{json}"),
                Err(e) => eprintln!("Failed to serialize report: {e}"),
            }
        }
        OutputFormat::Markdown => {
            println!("# Vulnerability Report\n");
            println!("**File**: {}", file.display());
            println!("**Date**: {}\n", chrono::Local::now().format("%Y-%m-%d"));
            println!("## Summary\n");
            println!("| Severity | Count |");
            println!("|----------|-------|");
            println!("| ⚠ Critical | {critical_count} |");
            println!("| ▲ High | {high_count} |");
            println!("| ● Medium | {medium_count} |");
            println!("| ○ Low | {low_count} |");
            println!("| **Total** | **{total_vulns}** |\n");

            if !direct_details.is_empty() {
                println!("## Direct dependencies ({})\n", direct_details.len());
                for v in &direct_details {
                    print_markdown_entry(
                        &v.package,
                        &v.version,
                        &v.id,
                        &v.severity,
                        &v.description,
                        v.url.as_deref(),
                        None,
                    );
                }
            }
            if !transitive_details.is_empty() {
                println!(
                    "## Transitive dependencies ({})\n",
                    transitive_details.len()
                );
                for v in &transitive_details {
                    print_markdown_entry(
                        &v.package,
                        &v.version,
                        &v.id,
                        &v.severity,
                        &v.description,
                        v.url.as_deref(),
                        Some(&v.via_direct),
                    );
                }
            }
        }
        OutputFormat::Html => {
            print!(
                "{}",
                fmt_html_report(
                    &file.display().to_string(),
                    &summary,
                    &direct_details,
                    &transitive_details
                )
            );
        }
        OutputFormat::Summary => {
            println!("Vulnerability Scan Results for {}", file.display());
            println!(
                "  Total: {total_vulns} ({} direct, {} transitive)",
                direct_details.len(),
                transitive_details.len()
            );
            println!("  ⚠ Critical: {critical_count}");
            println!("  ▲ High:     {high_count}");
            println!("  ● Medium:   {medium_count}");
            println!("  ○ Low:      {low_count}\n");

            if !direct_details.is_empty() {
                println!("Direct:");
                for v in &direct_details {
                    println!("  - {}@{} [{}]", v.package, v.version, v.id);
                }
            }
            if !transitive_details.is_empty() {
                println!("Transitive:");
                for v in &transitive_details {
                    println!(
                        "  - {}@{} (via {}) [{}]",
                        v.package, v.version, v.via_direct, v.id
                    );
                }
            }
            if total_vulns == 0 {
                println!("\n[OK] No vulnerabilities found!");
            }
        }
    }

    // Exit code
    if fail_on_vulns && total_vulns > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

async fn run_profile_parse(file: PathBuf, iterations: u32) -> ExitCode {
    use depsy_lsp::parsers::{
        Parser, cargo::CargoParser, csharp::CsharpParser, dart::DartParser, go::GoParser,
        lockfile_graph::read_lockfile_capped, maven::MavenParser, npm::NpmParser, php::PhpParser,
        python::PythonParser, ruby::RubyParser,
    };

    let content = match read_lockfile_capped(&file).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading file: {e}");
            return ExitCode::FAILURE;
        }
    };

    let file_name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");

    eprintln!("Profiling parse operations for: {}", file.display());
    eprintln!("Iterations: {iterations}");
    eprintln!("File size: {} bytes", content.len());

    enum ParserKind {
        Cargo(CargoParser),
        Npm(NpmParser),
        Python(PythonParser),
        Go(GoParser),
        Php(PhpParser),
        Dart(DartParser),
        Csharp(CsharpParser),
        Ruby(RubyParser),
        Maven(MavenParser),
    }

    let parser = if file_name.ends_with("Cargo.toml")
        || (file_name.ends_with(".toml") && file_name.contains("cargo"))
    {
        ParserKind::Cargo(CargoParser::new())
    } else if file_name.ends_with("package.json")
        || (file_name.ends_with(".json") && file_name.contains("package"))
    {
        ParserKind::Npm(NpmParser::new())
    } else if file_name.ends_with("requirements.txt") || file_name.ends_with("pyproject.toml") {
        ParserKind::Python(PythonParser::new())
    } else if file_name.ends_with("go.mod") {
        ParserKind::Go(GoParser::new())
    } else if file_name.ends_with("composer.json") {
        ParserKind::Php(PhpParser::new())
    } else if file_name.ends_with("pubspec.yaml") {
        ParserKind::Dart(DartParser::new())
    } else if file_name.ends_with(".csproj") {
        ParserKind::Csharp(CsharpParser::new())
    } else if file_name.ends_with("Gemfile") {
        ParserKind::Ruby(RubyParser::new())
    } else if file_name == "pom.xml" {
        ParserKind::Maven(MavenParser::new())
    } else {
        eprintln!("Unsupported file type: {file_name}");
        return ExitCode::FAILURE;
    };

    let start = Instant::now();

    for _ in 0..iterations {
        match &parser {
            ParserKind::Cargo(p) => std::hint::black_box(p.parse(&content)),
            ParserKind::Npm(p) => std::hint::black_box(p.parse(&content)),
            ParserKind::Python(p) => std::hint::black_box(p.parse(&content)),
            ParserKind::Go(p) => std::hint::black_box(p.parse(&content)),
            ParserKind::Php(p) => std::hint::black_box(p.parse(&content)),
            ParserKind::Dart(p) => std::hint::black_box(p.parse(&content)),
            ParserKind::Csharp(p) => std::hint::black_box(p.parse(&content)),
            ParserKind::Ruby(p) => std::hint::black_box(p.parse(&content)),
            ParserKind::Maven(p) => std::hint::black_box(p.parse(&content)),
        };
    }

    let elapsed = start.elapsed();
    let avg = elapsed.checked_div(iterations).unwrap_or_default();

    eprintln!("\nProfiling complete!");
    eprintln!("Total time: {elapsed:?}");
    eprintln!("Average per iteration: {avg:?}");

    ExitCode::SUCCESS
}

async fn run_profile_registry(
    registry: RegistryType,
    packages: String,
    iterations: u32,
    verbose: bool,
) -> ExitCode {
    use depsy_lsp::config::NpmRegistryConfig;
    use depsy_lsp::registries::{
        Registry, crates_io::CratesIoRegistry, go_proxy::GoProxyRegistry, npm::NpmRegistry,
        nuget::NuGetRegistry, packagist::PackagistRegistry, pub_dev::PubDevRegistry,
        pypi::PyPiRegistry, rubygems::RubyGemsRegistry,
    };

    let package_list: Vec<&str> = packages
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if package_list.is_empty() {
        eprintln!("Error: No packages specified. Provide comma-separated package names.");
        return ExitCode::FAILURE;
    }

    eprintln!("Profiling registry requests for: {registry:?}");
    eprintln!("Packages: {package_list:?}");
    eprintln!("Iterations: {iterations}");
    if verbose {
        eprintln!("Verbose mode enabled (may affect timing accuracy)");
    }

    let http_client = match depsy_lsp::registries::http_client::create_shared_client() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Error creating HTTP client: {e}");
            return ExitCode::FAILURE;
        }
    };

    enum RegistryKind {
        Crates(CratesIoRegistry),
        Npm(NpmRegistry),
        Pypi(PyPiRegistry),
        Go(GoProxyRegistry),
        Packagist(PackagistRegistry),
        PubDev(PubDevRegistry),
        Nuget(NuGetRegistry),
        Rubygems(RubyGemsRegistry),
    }

    let reg = match registry {
        RegistryType::Crates => RegistryKind::Crates(CratesIoRegistry::with_client(http_client)),
        RegistryType::Npm => RegistryKind::Npm(NpmRegistry::with_client_and_config(
            http_client,
            &NpmRegistryConfig::default(),
        )),
        RegistryType::Pypi => RegistryKind::Pypi(PyPiRegistry::with_client(http_client)),
        RegistryType::Go => RegistryKind::Go(GoProxyRegistry::with_client(http_client)),
        RegistryType::Packagist => {
            RegistryKind::Packagist(PackagistRegistry::with_client(http_client))
        }
        RegistryType::PubDev => RegistryKind::PubDev(PubDevRegistry::with_client(http_client)),
        RegistryType::Nuget => RegistryKind::Nuget(NuGetRegistry::with_client(http_client)),
        RegistryType::Rubygems => {
            RegistryKind::Rubygems(RubyGemsRegistry::with_client(http_client))
        }
    };

    let start = Instant::now();

    for i in 0..iterations {
        if verbose {
            eprintln!("Iteration {}/{iterations}", i + 1);
        }
        for pkg in &package_list {
            let result = match &reg {
                RegistryKind::Crates(r) => r.get_version_info(pkg).await,
                RegistryKind::Npm(r) => r.get_version_info(pkg).await,
                RegistryKind::Pypi(r) => r.get_version_info(pkg).await,
                RegistryKind::Go(r) => r.get_version_info(pkg).await,
                RegistryKind::Packagist(r) => r.get_version_info(pkg).await,
                RegistryKind::PubDev(r) => r.get_version_info(pkg).await,
                RegistryKind::Nuget(r) => r.get_version_info(pkg).await,
                RegistryKind::Rubygems(r) => r.get_version_info(pkg).await,
            };

            if verbose {
                match result {
                    Ok(info) => eprintln!(
                        "  {pkg} -> latest: {:?}",
                        info.latest.as_deref().unwrap_or("N/A")
                    ),
                    Err(e) => eprintln!("  {pkg} -> error: {e}"),
                }
            }
        }
    }

    let elapsed = start.elapsed();
    let total_fetches: u128 = iterations as u128 * package_list.len() as u128;

    if total_fetches == 0 {
        eprintln!("Error: No fetches performed (zero iterations or empty package list).");
        return ExitCode::FAILURE;
    }

    let avg_nanos = elapsed.as_nanos() / total_fetches;
    let avg = std::time::Duration::from_nanos(avg_nanos as u64);

    eprintln!("\nProfiling complete!");
    eprintln!("Total time: {elapsed:?}");
    eprintln!("Total fetches: {total_fetches}");
    eprintln!("Average per package fetch: {avg:?}");

    ExitCode::SUCCESS
}

async fn run_profile_full(file: PathBuf, iterations: u32, verbose: bool) -> ExitCode {
    use depsy_lsp::config::NpmRegistryConfig;
    use depsy_lsp::parsers::{
        Parser, cargo::CargoParser, csharp::CsharpParser, dart::DartParser, go::GoParser,
        lockfile_graph::read_lockfile_capped, maven::MavenParser, npm::NpmParser, php::PhpParser,
        python::PythonParser, ruby::RubyParser,
    };
    use depsy_lsp::registries::{
        Registry, crates_io::CratesIoRegistry, go_proxy::GoProxyRegistry,
        maven_central::MavenCentralRegistry, npm::NpmRegistry, nuget::NuGetRegistry,
        packagist::PackagistRegistry, pub_dev::PubDevRegistry, pypi::PyPiRegistry,
        rubygems::RubyGemsRegistry,
    };
    use depsy_lsp::vulnerabilities::{Ecosystem, VulnerabilityQuery, osv::OsvClient};
    use futures::future::join_all;

    let content = match read_lockfile_capped(&file).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading file: {e}");
            return ExitCode::FAILURE;
        }
    };

    let file_name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");

    eprintln!("Profiling full workflow for: {}", file.display());
    eprintln!("Iterations: {iterations}");
    if verbose {
        eprintln!("Verbose mode enabled (may affect timing accuracy)");
    }

    let http_client = match depsy_lsp::registries::http_client::create_shared_client() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Error creating HTTP client: {e}");
            return ExitCode::FAILURE;
        }
    };

    let ecosystem = if file_name.ends_with("Cargo.toml")
        || (file_name.ends_with(".toml") && file_name.contains("cargo"))
    {
        Ecosystem::CratesIo
    } else if file_name.ends_with("package.json")
        || (file_name.ends_with(".json") && file_name.contains("package"))
    {
        Ecosystem::Npm
    } else if file_name.ends_with("requirements.txt") || file_name.ends_with("pyproject.toml") {
        Ecosystem::PyPI
    } else if file_name.ends_with("go.mod") {
        Ecosystem::Go
    } else if file_name.ends_with("composer.json") {
        Ecosystem::Packagist
    } else if file_name.ends_with("pubspec.yaml") {
        Ecosystem::Pub
    } else if file_name.ends_with(".csproj") {
        Ecosystem::NuGet
    } else if file_name.ends_with("Gemfile") {
        Ecosystem::RubyGems
    } else if file_name == "pom.xml" {
        Ecosystem::Maven
    } else {
        eprintln!("Unsupported file type: {file_name}");
        return ExitCode::FAILURE;
    };

    let start = Instant::now();

    for i in 0..iterations {
        if verbose {
            eprintln!("Iteration {}/{iterations}", i + 1);
        }

        // Step 1: Parse
        let parse_start = Instant::now();
        let dependencies = match ecosystem {
            Ecosystem::CratesIo => CargoParser::new().parse(&content),
            Ecosystem::Npm => NpmParser::new().parse(&content),
            Ecosystem::PyPI => PythonParser::new().parse(&content),
            Ecosystem::Go => GoParser::new().parse(&content),
            Ecosystem::Packagist => PhpParser::new().parse(&content),
            Ecosystem::Pub => DartParser::new().parse(&content),
            Ecosystem::NuGet => CsharpParser::new().parse(&content),
            Ecosystem::RubyGems => RubyParser::new().parse(&content),
            Ecosystem::Maven => MavenParser::new().parse(&content),
        };
        let parse_elapsed = parse_start.elapsed();

        if dependencies.is_empty() {
            if verbose {
                eprintln!("No dependencies found");
            }
            continue;
        }

        if verbose {
            eprintln!("  Parse: {parse_elapsed:?} ({} deps)", dependencies.len());
        }

        // Step 2: Fetch registry info (parallel, limited to first 10 for profiling)
        let registry_start = Instant::now();
        let deps_to_fetch: Vec<_> = dependencies.iter().take(10).collect();

        let futures: Vec<_> = deps_to_fetch
            .iter()
            .map(|dep| {
                let name = dep.name.clone();
                let client = http_client.clone();
                async move {
                    match ecosystem {
                        Ecosystem::CratesIo => {
                            let reg = CratesIoRegistry::with_client(client);
                            reg.get_version_info(&name).await
                        }
                        Ecosystem::Npm => {
                            let reg = NpmRegistry::with_client_and_config(
                                client,
                                &NpmRegistryConfig::default(),
                            );
                            reg.get_version_info(&name).await
                        }
                        Ecosystem::PyPI => {
                            let reg = PyPiRegistry::with_client(client);
                            reg.get_version_info(&name).await
                        }
                        Ecosystem::Go => {
                            let reg = GoProxyRegistry::with_client(client);
                            reg.get_version_info(&name).await
                        }
                        Ecosystem::Packagist => {
                            let reg = PackagistRegistry::with_client(client);
                            reg.get_version_info(&name).await
                        }
                        Ecosystem::Pub => {
                            let reg = PubDevRegistry::with_client(client);
                            reg.get_version_info(&name).await
                        }
                        Ecosystem::NuGet => {
                            let reg = NuGetRegistry::with_client(client);
                            reg.get_version_info(&name).await
                        }
                        Ecosystem::RubyGems => {
                            let reg = RubyGemsRegistry::with_client(client);
                            reg.get_version_info(&name).await
                        }
                        Ecosystem::Maven => {
                            let reg = MavenCentralRegistry::with_client(client);
                            reg.get_version_info(&name).await
                        }
                    }
                }
            })
            .collect();

        let _results = join_all(futures).await;
        let registry_elapsed = registry_start.elapsed();
        if verbose {
            eprintln!("  Registry: {registry_elapsed:?}");
        }

        // Step 3: Vulnerability check
        let vuln_start = Instant::now();
        let queries: Vec<VulnerabilityQuery> = deps_to_fetch
            .iter()
            .map(|dep| VulnerabilityQuery {
                ecosystem,
                package_name: dep.name.clone(),
                version: dep.version.clone(),
            })
            .collect();

        let osv_client = OsvClient::default();
        let _ = osv_client.query_batch(&queries).await;
        let vuln_elapsed = vuln_start.elapsed();
        if verbose {
            eprintln!("  Vulns: {vuln_elapsed:?}");
        }
    }

    let elapsed = start.elapsed();
    let avg = elapsed.checked_div(iterations).unwrap_or_default();

    eprintln!("\nProfiling complete!");
    eprintln!("Total time: {elapsed:?}");
    eprintln!("Average per iteration: {avg:?}");

    ExitCode::SUCCESS
}
