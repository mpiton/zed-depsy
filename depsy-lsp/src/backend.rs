//! LSP backend — the central [`LanguageServer`](tower_lsp::LanguageServer) implementation.
//!
//! [`crate::backend::DepsyBackend`] owns all shared state and routes LSP
//! notifications and requests to the appropriate parsers, registry clients,
//! and providers. The public surface is intentionally small: callers construct
//! the backend with [`crate::backend::DepsyBackend::new`] (or
//! [`crate::backend::DepsyBackend::with_http_client`] for tests) and hand it
//! to [`tower_lsp::LspService::new`].
//!
//! # Concurrency model
//!
//! All mutable state is shared via `Arc`. Most collections use
//! [`dashmap::DashMap`] — a sharded `RwLock`-backed concurrent hashmap that
//! lets disjoint shards proceed in parallel without locking the whole map.
//! Fields that require full replacement at runtime (e.g. `osv_client`,
//! `advisory_cache`) are wrapped in [`tokio::sync::RwLock`]; each is swapped
//! atomically on its own when [`crate::backend::DepsyBackend`]`::initialize`
//! reconfigures the server, but the swaps happen sequentially — there is no
//! single global atomic replacement of the runtime. The backend itself is
//! `Clone` only in the sense that tower-lsp clones the handler type; each
//! clone shares the same underlying `Arc` handles — there is no deep copy.
//!
//! Document processing is debounced: `did_change` spawns a [`tokio`] task that
//! waits for a configurable idle period before calling the full
//! parse→fetch→diagnose pipeline. Vulnerability queries are always fired as a
//! second background `tokio::spawn` so they never block the initial inlay-hint
//! refresh.
//!
//! # Error handling at the LSP boundary
//!
//! [`tower_lsp::jsonrpc::Result`] is used as the return type for handler
//! methods. Internal errors are logged with `tracing` and either converted
//! to an LSP error response or silently swallowed (for notifications, which
//! have no response channel). Registry and network errors are `anyhow::Result`
//! internally and are downgraded to `tracing::warn!` / `tracing::error!` logs
//! so a single failing registry never crashes the server.

use core::fmt;
use std::time::Duration;
use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

use dashmap::DashMap;
use hashbrown::{HashMap, HashSet};
use reqwest::Client as HttpClient;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer};

use crate::cache::{HybridCache, ReadCache, WriteCache};
use crate::config::Config;
use crate::document::DocumentState;
use crate::file_types::{FileType, is_pnpm_workspace};
use crate::parsers::Parser;
use crate::parsers::cargo::CargoParser;
use crate::parsers::csharp::CsharpParser;
use crate::parsers::dart::DartParser;
use crate::parsers::go::GoParser;
use crate::parsers::maven::MavenParser;
use crate::parsers::npm::NpmParser;
use crate::parsers::php::PhpParser;
use crate::parsers::pnpm_workspace::{
    PnpmWorkspaceParser, read_pnpm_workspace_for_package, resolve_catalog_references,
};
use crate::parsers::python::PythonParser;
use crate::parsers::ruby::RubyParser;
use crate::providers::code_actions::create_code_actions;
use crate::providers::completion::{fmt_release_age, get_completions};
use crate::providers::diagnostics::{VulnSources, create_diagnostics};
use crate::providers::document_links::create_document_links;
use crate::providers::inlay_hints::create_inlay_hint;
use crate::registries::cargo_sparse::CargoSparseRegistry;
use crate::registries::crates_io::CratesIoRegistry;
use crate::registries::go_proxy::GoProxyRegistry;
use crate::registries::http_client::create_shared_client;
use crate::registries::maven_central::MavenCentralRegistry;
use crate::registries::npm::NpmRegistry;
use crate::registries::nuget::NuGetRegistry;
use crate::registries::packagist::PackagistRegistry;
use crate::registries::pub_dev::PubDevRegistry;
use crate::registries::pypi::PyPiRegistry;
use crate::registries::rubygems::RubyGemsRegistry;
use crate::registries::{Registry, VersionInfo, Vulnerability, VulnerabilitySeverity};
use crate::reports::{VulnerabilityReportEntry, VulnerabilitySummary};
use crate::vulnerabilities::cache::{VulnCacheKey, VulnerabilityCache};
use crate::vulnerabilities::osv::OsvClient;
use crate::vulnerabilities::{
    VulnerabilityQuery, apply_osv_result, cached_version_info, normalize_version_for_osv,
};
use crate::{
    auth::{EnvTokenProvider, TokenProviderManager, cargo_credentials, fmt_redact_token},
    reports::fmt_markdown_report,
};

/// Walk parents of `file_path` looking for a `.zed/` directory.
/// Returns the first ancestor that contains it, or `None` if no ancestor has `.zed/`.
///
/// Returning `None` (rather than guessing the file's parent) avoids writing
/// `.zed/settings.json` to a nested directory when the real workspace lives higher up.
/// The Ignore code action degrades gracefully when this returns `None`.
///
/// Uses `tokio::fs::metadata` (async) per project rule: no blocking I/O in async tasks.
async fn find_workspace_root(file_path: &std::path::Path) -> Option<std::path::PathBuf> {
    let start = file_path.parent()?;
    for ancestor in start.ancestors() {
        let candidate = ancestor.join(".zed");
        if let Ok(meta) = tokio::fs::metadata(&candidate).await
            && meta.is_dir()
        {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

/// Compute cache key for a dependency, including registry for Cargo alternative registries.
///
/// For Cargo deps with `registry = "name"`, the key is `crates:{registry}:{name}` to avoid
/// collisions between crates.io and private registries. All other deps use the standard key.
fn dep_cache_key(dep: &crate::parsers::Dependency, file_type: FileType) -> String {
    let dep_name = &*dep.name;
    match (dep.registry.as_deref(), file_type) {
        (Some(registry), FileType::Cargo) => format!("crates:{registry}:{dep_name}"),
        _ => file_type.cache_key(dep_name),
    }
}

/// Holds cloneable references to backend state for async document processing.
/// Used by debounce tasks to process documents after the debounce period.
#[derive(Clone)]
struct ProcessingContext {
    client: Client,
    config: Arc<RwLock<Config>>,
    documents: Arc<DashMap<Url, DocumentState>>,
    version_cache: Arc<HybridCache>,
    cargo_parser: Arc<CargoParser>,
    npm_parser: Arc<NpmParser>,
    python_parser: Arc<PythonParser>,
    go_parser: Arc<GoParser>,
    php_parser: Arc<PhpParser>,
    dart_parser: Arc<DartParser>,
    csharp_parser: Arc<CsharpParser>,
    ruby_parser: Arc<RubyParser>,
    maven_parser: Arc<MavenParser>,
    crates_io: Arc<CratesIoRegistry>,
    cargo_custom_registries: Arc<DashMap<String, Arc<CargoSparseRegistry>>>,
    npm_registry: Arc<tokio::sync::RwLock<NpmRegistry>>,
    pypi: Arc<PyPiRegistry>,
    go_proxy: Arc<GoProxyRegistry>,
    packagist: Arc<PackagistRegistry>,
    pub_dev: Arc<PubDevRegistry>,
    nuget: Arc<NuGetRegistry>,
    rubygems: Arc<RubyGemsRegistry>,
    maven_central: Arc<tokio::sync::RwLock<MavenCentralRegistry>>,
    osv_client: Arc<OsvClient>,
    vuln_cache: Arc<VulnerabilityCache>,
}

/// Parse an npm-ecosystem manifest: the catalogs of a `pnpm-workspace.yaml`,
/// the dependency sections of a `package.json` otherwise.
fn parse_npm_manifest(
    uri: &Url,
    content: &str,
    npm_parser: &NpmParser,
) -> Vec<crate::parsers::Dependency> {
    if is_pnpm_workspace(uri) {
        PnpmWorkspaceParser.parse(content)
    } else {
        npm_parser.parse(content)
    }
}

impl ProcessingContext {
    fn parse_document(&self, uri: &Url, content: &str) -> Vec<crate::parsers::Dependency> {
        match FileType::detect(uri) {
            Some(FileType::Cargo) => self.cargo_parser.parse(content),
            Some(FileType::Npm) => parse_npm_manifest(uri, content, &self.npm_parser),
            Some(FileType::Python) => self.python_parser.parse(content),
            Some(FileType::Go) => self.go_parser.parse(content),
            Some(FileType::Php) => self.php_parser.parse(content),
            Some(FileType::Dart) => self.dart_parser.parse(content),
            Some(FileType::Csharp) => self.csharp_parser.parse(content),
            Some(FileType::Ruby) => self.ruby_parser.parse(content),
            Some(FileType::Maven) => self.maven_parser.parse(content),
            None => vec![],
        }
    }

    async fn process_document(&self, uri: &Url, content: &str) {
        let Some(file_type) = FileType::detect(uri) else {
            return;
        };

        let mut dependencies = self.parse_document(uri, content);
        let is_pnpm_workspace = is_pnpm_workspace(uri);
        if file_type == FileType::Npm
            && !is_pnpm_workspace
            && let Ok(manifest_path) = uri.to_file_path()
        {
            let workspace_content = read_pnpm_workspace_for_package(&manifest_path).await;
            dependencies = resolve_catalog_references(dependencies, workspace_content.as_deref());
        }

        let lockfile_graph = if let Ok(manifest_path) = uri.to_file_path() {
            if let Some(resolver) = crate::parsers::lockfile_resolver::select_resolver(
                file_type,
                &manifest_path,
                content,
            )
            .await
            {
                crate::parsers::lockfile_resolver::resolve_versions_from_lockfile(
                    &mut dependencies,
                    resolver,
                    &manifest_path,
                )
                .await
            } else {
                None
            }
        } else {
            None
        };

        tracing::info!(
            "Parsed {} dependencies from {}",
            dependencies.len(),
            uri.path()
        );

        // Clone Arc references for async tasks
        let crates_io = Arc::clone(&self.crates_io);
        let cargo_custom_registries = Arc::clone(&self.cargo_custom_registries);
        let npm_registry = Arc::clone(&self.npm_registry);
        let pypi = Arc::clone(&self.pypi);
        let go_proxy = Arc::clone(&self.go_proxy);
        let packagist = Arc::clone(&self.packagist);
        let pub_dev = Arc::clone(&self.pub_dev);
        let nuget = Arc::clone(&self.nuget);
        let rubygems = Arc::clone(&self.rubygems);
        let maven_central = Arc::clone(&self.maven_central);
        let cache = Arc::clone(&self.version_cache);

        let fetch_tasks: Vec<_> = dependencies
            .iter()
            .map(|dep| {
                let name = dep.name.clone();
                let registry = dep.registry.clone();
                let cache_key = dep_cache_key(dep, file_type);
                let crates_io = Arc::clone(&crates_io);
                let cargo_custom_registries = Arc::clone(&cargo_custom_registries);
                let npm_registry = Arc::clone(&npm_registry);
                let pypi = Arc::clone(&pypi);
                let go_proxy = Arc::clone(&go_proxy);
                let packagist = Arc::clone(&packagist);
                let pub_dev = Arc::clone(&pub_dev);
                let nuget = Arc::clone(&nuget);
                let rubygems = Arc::clone(&rubygems);
                let maven_central = Arc::clone(&maven_central);
                let cache = Arc::clone(&cache);
                async move {
                    // Check cache first
                    if cache.get(&cache_key).await.is_some() {
                        tracing::debug!("Cache hit for '{name}' (key: {cache_key})");
                        return;
                    }
                    tracing::debug!("Cache miss for '{name}' (key: {cache_key}), fetching from registry {registry:?}");
                    // Fetch from appropriate registry
                    let result = match file_type {
                        FileType::Cargo => {
                            if let Some(ref reg_name) = registry {
                                if let Some(reg) = cargo_custom_registries.get(reg_name) {
                                    reg.get_version_info(&name).await
                                } else {
                                    tracing::warn!(
                                        "Unknown Cargo registry '{reg_name}' for package '{name}', falling back to crates.io",
                                    );
                                    crates_io.get_version_info(&name).await
                                }
                            } else {
                                crates_io.get_version_info(&name).await
                            }
                        }
                        FileType::Npm => npm_registry.read().await.get_version_info(&name).await,
                        FileType::Python => pypi.get_version_info(&name).await,
                        FileType::Go => go_proxy.get_version_info(&name).await,
                        FileType::Php => packagist.get_version_info(&name).await,
                        FileType::Dart => pub_dev.get_version_info(&name).await,
                        FileType::Csharp => nuget.get_version_info(&name).await,
                        FileType::Ruby => rubygems.get_version_info(&name).await,
                        FileType::Maven => {
                            maven_central.read().await.get_version_info(&name).await
                        }
                    };
                    match result {
                        Ok(info) => {
                            cache.insert(cache_key, info).await;
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to fetch version info for '{name}' (registry: {registry:?}): {e}",
                            );
                        }
                    }
                }
            })
            .collect();

        // Run up to 5 concurrent requests
        let semaphore = Arc::new(tokio::sync::Semaphore::new(5));
        let handles: Vec<_> = fetch_tasks
            .into_iter()
            .map(|task| {
                let permit = Arc::clone(&semaphore);
                tokio::spawn(async move {
                    let _permit = permit.acquire().await;
                    task.await
                })
            })
            .collect();

        // Wait for all tasks to complete
        for handle in handles {
            let _ = handle.await;
        }

        // Store document state IMMEDIATELY (before vulnerability check)
        self.documents.insert(
            uri.clone(),
            DocumentState {
                dependencies: dependencies.clone(),
                file_type,
                lockfile_graph: lockfile_graph.clone(),
                transitive_vulns_by_direct: hashbrown::HashMap::new(),
            },
        );

        // Publish diagnostics IMMEDIATELY (versions are available, vulnerabilities will update later)
        self.publish_diagnostics(uri).await;

        // Refresh inlay hints IMMEDIATELY (versions are available)
        self.client
            .send_request::<request::InlayHintRefreshRequest>(())
            .await
            .ok();

        let security_enabled = self
            .config
            .read()
            .map(|c| c.security.enabled)
            .unwrap_or(true);

        // Fetch vulnerabilities from OSV.dev in BACKGROUND (non-blocking), then
        // republish so the findings reach the Problems panel without an edit.
        if security_enabled && !dependencies.is_empty() {
            let ctx = self.clone();
            let uri = uri.clone();

            tokio::spawn(async move {
                DepsyBackend::fetch_vulnerabilities_background(
                    dependencies,
                    file_type,
                    Arc::clone(&ctx.osv_client),
                    Arc::clone(&ctx.vuln_cache),
                    ctx.client.clone(),
                    VulnBgContext {
                        documents: Arc::clone(&ctx.documents),
                        uri: uri.clone(),
                        lockfile_graph,
                    },
                )
                .await;
                ctx.publish_diagnostics(&uri).await;
            });
        }
    }

    /// Publishes diagnostics for `uri` from its current document state.
    ///
    /// Runs once versions are fetched and again after the background OSV
    /// check. Does nothing when the document was closed in the meantime.
    async fn publish_diagnostics(&self, uri: &Url) {
        // Snapshot the document so no DashMap guard is held across an await.
        let Some((dependencies, file_type, transitive)) = self.documents.get(uri).map(|doc| {
            (
                doc.dependencies.clone(),
                doc.file_type,
                doc.transitive_vulns_by_direct.clone(),
            )
        }) else {
            return;
        };
        let (diagnostics_enabled, severity_filter, ignored_packages) = self
            .config
            .read()
            .map(|c| {
                (
                    c.diagnostics.enabled,
                    c.security
                        .show_diagnostics
                        .then(|| c.security.min_severity_level()),
                    c.ignore.clone(),
                )
            })
            .unwrap_or((true, None, Vec::new()));
        if !diagnostics_enabled {
            return;
        }

        // Pre-build cache key map for registry-aware lookups
        let cache_key_map: HashMap<String, String> = dependencies
            .iter()
            .map(|dep| (dep.name.clone(), dep_cache_key(dep, file_type)))
            .collect();
        let diagnostics = create_diagnostics(
            &dependencies,
            &self.version_cache,
            |name| {
                cache_key_map
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| file_type.cache_key(name))
            },
            severity_filter,
            file_type,
            VulnSources {
                osv_results: &self.vuln_cache,
                transitive: &transitive,
            },
            &ignored_packages,
        )
        .await;

        self.client
            .publish_diagnostics(uri.clone(), diagnostics, None)
            .await;
    }
}

/// The cache trio + OsvClient + cleanup-task handles produced by
/// [`build_advisory_runtime`]. Returned together so callers can swap the
/// runtime atomically and abort the previous cleanup tasks instead of
/// leaking them.
struct AdvisoryRuntime {
    positive: Arc<crate::cache::HybridAdvisoryCache>,
    negative: Arc<crate::cache::HybridAdvisoryCache>,
    osv_client: Arc<OsvClient>,
    cleanup_handles: Vec<tokio::task::JoinHandle<()>>,
}

/// Build the cache trio + OsvClient configured from
/// [`crate::config::AdvisoryCacheConfig`] and spawn the cleanup tasks.
///
/// Extracted as a free function so [`DepsyBackend::with_http_client`] and
/// [`DepsyBackend::initialize`] share one construction path. Keeping the
/// helper isolated also makes the configuration wiring testable without
/// instantiating an LSP `Client`.
///
/// Infallible: reuses the caller-supplied `reqwest::Client` (the LSP's
/// shared HTTP client) instead of building a second one. The caller has
/// already proven `reqwest` works on this platform, so this avoids a
/// second TLS/builder failure point that previously forced the helper to
/// either panic or fall back to the panicky `Client::new()`.
fn build_advisory_runtime(
    config: &crate::config::AdvisoryCacheConfig,
    http_client: Arc<HttpClient>,
) -> AdvisoryRuntime {
    let positive = Arc::new(crate::cache::HybridAdvisoryCache::from_config(config));
    let h1 = positive.spawn_default_cleanup_task();
    let negative = Arc::new(crate::cache::HybridAdvisoryCache::negative_from_config(
        config,
    ));
    let h2 = negative.spawn_default_cleanup_task();

    let positive_dyn = Arc::clone(&positive) as Arc<dyn crate::cache::AdvisoryWriteCache>;
    let negative_dyn = Arc::clone(&negative) as Arc<dyn crate::cache::AdvisoryWriteCache>;
    let osv_client = Arc::new(OsvClient::with_shared_client_and_caches(
        http_client,
        positive_dyn,
        negative_dyn,
    ));

    AdvisoryRuntime {
        positive,
        negative,
        osv_client,
        cleanup_handles: vec![h1, h2],
    }
}

/// Context passed to the background vulnerability fetch task so it can store
/// per-document transitive attribution after the query completes.
struct VulnBgContext {
    documents: Arc<DashMap<Url, DocumentState>>,
    uri: Url,
    lockfile_graph: Option<std::sync::Arc<crate::parsers::lockfile_graph::LockfileGraph>>,
}

/// The main LSP backend for Depsy.
///
/// `DepsyBackend` implements [`tower_lsp::LanguageServer`] and owns every
/// piece of shared state required to serve LSP requests: parsed document state,
/// version and advisory caches, registry clients, parsers, and the OSV
/// vulnerability client.
///
/// # Responsibilities
///
/// - Parsing manifest files into [`crate::parsers::Dependency`] lists via
///   ecosystem-specific parsers.
/// - Fetching and caching package metadata from remote registries.
/// - Running vulnerability queries against the OSV API and caching results.
/// - Publishing diagnostics, inlay hints, code actions, and completions.
/// - Managing per-URI debounce tasks so rapid edits do not flood the network.
///
/// # Cloning
///
/// `DepsyBackend` is `Clone` (required by tower-lsp) but cloning is cheap:
/// every field is either `Clone` by value (primitives, `Client`) or an `Arc`
/// handle. All clones share the same underlying state.
///
/// # Construction
///
/// Use [`DepsyBackend::new`] for production. Use
/// [`DepsyBackend::with_http_client`] in tests to inject a pre-built
/// `reqwest::Client` (e.g. one backed by a mock server).
pub struct DepsyBackend {
    client: Client,
    /// Configuration (Arc-wrapped for sharing with debounce tasks)
    config: Arc<RwLock<Config>>,
    /// Cache for documents and their parsed state (Arc-wrapped for sharing with debounce tasks)
    documents: Arc<DashMap<Url, DocumentState>>,
    /// Cache for version information (keyed by "registry:package")
    version_cache: Arc<HybridCache>,
    /// Parsers (Arc-wrapped for sharing with debounce tasks)
    cargo_parser: Arc<CargoParser>,
    npm_parser: Arc<NpmParser>,
    python_parser: Arc<PythonParser>,
    go_parser: Arc<GoParser>,
    php_parser: Arc<PhpParser>,
    dart_parser: Arc<DartParser>,
    csharp_parser: Arc<CsharpParser>,
    ruby_parser: Arc<RubyParser>,
    maven_parser: Arc<MavenParser>,
    /// Registry clients
    crates_io: Arc<CratesIoRegistry>,
    /// Cargo alternative registries (registry name -> sparse registry client)
    cargo_custom_registries: Arc<DashMap<String, Arc<CargoSparseRegistry>>>,
    /// npm registry (tokio::sync::RwLock-wrapped to allow reconfiguration during initialize)
    npm_registry: Arc<tokio::sync::RwLock<NpmRegistry>>,
    pypi: Arc<PyPiRegistry>,
    go_proxy: Arc<GoProxyRegistry>,
    packagist: Arc<PackagistRegistry>,
    pub_dev: Arc<PubDevRegistry>,
    nuget: Arc<NuGetRegistry>,
    rubygems: Arc<RubyGemsRegistry>,
    maven_central: Arc<tokio::sync::RwLock<MavenCentralRegistry>>,
    /// Shared HTTP client for creating new registry instances
    http_client: Arc<HttpClient>,
    /// Token provider manager for authentication across all ecosystems
    token_manager: Arc<TokenProviderManager>,
    /// Vulnerability scanning. Wrapped in `RwLock` so [`Self::initialize`]
    /// can swap the client to one wired with caches built from the user's
    /// `AdvisoryCacheConfig` once the LSP receives client settings.
    osv_client: Arc<tokio::sync::RwLock<Arc<OsvClient>>>,
    vuln_cache: Arc<VulnerabilityCache>,
    /// RustSec advisory cache (issue #237).
    ///
    /// Held on the struct so the background cleanup task spawned by
    /// `HybridAdvisoryCache::spawn_default_cleanup_task` keeps a strong
    /// reference to the underlying memory/SQLite layers for the lifetime of
    /// the backend. Wrapped in `RwLock` so [`Self::initialize`] can swap in
    /// a cache built from the user's `AdvisoryCacheConfig`. Exposed via
    /// [`DepsyBackend::advisory_cache`] for tests and observability.
    advisory_cache: Arc<tokio::sync::RwLock<Arc<crate::cache::HybridAdvisoryCache>>>,
    /// Negative RustSec advisory cache (issue #237).
    ///
    /// Same shape as [`Self::advisory_cache`] but with `negative_ttl_secs`
    /// and no SQLite layer — 404 entries should not be persisted across
    /// LSP sessions. Held on the struct so the spawned cleanup task can
    /// keep strong references. Wrapped in `RwLock` for the same
    /// reconfiguration reason as `advisory_cache`.
    negative_advisory_cache: Arc<tokio::sync::RwLock<Arc<crate::cache::HybridAdvisoryCache>>>,
    /// `JoinHandle`s for the advisory cache cleanup tasks (issue #237).
    ///
    /// `initialize` rebuilds the advisory runtime and must abort the previous
    /// cleanup tasks before installing the new caches; otherwise the old
    /// tasks keep ticking forever holding `Arc` clones of the previous
    /// memory/SQLite layers (a slow leak that grows on every reconfigure).
    advisory_cleanup_handles: Arc<tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    /// Debounce tasks for did_change notifications (per-URI)
    /// Maps URI -> (generation, JoinHandle) for safe cleanup with racing tasks
    debounce_tasks: Arc<DashMap<Url, (u64, tokio::task::JoinHandle<()>)>>,
    /// Generation counter for debounce tasks (incremented on each spawn)
    debounce_generation: Arc<std::sync::atomic::AtomicU64>,
    /// Pending content changes awaiting debounce completion
    pending_changes: Arc<DashMap<Url, String>>,
}

impl DepsyBackend {
    /// Create a new [`DepsyBackend`] with default configuration, parsers,
    /// registry clients, caches, and an OSV client.
    ///
    /// Builds a shared `reqwest::Client` internally (TLS-enabled) and uses it
    /// for all outbound HTTP traffic. All registry clients, the advisory cache,
    /// and the OSV client are initialised from [`crate::config::Config::default`].
    /// The configuration is replaced by the values received in the LSP
    /// `initialize` request.
    ///
    /// # Parameters
    ///
    /// - `client`: The tower-lsp [`Client`] handle used to push diagnostics,
    ///   inlay-hint refresh requests, and other server-initiated messages to the
    ///   editor.
    ///
    /// # Examples
    ///
    /// ```text
    /// // Obtain an LSP `Client` from the tower-lsp runtime and pass it in:
    /// //
    /// //   let (service, socket) = LspService::new(DepsyBackend::new);
    /// //   Server::new(stdin, stdout, socket).serve(service).await;
    /// //
    /// // See the integration tests under depsy-lsp/tests/ for a full example.
    /// ```
    pub fn new(client: Client) -> Self {
        Self::with_http_client(client, None)
    }

    /// Create a [`DepsyBackend`] with an optional pre-built HTTP client.
    ///
    /// This is the canonical constructor used by both [`DepsyBackend::new`] and
    /// integration tests. Passing `None` for `http_client` is equivalent to
    /// calling [`DepsyBackend::new`]: a shared `reqwest::Client` is built
    /// automatically.
    ///
    /// Passing `Some(client)` lets tests inject a mock HTTP client (e.g. one
    /// pointing at a local wiremock server) without touching the network.
    ///
    /// # Parameters
    ///
    /// - `client`: The tower-lsp [`Client`] handle for server-initiated messages.
    /// - `http_client`: Optional pre-built `reqwest::Client`. Pass `None` to use
    ///   the default TLS-enabled client.
    ///
    /// # Panics
    ///
    /// Panics if `http_client` is `None` and building the default
    /// `reqwest::Client` fails (e.g. TLS initialisation error on the current
    /// platform).
    pub fn with_http_client(client: Client, http_client: Option<Arc<HttpClient>>) -> Self {
        let http_client = http_client.unwrap_or_else(|| {
            create_shared_client().expect("Failed to create shared HTTP client")
        });

        let config = Config::default();
        let npm_registry = Arc::new(tokio::sync::RwLock::new(
            NpmRegistry::with_client_and_config(Arc::clone(&http_client), &config.registries.npm),
        ));
        let maven_central = Arc::new(tokio::sync::RwLock::new(
            MavenCentralRegistry::with_client_and_config(
                Arc::clone(&http_client),
                &config.registries.maven,
            ),
        ));

        // Create token provider manager for centralized auth management
        let token_manager = Arc::new(TokenProviderManager::new());

        // Build the RustSec advisory caches (issue #237) from defaults so the
        // backend has a working OsvClient even before `initialize` arrives.
        // The trio is wrapped in RwLock and replaced in `initialize` once the
        // user's `AdvisoryCacheConfig` is parsed; otherwise client overrides
        // (custom `db_path`, custom TTLs, `enabled = false`) would never take
        // effect because the LSP cannot see them at struct-construction time.
        let runtime = build_advisory_runtime(&config.advisory_cache, Arc::clone(&http_client));
        let advisory_cache = runtime.positive;
        let negative_advisory_cache = runtime.negative;
        let osv_client = runtime.osv_client;
        let advisory_cleanup_handles = runtime.cleanup_handles;

        Self {
            client,
            config: Arc::new(RwLock::new(config)),
            documents: Arc::new(DashMap::new()),
            version_cache: Arc::new(HybridCache::new()),
            cargo_parser: Arc::new(CargoParser::new()),
            npm_parser: Arc::new(NpmParser::new()),
            python_parser: Arc::new(PythonParser::new()),
            go_parser: Arc::new(GoParser::new()),
            php_parser: Arc::new(PhpParser::new()),
            dart_parser: Arc::new(DartParser::new()),
            csharp_parser: Arc::new(CsharpParser::new()),
            ruby_parser: Arc::new(RubyParser::new()),
            maven_parser: Arc::new(MavenParser::new()),
            crates_io: Arc::new(CratesIoRegistry::with_client(Arc::clone(&http_client))),
            cargo_custom_registries: Arc::new(DashMap::new()),
            npm_registry,
            pypi: Arc::new(PyPiRegistry::with_client(Arc::clone(&http_client))),
            go_proxy: Arc::new(GoProxyRegistry::with_client(Arc::clone(&http_client))),
            packagist: Arc::new(PackagistRegistry::with_client(Arc::clone(&http_client))),
            pub_dev: Arc::new(PubDevRegistry::with_client(Arc::clone(&http_client))),
            nuget: Arc::new(NuGetRegistry::with_client(Arc::clone(&http_client))),
            rubygems: Arc::new(RubyGemsRegistry::with_client(Arc::clone(&http_client))),
            maven_central,
            http_client,
            token_manager,
            osv_client: Arc::new(tokio::sync::RwLock::new(osv_client)),
            vuln_cache: Arc::new(VulnerabilityCache::new()),
            advisory_cache: Arc::new(tokio::sync::RwLock::new(advisory_cache)),
            negative_advisory_cache: Arc::new(tokio::sync::RwLock::new(negative_advisory_cache)),
            advisory_cleanup_handles: Arc::new(tokio::sync::Mutex::new(advisory_cleanup_handles)),
            debounce_tasks: Arc::new(DashMap::new()),
            debounce_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            pending_changes: Arc::new(DashMap::new()),
        }
    }

    /// Return a clone of the current positive advisory cache.
    ///
    /// Returns the hybrid memory+SQLite [`crate::cache::HybridAdvisoryCache`]
    /// that [`crate::vulnerabilities::osv::OsvClient`] consults
    /// before issuing HTTP requests for individual RustSec advisories.
    ///
    /// The cache is wrapped in a [`tokio::sync::RwLock`] so the `initialize`
    /// handler can atomically swap in a cache built from the user's
    /// [`crate::config::AdvisoryCacheConfig`]. This method acquires a read
    /// lock and returns an `Arc` clone — callers do not hold the lock.
    ///
    /// Primarily used by integration tests and observability tooling.
    pub async fn advisory_cache(&self) -> Arc<crate::cache::HybridAdvisoryCache> {
        Arc::clone(&*self.advisory_cache.read().await)
    }

    /// Return a clone of the current negative advisory cache.
    ///
    /// The negative cache stores "not-found" (HTTP 404) advisory responses so
    /// the server does not re-query OSV for packages with no known advisories.
    /// Unlike the positive cache it has no SQLite backing layer — 404 entries
    /// should not persist across LSP sessions.
    ///
    /// Primarily used by integration tests to inspect 404 caching state.
    pub async fn negative_advisory_cache(&self) -> Arc<crate::cache::HybridAdvisoryCache> {
        Arc::clone(&*self.negative_advisory_cache.read().await)
    }

    async fn create_processing_context(&self) -> ProcessingContext {
        ProcessingContext {
            client: self.client.clone(),
            config: Arc::clone(&self.config),
            documents: Arc::clone(&self.documents),
            version_cache: Arc::clone(&self.version_cache),
            cargo_parser: Arc::clone(&self.cargo_parser),
            npm_parser: Arc::clone(&self.npm_parser),
            python_parser: Arc::clone(&self.python_parser),
            go_parser: Arc::clone(&self.go_parser),
            php_parser: Arc::clone(&self.php_parser),
            dart_parser: Arc::clone(&self.dart_parser),
            csharp_parser: Arc::clone(&self.csharp_parser),
            ruby_parser: Arc::clone(&self.ruby_parser),
            maven_parser: Arc::clone(&self.maven_parser),
            crates_io: Arc::clone(&self.crates_io),
            cargo_custom_registries: Arc::clone(&self.cargo_custom_registries),
            npm_registry: Arc::clone(&self.npm_registry),
            pypi: Arc::clone(&self.pypi),
            go_proxy: Arc::clone(&self.go_proxy),
            packagist: Arc::clone(&self.packagist),
            pub_dev: Arc::clone(&self.pub_dev),
            nuget: Arc::clone(&self.nuget),
            rubygems: Arc::clone(&self.rubygems),
            maven_central: Arc::clone(&self.maven_central),
            osv_client: Arc::clone(&*self.osv_client.read().await),
            vuln_cache: Arc::clone(&self.vuln_cache),
        }
    }

    async fn get_version_info(
        &self,
        file_type: FileType,
        package_name: &str,
        cargo_registry: Option<&str>,
    ) -> Option<VersionInfo> {
        let cache_key = match (cargo_registry, file_type) {
            (Some(registry), FileType::Cargo) => {
                format!("crates:{registry}:{package_name}")
            }
            _ => file_type.cache_key(package_name),
        };

        // Check cache first
        if let Some(cached) = self.version_cache.get(&cache_key).await {
            return Some(cached);
        }

        // Fetch from appropriate registry
        let result = match file_type {
            FileType::Cargo => {
                if let Some(reg_name) = cargo_registry {
                    if let Some(reg) = self.cargo_custom_registries.get(reg_name) {
                        reg.get_version_info(package_name).await
                    } else {
                        self.crates_io.get_version_info(package_name).await
                    }
                } else {
                    self.crates_io.get_version_info(package_name).await
                }
            }
            FileType::Npm => {
                self.npm_registry
                    .read()
                    .await
                    .get_version_info(package_name)
                    .await
            }
            FileType::Python => self.pypi.get_version_info(package_name).await,
            FileType::Go => self.go_proxy.get_version_info(package_name).await,
            FileType::Php => self.packagist.get_version_info(package_name).await,
            FileType::Dart => self.pub_dev.get_version_info(package_name).await,
            FileType::Csharp => self.nuget.get_version_info(package_name).await,
            FileType::Ruby => self.rubygems.get_version_info(package_name).await,
            FileType::Maven => {
                self.maven_central
                    .read()
                    .await
                    .get_version_info(package_name)
                    .await
            }
        };

        match result {
            Ok(info) => {
                self.version_cache.insert(cache_key, info.clone()).await;
                Some(info)
            }
            Err(e) => {
                tracing::warn!("Failed to fetch version info for {}: {}", package_name, e);
                None
            }
        }
    }

    async fn fetch_vulnerabilities_background(
        dependencies: Vec<crate::parsers::Dependency>,
        file_type: FileType,
        osv_client: Arc<OsvClient>,
        vuln_cache: Arc<VulnerabilityCache>,
        client: Client,
        bg_ctx: VulnBgContext,
    ) {
        let ecosystem = file_type.to_ecosystem();

        // Collect transitive packages from the lockfile graph.
        // Names are canonicalized to match the lockfile graph keys (Python/PHP/Ruby normalize).
        // Also build a reverse map so that normalized parent names from reverse_index can be
        // translated back to the raw manifest name used as keys in diagnostics/hover lookups.
        let (direct_names, normalized_to_raw): (Vec<String>, HashMap<String, String>) = {
            let mut names = Vec::with_capacity(dependencies.len());
            let mut map: HashMap<String, String> = HashMap::new();
            for d in dependencies.iter() {
                let canonical = match file_type {
                    FileType::Python => crate::parsers::python_lock::normalize_python_name(&d.name),
                    FileType::Php => {
                        crate::parsers::composer_lock::normalize_composer_name(&d.name)
                    }
                    FileType::Ruby => crate::parsers::gemfile_lock::normalize_gem_name(&d.name),
                    _ => d.name.clone(),
                };
                names.push(canonical.clone());
                map.insert(canonical, d.name.clone());
            }
            (names, map)
        };
        let transitives: Vec<crate::parsers::lockfile_graph::LockfilePackage> = bg_ctx
            .lockfile_graph
            .as_deref()
            .map(|g| {
                g.transitives_only(&direct_names)
                    .into_iter()
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        // Build queries for direct packages not in vulnerability cache.
        // Track the filtered subset so we can correlate results back.
        let mut direct_queries: Vec<VulnerabilityQuery> = Vec::new();
        let mut direct_query_keys: Vec<VulnCacheKey> = Vec::new();
        for dep in dependencies.iter() {
            let vuln_key = VulnCacheKey::for_dependency(ecosystem, dep);
            if vuln_cache.contains(&vuln_key) {
                continue;
            }
            direct_queries.push(VulnerabilityQuery {
                ecosystem,
                package_name: dep.name.clone(),
                version: vuln_key.version.clone(),
            });
            direct_query_keys.push(vuln_key);
        }

        // Build queries for transitive packages not in vulnerability cache.
        // Cached transitives with advisories are kept so we can still attribute them.
        let mut transitive_queries: Vec<VulnerabilityQuery> = Vec::new();
        let mut transitive_query_pkgs: Vec<&crate::parsers::lockfile_graph::LockfilePackage> =
            Vec::new();
        let mut transitive_cached_vulns: Vec<(
            &crate::parsers::lockfile_graph::LockfilePackage,
            Vec<Vulnerability>,
        )> = Vec::new();
        for t in transitives.iter() {
            let normalized_version = normalize_version_for_osv(&t.version);
            let vuln_key = VulnCacheKey::new(ecosystem, &t.name, &normalized_version);
            if let Some(result) = vuln_cache.get(&vuln_key) {
                if !result.vulnerabilities.is_empty() {
                    transitive_cached_vulns.push((t, result.vulnerabilities));
                }
                continue;
            }
            transitive_queries.push(VulnerabilityQuery {
                ecosystem,
                package_name: t.name.clone(),
                version: normalized_version,
            });
            transitive_query_pkgs.push(t);
        }

        let direct_count = direct_queries.len();
        let mut all_queries = direct_queries;
        all_queries.extend(transitive_queries);

        tracing::info!(
            "Background: Querying OSV.dev for {} packages ({} direct, {} transitive)",
            all_queries.len(),
            direct_count,
            transitive_query_pkgs.len()
        );

        // Transitive findings to attribute: the cached ones, plus the fresh ones
        // once OSV answers.
        let mut transitive_findings = transitive_cached_vulns;

        // Batch query OSV.dev
        let osv_answered = match osv_client.query_batch(&all_queries).await {
            Ok(results) => {
                let (direct_results, transitive_results) = results.split_at(direct_count);

                // Store direct results per (ecosystem, name, version), not in the
                // name-keyed version_cache: the same package can be declared at two
                // versions (two manifests, or pnpm named catalogs).
                // direct_query_keys is the filtered list (cached ones were skipped above).
                for (vuln_key, result) in direct_query_keys.into_iter().zip(direct_results.iter()) {
                    if result.deprecated {
                        tracing::info!(
                            "Background: Package {} {} is deprecated (unmaintained)",
                            vuln_key.package_name,
                            vuln_key.version
                        );
                    }
                    tracing::debug!(
                        "Background: Updated {} {} with {} vulnerabilities, deprecated={}",
                        vuln_key.package_name,
                        vuln_key.version,
                        result.vulnerabilities.len(),
                        result.deprecated
                    );
                    vuln_cache.insert(vuln_key, result.clone());
                }

                // transitive_query_pkgs is the filtered list (cached ones were skipped above).
                for (tpkg, result) in transitive_query_pkgs.iter().zip(transitive_results.iter()) {
                    let normalized_version = normalize_version_for_osv(&tpkg.version);
                    vuln_cache.insert(
                        VulnCacheKey::new(ecosystem, &tpkg.name, &normalized_version),
                        result.clone(),
                    );
                    if !result.vulnerabilities.is_empty() {
                        transitive_findings.push((tpkg, result.vulnerabilities.clone()));
                    }
                }

                tracing::info!(
                    "Background: Cached vulnerability info for {} packages",
                    direct_count
                );
                true
            }
            Err(e) => {
                tracing::warn!(
                    "Background: Failed to fetch vulnerabilities from OSV.dev: {}",
                    e
                );
                false
            }
        };

        // Attribute transitive vulnerabilities to ALL direct parents that reach them.
        // This runs even when OSV fails: process_document cleared the previous
        // findings, and the cached ones must come back.
        // Stored per-document (not in global version_cache) to avoid cross-workspace
        // contamination: transitive attribution depends on this document's lockfile graph.
        if let Some(graph) = bg_ctx.lockfile_graph.as_deref() {
            use crate::registries::TransitiveVuln;

            let inverse = graph.reverse_index(&direct_names);

            // Build per-document transitive attribution map.
            let mut transitive_vulns_by_direct: hashbrown::HashMap<String, Vec<TransitiveVuln>> =
                hashbrown::HashMap::new();

            for (tpkg, vulns) in &transitive_findings {
                // Attribute to ALL direct parents that transitively reach this package.
                let parents = inverse.get(&tpkg.name).cloned().unwrap_or_default();

                if parents.is_empty() {
                    // No known parent — attribute to "(unknown)" so we don't drop the finding.
                    for v in vulns {
                        transitive_vulns_by_direct
                            .entry_ref("(unknown)")
                            .or_default()
                            .push(TransitiveVuln {
                                package_name: tpkg.name.clone(),
                                package_version: tpkg.version.clone(),
                                vulnerability: v.clone(),
                            });
                    }
                } else {
                    for parent in &parents {
                        // Translate normalized parent name back to the raw manifest name
                        // so that diagnostics/hover lookups using dep.name succeed.
                        let raw_parent = normalized_to_raw
                            .get(parent.as_str())
                            .cloned()
                            .unwrap_or_else(|| parent.clone());
                        for v in vulns {
                            transitive_vulns_by_direct
                                .entry_ref(raw_parent.as_str())
                                .or_default()
                                .push(TransitiveVuln {
                                    package_name: tpkg.name.clone(),
                                    package_version: tpkg.version.clone(),
                                    vulnerability: v.clone(),
                                });
                        }
                        tracing::debug!(
                            "Background: Attributed {} transitive vulns from {}@{} to direct dep {}",
                            vulns.len(),
                            tpkg.name,
                            tpkg.version,
                            raw_parent
                        );
                    }
                }
            }

            // Dedup within each parent bucket.
            for bucket in transitive_vulns_by_direct.values_mut() {
                bucket.sort_by(|a, b| {
                    (&a.package_name, &a.package_version, &a.vulnerability.id).cmp(&(
                        &b.package_name,
                        &b.package_version,
                        &b.vulnerability.id,
                    ))
                });
                bucket.dedup_by(|a, b| {
                    a.package_name == b.package_name
                        && a.package_version == b.package_version
                        && a.vulnerability.id == b.vulnerability.id
                });
            }

            // Write per-document transitive findings into the DocumentState so they are
            // isolated from other workspaces that share the same global version_cache.
            if let Some(mut doc) = bg_ctx.documents.get_mut(&bg_ctx.uri) {
                doc.transitive_vulns_by_direct = transitive_vulns_by_direct;
            }
        }

        if osv_answered {
            // Refresh UI with new vulnerability data
            tracing::debug!("Background: Refreshing inlay hints after vulnerability check");
            client
                .send_request::<request::InlayHintRefreshRequest>(())
                .await
                .ok();
            client
                .send_request::<request::WorkspaceDiagnosticRefresh>(())
                .await
                .ok();

            tracing::info!("Background: Vulnerability check complete, UI updated");
        }
    }

    async fn process_document(&self, uri: &Url, content: &str) {
        self.create_processing_context()
            .await
            .process_document(uri, content)
            .await;
    }

    /// Generate a vulnerability report for a document
    async fn generate_vulnerability_report(
        &self,
        arguments: &[serde_json::Value],
    ) -> serde_json::Value {
        // Parse arguments
        let format = arguments
            .first()
            .and_then(|v| v.get("format"))
            .and_then(|v| v.as_str())
            .unwrap_or("json");

        let uri_str = arguments
            .first()
            .and_then(|v| v.get("uri"))
            .and_then(|v| v.as_str());

        // Find the document
        let (uri, doc_state) = if let Some(uri_str) = uri_str {
            if let Ok(uri) = Url::parse(uri_str) {
                if let Some(doc) = self.documents.get(&uri) {
                    (uri.clone(), Some((doc.file_type, doc.dependencies.clone())))
                } else {
                    (uri, None)
                }
            } else {
                return serde_json::json!({
                    "error": "Invalid URI format"
                });
            }
        } else {
            // Use the first open document
            if let Some(entry) = self.documents.iter().next() {
                (
                    entry.key().clone(),
                    Some((entry.value().file_type, entry.value().dependencies.clone())),
                )
            } else {
                return serde_json::json!({
                    "error": "No open documents"
                });
            }
        };

        let Some((file_type, dependencies)) = doc_state else {
            return serde_json::json!({
                "error": "Document not found or not yet processed"
            });
        };

        // Collect vulnerabilities from the version cache and per-version OSV results
        let mut hits: Vec<(&crate::parsers::Dependency, Vec<Vulnerability>)> = Vec::new();
        for dep in &dependencies {
            let cache_key = dep_cache_key(dep, file_type);
            if let Some(info) = cached_version_info(
                &self.version_cache,
                &cache_key,
                &self.vuln_cache,
                file_type.to_ecosystem(),
                dep,
            )
            .await
            {
                hits.push((dep, info.vulnerabilities));
            }
        }
        let (summary, vulnerabilities) =
            build_vulnerability_report(hits.iter().map(|(dep, vulns)| (*dep, vulns.as_slice())));

        // Generate report based on format
        match format {
            "markdown" => {
                let md = fmt_markdown_report(&uri, &summary, &vulnerabilities).to_string();
                serde_json::json!({
                    "format": "markdown",
                    "content": md
                })
            }
            _ => {
                // Default to JSON
                serde_json::json!({
                    "summary": summary,
                    "vulnerabilities": vulnerabilities,
                    "file": String::from(uri) // .to_string() clones the inner String of the Url
                })
            }
        }
    }
}

/// Format the hover content for a dependency with version info.
///
/// Extracted from the hover handler to enable unit testing.
/// Folds cached advisories into a report plus its severity summary.
///
/// A crate declared in several sections — the manifest root plus one or more
/// `[target.<cfg>]` tables — produces one [`Dependency`] per declaration, each
/// carrying its own span. They all resolve to the same cache entry, so the same
/// advisory is reachable several times; `(package, version, id)` is counted and
/// listed once so the summary is not inflated.
///
/// [`Dependency`]: crate::parsers::Dependency
fn build_vulnerability_report<'a>(
    hits: impl IntoIterator<Item = (&'a crate::parsers::Dependency, &'a [Vulnerability])>,
) -> (VulnerabilitySummary, Vec<VulnerabilityReportEntry>) {
    let mut summary = VulnerabilitySummary::default();
    let mut entries: Vec<VulnerabilityReportEntry> = Vec::new();
    let mut seen: HashSet<(&str, &str, &str)> = HashSet::new();

    for (dep, vulns) in hits {
        for vuln in vulns {
            if !seen.insert((&dep.name, &dep.version, &vuln.id)) {
                continue;
            }
            summary.total += 1;
            match vuln.severity {
                VulnerabilitySeverity::Critical => summary.critical += 1,
                VulnerabilitySeverity::High => summary.high += 1,
                VulnerabilitySeverity::Medium => summary.medium += 1,
                VulnerabilitySeverity::Low => summary.low += 1,
            }

            entries.push(VulnerabilityReportEntry {
                package: dep.name.clone(),
                version: dep.version.clone(),
                id: vuln.id.clone(),
                severity: format!("{:?}", vuln.severity).to_lowercase(),
                description: vuln.description.clone(),
                url: vuln.url.clone(),
            });
        }
    }

    (summary, entries)
}

fn format_hover_content(
    dep: &crate::parsers::Dependency,
    file_type: FileType,
    info: &VersionInfo,
    doc_transitive_vulns: &[crate::registries::TransitiveVuln],
) -> String {
    let dep_name = &*dep.name;
    let dep_version = dep.effective_version();

    fmt::from_fn(|f| {
        writeln!(f, "## {dep_name}\n")?;

        if let Some(desc) = &info.description {
            writeln!(f, "{desc}\n")?;
        }

        // Current version with release date
        let current_date_str = info
            .get_release_date(dep_version)
            .map(|dt| format!(" ({})", fmt_release_age(dt)))
            .unwrap_or_default();
        writeln!(f, "**Current:** {dep_version}{current_date_str}")?;

        if let Some(latest) = info.latest.as_deref() {
            let latest_date_str = info
                .get_release_date(latest)
                .map(|dt| format!(" ({})", fmt_release_age(dt)))
                .unwrap_or_default();
            writeln!(f, "**Latest:** {latest}{latest_date_str}")?;
        }

        if let Some(license) = info.license.as_deref() {
            writeln!(f, "**License:** {license}")?;
        }

        if let Some(repo) = info.repository.as_deref() {
            writeln!(f, "\n[Repository]({repo})")?;
        }

        if let Some(homepage) = info.homepage.as_deref() {
            writeln!(f, "[Homepage]({homepage})")?;
        }

        if dep.registry.is_none() {
            let registry_url = file_type.fmt_registry_package_url(dep_name);
            writeln!(f, "[View on {}]({registry_url})", file_type.registry_name())?;
        }

        // Add vulnerability information if present
        if !info.vulnerabilities.is_empty() {
            let vulns_count = info.vulnerabilities.len();
            let suffix = if vulns_count == 1 {
                "Vulnerability"
            } else {
                "Vulnerabilities"
            };
            writeln!(f, "\n### ⚠ {vulns_count} Security {suffix}")?;

            for vuln in &info.vulnerabilities {
                let (severity_icon, severity_str) = match vuln.severity {
                    VulnerabilitySeverity::Critical => ("⚠", "CRITICAL"),
                    VulnerabilitySeverity::High => ("▲", "HIGH"),
                    VulnerabilitySeverity::Medium => ("●", "MEDIUM"),
                    VulnerabilitySeverity::Low => ("○", "LOW"),
                };

                let id = &*vuln.id;
                if let Some(url) = vuln.url.as_deref() {
                    writeln!(f, "\n#### [{id}]({url}) - {severity_icon} {severity_str}")?;
                } else {
                    writeln!(f, "\n#### {id} - {severity_icon} {severity_str}")?;
                }
                f.write_str(&vuln.description)?;
            }
        }

        // Add transitive vulnerability information if present.
        // Uses per-document attribution (not global version_cache) to avoid cross-workspace leaks.
        if !doc_transitive_vulns.is_empty() {
            writeln!(f, "\n## Transitive vulnerabilities")?;
            for t in doc_transitive_vulns {
                let link = match &t.vulnerability.url {
                    Some(u) => format!("[{}]({u})", t.vulnerability.id),
                    None => t.vulnerability.id.clone(),
                };
                let sev = t.vulnerability.severity.as_str();
                let name = &t.package_name;
                let ver = &t.package_version;
                let desc = &t.vulnerability.description;
                writeln!(f, "- {link} **{sev}** — {name}@{ver}: {desc}")?;
            }
        }

        Ok(())
    })
    .to_string()
}

#[tower_lsp::async_trait]
impl LanguageServer for DepsyBackend {
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        // Parse configuration from initialization options
        let config = Config::from_init_options(params.initialization_options);
        tracing::info!("Configuration: {config:?}");

        // Register token providers from npm scoped registry config
        for (scope, scoped_config) in &config.registries.npm.scoped {
            if let Some(auth) = &scoped_config.auth
                && auth.is_configured()
            {
                if let Some(token) = auth.get_token() {
                    let provider = Arc::new(EnvTokenProvider::new(token.clone()));
                    self.token_manager
                        .register(scoped_config.url.clone(), provider)
                        .await;
                    tracing::info!(
                        "Registered auth provider for npm scope @{scope} -> {} (token: {})",
                        scoped_config.url,
                        fmt_redact_token(&token)
                    );
                } else {
                    tracing::warn!(
                        "Auth configured for npm scope @{scope} but token not found in env var {}",
                        auth.variable
                    );
                }
            }
        }

        tracing::info!(
            "Token manager initialized with {} providers",
            self.token_manager.provider_count().await
        );

        // Reconfigure npm registry with custom settings if provided
        {
            let new_npm_registry = NpmRegistry::with_client_and_config(
                Arc::clone(&self.http_client),
                &config.registries.npm,
            );
            let mut registry = self.npm_registry.write().await;
            *registry = new_npm_registry;
            tracing::info!(
                "npm registry configured with base URL: {}",
                config.registries.npm.url
            );
        }

        // Reconfigure Maven Central registry with custom base URL if provided
        {
            let new_maven = MavenCentralRegistry::with_client_and_config(
                Arc::clone(&self.http_client),
                &config.registries.maven,
            );
            let mut registry = self.maven_central.write().await;
            *registry = new_maven;
            tracing::info!(
                "Maven Central registry configured with base URL: {}",
                config.registries.maven.url
            );
        }

        // Configure Cargo alternative registries
        if !config.registries.cargo.registries.is_empty() {
            // Read tokens from ~/.cargo/credentials.toml (fallback auth source)
            let credential_tokens = {
                let cargo_home = std::env::var_os("CARGO_HOME")
                    .map(PathBuf::from)
                    .or_else(|| dirs::home_dir().map(|h| h.join(".cargo")));

                let mut tokens = HashMap::new();
                if let Some(cargo_home) = cargo_home {
                    let cred_path = cargo_home.join("credentials.toml");
                    let content = if let Ok(c) = tokio::fs::read_to_string(&cred_path).await {
                        c
                    } else {
                        let alt_path = cargo_home.join("credentials");
                        tokio::fs::read_to_string(&alt_path)
                            .await
                            .unwrap_or_default()
                    };

                    if !content.is_empty() {
                        tokens = cargo_credentials::parse_credentials_content(&content);
                        tracing::debug!("Loaded {} tokens from Cargo credentials", tokens.len());
                    }
                }
                tokens
            };

            for (registry_name, registry_config) in &config.registries.cargo.registries {
                // Token priority: LSP config auth > credentials.toml
                let token = registry_config
                    .auth
                    .as_ref()
                    .and_then(|auth| auth.get_token())
                    .or_else(|| credential_tokens.get(registry_name).cloned());

                if let Some(t) = token.as_deref() {
                    tracing::info!(
                        "Using auth token for Cargo registry '{registry_name}' (token: {})",
                        fmt_redact_token(t)
                    );
                }

                let registry = Arc::new(CargoSparseRegistry::with_client_and_config(
                    Arc::clone(&self.http_client),
                    registry_config.index_url.clone(),
                    token,
                ));

                self.cargo_custom_registries
                    .insert(registry_name.clone(), registry);
                tracing::info!(
                    "Configured Cargo alternative registry: {registry_name} -> {}",
                    registry_config.index_url
                );
            }

            tracing::info!(
                "Cargo alternative registries configured: {}",
                self.cargo_custom_registries.len()
            );
        }

        // Reconfigure the RustSec advisory cache trio (issue #237). The
        // backend was constructed with `Config::default()` because the LSP
        // protocol delivers client settings only at `initialize` time, so
        // user overrides for `db_path`, TTLs, or `enabled` would otherwise
        // never take effect. Abort the previous cleanup tasks before
        // installing the new runtime; otherwise they keep ticking with
        // strong references to the now-replaced caches (slow leak).
        let new_runtime =
            build_advisory_runtime(&config.advisory_cache, Arc::clone(&self.http_client));
        {
            let mut handles = self.advisory_cleanup_handles.lock().await;
            for handle in handles.drain(..) {
                handle.abort();
            }
            *handles = new_runtime.cleanup_handles;
        }
        *self.advisory_cache.write().await = new_runtime.positive;
        *self.negative_advisory_cache.write().await = new_runtime.negative;
        *self.osv_client.write().await = new_runtime.osv_client;
        tracing::info!(
            "Advisory cache reconfigured from client settings (enabled={}, ttl_secs={}, negative_ttl_secs={})",
            config.advisory_cache.enabled,
            config.advisory_cache.ttl_secs,
            config.advisory_cache.negative_ttl_secs
        );

        // Store the configuration
        if let Ok(mut cfg) = self.config.write() {
            *cfg = config;
        }

        Ok(InitializeResult {
            server_info: Some(ServerInfo {
                name: "depsy-lsp".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                inlay_hint_provider: Some(OneOf::Left(true)),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
                document_link_provider: Some(DocumentLinkOptions {
                    resolve_provider: Some(false),
                    work_done_progress_options: Default::default(),
                }),
                completion_provider: Some(CompletionOptions {
                    trigger_characters: Some(vec!["\"".to_string(), "=".to_string()]),
                    ..Default::default()
                }),
                execute_command_provider: Some(ExecuteCommandOptions {
                    commands: vec!["depsy/generateReport".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "Depsy LSP initialized")
            .await;

        // Verify all registries share the same HTTP client
        let base_client = self.crates_io.http_client();
        debug_assert!(Arc::ptr_eq(
            &base_client,
            &self.npm_registry.read().await.http_client()
        ));
        debug_assert!(Arc::ptr_eq(&base_client, &self.pypi.http_client()));
        debug_assert!(Arc::ptr_eq(&base_client, &self.go_proxy.http_client()));
        debug_assert!(Arc::ptr_eq(&base_client, &self.packagist.http_client()));
        debug_assert!(Arc::ptr_eq(&base_client, &self.pub_dev.http_client()));
        debug_assert!(Arc::ptr_eq(&base_client, &self.nuget.http_client()));
        debug_assert!(Arc::ptr_eq(&base_client, &self.rubygems.http_client()));

        tracing::info!("Depsy LSP initialized");
    }

    async fn shutdown(&self) -> Result<()> {
        tracing::info!("Depsy LSP shutting down");
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let content = params.text_document.text;

        tracing::debug!("Document opened: {}", uri);
        self.process_document(&uri, &content).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        use std::sync::atomic::Ordering;

        let uri = params.text_document.uri;

        // With FULL sync, we get the entire document content
        if let Some(change) = params.content_changes.into_iter().next() {
            tracing::debug!("Document changed: {}", uri);

            // Store pending content
            self.pending_changes
                .insert(uri.clone(), change.text.clone());

            // Cancel any existing debounce task for this URI
            if let Some((_, (_, handle))) = self.debounce_tasks.remove(&uri) {
                handle.abort();
            }

            // Increment generation for this new task
            let generation = self.debounce_generation.fetch_add(1, Ordering::SeqCst) + 1;

            // Get debounce delay from config (default 200ms)
            let debounce_ms = self
                .config
                .read()
                .map(|c| c.cache.debounce_ms)
                .unwrap_or(200);

            // Create processing context for the spawned task
            let ctx = self.create_processing_context().await;
            let uri_clone = uri.clone();
            let content = change.text;
            let pending_changes = Arc::clone(&self.pending_changes);
            let debounce_tasks = Arc::clone(&self.debounce_tasks);

            // Spawn debounced processing task
            let handle = tokio::spawn(async move {
                // Wait for debounce period
                tokio::time::sleep(Duration::from_millis(debounce_ms)).await;

                // Check if this is still the latest content (no newer changes)
                let should_process = pending_changes
                    .get(&uri_clone)
                    .map(|v| *v == content)
                    .unwrap_or(false);

                if should_process {
                    tracing::debug!("Processing document after debounce: {}", uri_clone);
                    ctx.process_document(&uri_clone, &content).await;
                    pending_changes.remove(&uri_clone);
                }

                // Clean up task handle only if generation matches (no newer task spawned)
                debounce_tasks
                    .remove_if(&uri_clone, |_, (stored_gen, _)| *stored_gen == generation);
            });

            // Store new task handle with generation
            self.debounce_tasks.insert(uri, (generation, handle));
        }
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        let uri = params.text_document.uri;

        // Re-process on save if we have the text
        if let Some(text) = params.text {
            tracing::debug!("Document saved: {}", uri);

            // Cancel any pending debounce task for this URI (save bypasses debounce)
            if let Some((_, (_, handle))) = self.debounce_tasks.remove(&uri) {
                handle.abort();
            }
            self.pending_changes.remove(&uri);

            // Process immediately on save
            self.process_document(&uri, &text).await;
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        tracing::debug!("Document closed: {}", uri);

        // Cancel any pending debounce task for this URI
        if let Some((_, (_, handle))) = self.debounce_tasks.remove(&uri) {
            handle.abort();
        }
        self.pending_changes.remove(&uri);

        self.documents.remove(&uri);

        // Clear diagnostics for this document
        self.client.publish_diagnostics(uri, vec![], None).await;
    }

    async fn inlay_hint(&self, params: InlayHintParams) -> Result<Option<Vec<InlayHint>>> {
        // Read config values and drop the guard immediately so it doesn't cross await points.
        let (show_up_to_date, ignored_packages) = {
            let Ok(config) = self.config.read() else {
                return Ok(Some(vec![]));
            };
            if !config.inlay_hints.enabled {
                return Ok(Some(vec![]));
            }
            (config.inlay_hints.show_up_to_date, config.ignore.clone())
        };

        let uri = &params.text_document.uri;

        // Clone doc data out of DashMap before any await points to avoid holding
        // the non-Send DashMap Ref guard across await boundaries.
        let (file_type, visible_deps) = {
            let Some(doc) = self.documents.get(uri) else {
                return Ok(Some(vec![]));
            };
            let file_type = doc.file_type;
            let visible_deps: Vec<_> = doc
                .dependencies
                .iter()
                .filter(|dep| {
                    // Only show hints for dependencies in the visible range
                    (params.range.start.line..=params.range.end.line)
                        .contains(&dep.version_span.line)
                })
                .filter(|dep| !crate::config::is_package_ignored(&dep.name, &ignored_packages))
                .cloned()
                .collect();
            (file_type, visible_deps)
        };

        // Pre-fetch all cache values asynchronously before the sync iterator chain.
        // Bound the fan-out so a large file or canceled inlay-hint request can't
        // enqueue an unbounded number of `spawn_blocking` SQLite jobs (which are
        // not cancelable: a dropped future may still complete the underlying op).
        // Prefetch per dependency, not per cache key: two declarations of one
        // package (pnpm named catalogs) share a key but need their own overlay.
        const PREFETCH_CONCURRENCY: usize = 8;
        let version_infos: Vec<Option<VersionInfo>> = {
            use futures::stream::{self, StreamExt};
            // Collected first: keeping the `&Dependency` closure inside the stream
            // trips a higher-ranked lifetime error in the async-trait future.
            let lookups: Vec<_> = visible_deps
                .iter()
                .map(|dep| async move {
                    cached_version_info(
                        &self.version_cache,
                        &dep_cache_key(dep, file_type),
                        &self.vuln_cache,
                        file_type.to_ecosystem(),
                        dep,
                    )
                    .await
                })
                .collect();
            stream::iter(lookups)
                .buffered(PREFETCH_CONCURRENCY)
                .collect()
                .await
        };

        let hints: Vec<InlayHint> = visible_deps
            .into_iter()
            .zip(version_infos)
            .filter_map(|(dep, version_info)| {
                let hint = create_inlay_hint(&dep, version_info.as_ref(), file_type);

                // Optionally filter out up-to-date hints
                if !show_up_to_date {
                    let label_text = match &hint.label {
                        InlayHintLabel::String(s) => s.clone(),
                        InlayHintLabel::LabelParts(parts) => {
                            parts.iter().map(|p| p.value.as_str()).collect()
                        }
                    };
                    if label_text.contains("[OK]") {
                        return None;
                    }
                }
                Some(hint)
            })
            .collect();

        tracing::debug!("Returning {} inlay hints for {}", hints.len(), uri);
        Ok(Some(hints))
    }

    async fn document_link(&self, params: DocumentLinkParams) -> Result<Option<Vec<DocumentLink>>> {
        let uri = &params.text_document.uri;

        let Some(doc) = self.documents.get(uri) else {
            return Ok(Some(vec![]));
        };

        let links = create_document_links(&doc.dependencies, &doc.file_type);
        tracing::debug!("Returning {} document links for {}", links.len(), uri);
        Ok(Some(links))
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;

        let Some(doc) = self.documents.get(uri) else {
            return Ok(None);
        };

        let file_type = doc.file_type;

        enum HoveredSpan {
            Name,
            Version,
        }

        // Find dependency at this position
        let Some((dep, hovered_span)) = doc.dependencies.iter().find_map(|d| {
            if d.name_span.contains_lsp_position(&position) {
                Some((d.clone(), HoveredSpan::Name))
            } else if d.version_span.contains_lsp_position(&position) {
                Some((d.clone(), HoveredSpan::Version))
            } else {
                None
            }
        }) else {
            return Ok(None);
        };
        let dep_name = &*dep.name;
        let hovered_span = match hovered_span {
            HoveredSpan::Name => dep.name_span,
            HoveredSpan::Version => dep.version_span,
        };

        // Snapshot per-document transitive vulns for this dependency before dropping the lock.
        let doc_transitive_vulns: Vec<crate::registries::TransitiveVuln> = doc
            .transitive_vulns_by_direct
            .get(dep_name)
            .cloned()
            .unwrap_or_default();

        // Drop the lock before async call
        drop(doc);

        // Get version info
        let mut version_info = self
            .get_version_info(file_type, dep_name, dep.registry.as_deref())
            .await;
        if let Some(info) = version_info.as_mut() {
            apply_osv_result(info, &self.vuln_cache, file_type.to_ecosystem(), &dep);
        }

        let content = match version_info {
            Some(info) => format_hover_content(&dep, file_type, &info, &doc_transitive_vulns),
            None => format!("## {dep_name}\n\nCould not fetch package information."),
        };

        Ok(Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: content,
            }),
            range: Some(Range {
                start: Position {
                    line: hovered_span.line,
                    character: hovered_span.line_start,
                },
                end: Position {
                    line: hovered_span.line,
                    character: hovered_span.line_end,
                },
            }),
        }))
    }

    async fn code_action(&self, params: CodeActionParams) -> Result<Option<CodeActionResponse>> {
        let uri = &params.text_document.uri;

        // Snapshot everything we need from the document state, then drop the
        // DashMap guard before any .await — holding a guard across .await can
        // deadlock other tasks waiting on the same key.
        let (file_type, dependencies, cache_key_map) = {
            let Some(doc) = self.documents.get(uri) else {
                return Ok(Some(vec![]));
            };
            let file_type = doc.file_type;
            let dependencies = doc.dependencies.clone();
            let cache_key_map: HashMap<String, String> = doc
                .dependencies
                .iter()
                .map(|dep| (dep.name.clone(), dep_cache_key(dep, file_type)))
                .collect();
            (file_type, dependencies, cache_key_map)
        };

        let ignored_packages = self
            .config
            .read()
            .map(|c| c.ignore.clone())
            .unwrap_or_default();

        // Detect workspace root + read .zed/settings.json (best-effort).
        // If anything fails, the Ignore action will be omitted but Update actions still work.
        let file_path = uri.to_file_path().ok();
        let workspace_root = match file_path.as_deref() {
            Some(p) => find_workspace_root(p).await,
            None => None,
        };
        let current_settings: Option<String> = match &workspace_root {
            Some(root) => {
                let settings_path = root.join(".zed").join("settings.json");
                tokio::fs::read_to_string(&settings_path).await.ok()
            }
            None => None,
        };

        let actions = create_code_actions(
            &dependencies,
            &self.version_cache,
            uri,
            params.range,
            file_type,
            |name| {
                cache_key_map
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| file_type.cache_key(name))
            },
            &ignored_packages,
            workspace_root.as_deref(),
            current_settings.as_deref(),
        )
        .await;

        Ok(Some(actions))
    }

    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        let uri = &params.text_document_position.text_document.uri;
        let position = params.text_document_position.position;

        // Snapshot everything we need from the document state, then drop the
        // DashMap guard before any .await — holding a guard across .await can
        // block other tasks waiting on the same key.
        let (file_type, dependencies, cache_key_map) = {
            let Some(doc) = self.documents.get(uri) else {
                return Ok(Some(CompletionResponse::Array(vec![])));
            };
            let file_type = doc.file_type;
            let dependencies = doc.dependencies.clone();
            let cache_key_map: HashMap<String, String> = doc
                .dependencies
                .iter()
                .map(|dep| (dep.name.clone(), dep_cache_key(dep, file_type)))
                .collect();
            (file_type, dependencies, cache_key_map)
        };

        let completions = get_completions(&dependencies, position, &self.version_cache, |name| {
            cache_key_map
                .get(name)
                .cloned()
                .unwrap_or_else(|| file_type.cache_key(name))
        })
        .await;

        match completions {
            Some(items) => Ok(Some(CompletionResponse::Array(items))),
            None => Ok(Some(CompletionResponse::Array(vec![]))),
        }
    }

    async fn execute_command(
        &self,
        params: ExecuteCommandParams,
    ) -> Result<Option<serde_json::Value>> {
        match params.command.as_str() {
            "depsy/generateReport" => {
                let report = self.generate_vulnerability_report(&params.arguments).await;
                Ok(Some(report))
            }
            _ => {
                tracing::warn!("Unknown command: {}", params.command);
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::{Dependency, Span};

    #[test]
    fn npm_manifests_are_parsed_according_to_their_file_name() {
        // Given a pnpm workspace file with a catalog and a package.json
        // When each is parsed as an npm manifest
        // Then the workspace file yields its catalog entries
        // And the package.json yields its dependency sections
        let npm_parser = NpmParser::new();
        let names = |uri: &str, content: &str| {
            let uri = Url::parse(uri).unwrap();
            parse_npm_manifest(&uri, content, &npm_parser)
                .into_iter()
                .map(|dependency| dependency.name)
                .collect::<Vec<_>>()
        };

        let workspace_names = names(
            "file:///w/pnpm-workspace.yaml",
            "catalog:\n  react: ^18.3.1\ncatalogs:\n  legacy:\n    lodash: ^4.17.21\n",
        );
        let package_names = names(
            "file:///w/package.json",
            r#"{"dependencies": {"express": "^4.18.0"}}"#,
        );

        assert_eq!(workspace_names, vec!["react", "lodash"]);
        assert_eq!(package_names, vec!["express"]);
    }

    fn make_dep(name: &str, version: &str, resolved: Option<&str>) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.to_string(),
            name_span: Span {
                line: 0,
                line_start: 0,
                line_end: name.len() as u32,
            },
            version_span: Span {
                line: 0,
                line_start: name.len() as u32 + 3,
                line_end: name.len() as u32 + 3 + version.len() as u32,
            },
            dev: false,
            optional: false,
            registry: None,
            resolved_version: resolved.map(str::to_string),
            has_additional_version_constraints: false,
        }
    }

    #[test]
    fn vulnerability_report_counts_a_crate_declared_in_several_sections_once() {
        // Same crate in [dependencies] and two [target.<cfg>.dependencies] tables:
        // three Dependency values, three spans, one cache entry.
        let root = make_dep("libc", "0.2", None);
        let linux = make_dep("libc", "0.2", None);
        let macos = make_dep("libc", "0.2", None);
        let vulns = [Vulnerability {
            id: "RUSTSEC-0000-0000".to_string(),
            severity: VulnerabilitySeverity::Critical,
            description: "boom".to_string(),
            url: None,
        }];

        let (summary, entries) = build_vulnerability_report([
            (&root, vulns.as_slice()),
            (&linux, vulns.as_slice()),
            (&macos, vulns.as_slice()),
        ]);

        assert_eq!(summary.total, 1, "{entries:#?}");
        assert_eq!(summary.critical, 1);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn vulnerability_report_keeps_distinct_advisories_and_versions() {
        let serde = make_dep("serde", "1.0", None);
        let libc = make_dep("libc", "0.2", None);
        let critical = Vulnerability {
            id: "RUSTSEC-0000-0001".to_string(),
            severity: VulnerabilitySeverity::Critical,
            description: "one".to_string(),
            url: None,
        };
        let low = Vulnerability {
            id: "RUSTSEC-0000-0002".to_string(),
            severity: VulnerabilitySeverity::Low,
            description: "two".to_string(),
            url: None,
        };

        let (summary, entries) = build_vulnerability_report([
            (&serde, std::slice::from_ref(&critical)),
            (&libc, std::slice::from_ref(&critical)),
            (&libc, std::slice::from_ref(&low)),
        ]);

        assert_eq!(summary.total, 3, "{entries:#?}");
        assert_eq!(summary.critical, 2);
        assert_eq!(summary.low, 1);
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_hover_uses_effective_version_not_manifest_specifier() {
        let dep = make_dep("serde", "^1.0", Some("1.0.200"));
        let info = VersionInfo {
            latest: Some("1.0.210".to_string()),
            ..Default::default()
        };

        let content = format_hover_content(&dep, FileType::Cargo, &info, &[]);

        // Must show the resolved version, not the manifest specifier
        assert!(
            content.contains("**Current:** 1.0.200"),
            "Hover should show effective_version '1.0.200', got:\n{content}"
        );
        assert!(
            !content.contains("**Current:** ^1.0"),
            "Hover should NOT show manifest specifier '^1.0'"
        );
    }

    #[test]
    fn test_hover_uses_manifest_version_when_no_lockfile() {
        let dep = make_dep("tokio", "1.35.0", None);
        let info = VersionInfo {
            latest: Some("1.40.0".to_string()),
            ..Default::default()
        };

        let content = format_hover_content(&dep, FileType::Cargo, &info, &[]);

        assert!(
            content.contains("**Current:** 1.35.0"),
            "Without lockfile, should show manifest version, got:\n{content}"
        );
    }

    #[test]
    fn test_hover_release_date_uses_effective_version() {
        use chrono::{TimeZone, Utc};

        let dep = make_dep("serde", "^1.0", Some("1.0.200"));
        let release_date = Utc.with_ymd_and_hms(2025, 1, 15, 0, 0, 0).unwrap();

        let mut info = VersionInfo {
            latest: Some("1.0.200".to_string()),
            ..Default::default()
        };
        // Insert release date keyed by the resolved version, NOT the specifier
        info.release_dates
            .insert("1.0.200".to_string(), release_date);

        let content = format_hover_content(&dep, FileType::Cargo, &info, &[]);

        // The release date should be found (keyed by effective_version "1.0.200")
        assert!(
            content.contains("2025-01-15") || content.contains("ago"),
            "Release date should be found via effective_version lookup, got:\n{content}"
        );
    }

    #[test]
    fn test_hover_lists_transitive_vulnerabilities() {
        use crate::registries::{TransitiveVuln, Vulnerability, VulnerabilitySeverity};

        let dep = make_dep("react", "^18.0", Some("18.2.0"));
        let info = VersionInfo {
            latest: Some("18.2.0".to_string()),
            ..Default::default()
        };
        let transitive_vulns = vec![TransitiveVuln {
            package_name: "scheduler".to_string(),
            package_version: "1.2.3".to_string(),
            vulnerability: Vulnerability {
                id: "CVE-1".to_string(),
                severity: VulnerabilitySeverity::High,
                description: "desc".to_string(),
                url: None,
            },
        }];
        let content = format_hover_content(&dep, FileType::Npm, &info, &transitive_vulns);
        assert!(
            content.contains("Transitive vulnerabilities"),
            "Hover should contain transitive section, got:\n{content}"
        );
        assert!(
            content.contains("scheduler@1.2.3"),
            "Hover should contain transitive package, got:\n{content}"
        );
        assert!(
            content.contains("CVE-1"),
            "Hover should contain transitive vuln id, got:\n{content}"
        );
    }

    #[tokio::test]
    async fn test_find_workspace_root_locates_zed_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let workspace = dir.path();
        std::fs::create_dir_all(workspace.join(".zed")).expect("create .zed");

        let nested_file = workspace.join("subdir").join("Cargo.toml");
        std::fs::create_dir_all(nested_file.parent().unwrap()).expect("create subdir");
        std::fs::write(&nested_file, "").expect("create file");

        let found = super::find_workspace_root(&nested_file).await;
        assert_eq!(found.as_deref(), Some(workspace));
    }

    #[tokio::test]
    async fn test_find_workspace_root_returns_none_when_no_zed_ancestor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("a").join("b").join("c").join("d");
        std::fs::create_dir_all(&nested).expect("create nested");
        let file = nested.join("Cargo.toml");
        std::fs::write(&file, "").expect("create file");

        let found = super::find_workspace_root(&file).await;
        assert!(
            found.is_none(),
            "expected None when no ancestor has .zed/, got {found:?}"
        );
    }

    /// Regression for issue #237 reviewer finding: `AdvisoryCacheConfig` must
    /// flow through to the SQLite layer instead of being locked to defaults.
    /// We point the helper at a custom `db_path` and verify the file appears
    /// after a write — proof that the user's config was honoured end-to-end.
    #[tokio::test]
    async fn build_advisory_runtime_honors_custom_db_path() {
        use crate::cache::{AdvisoryKind, AdvisoryWriteCache, CachedAdvisory};
        use crate::config::AdvisoryCacheConfig;
        use std::time::SystemTime;

        let tmp = tempfile::tempdir().expect("tempdir");
        let db_path = tmp.path().join("nested").join("custom.db");
        let config = AdvisoryCacheConfig {
            enabled: true,
            ttl_secs: 60,
            negative_ttl_secs: 30,
            db_path: Some(db_path.clone()),
        };

        let http_client = crate::registries::http_client::create_shared_client()
            .expect("shared client builds in test");
        let runtime = super::build_advisory_runtime(&config, http_client);
        runtime
            .positive
            .insert(CachedAdvisory {
                id: "RUSTSEC-2020-0036".into(),
                kind: AdvisoryKind::Found {
                    summary: None,
                    unmaintained: false,
                },
                fetched_at: SystemTime::now(),
            })
            .await;

        assert!(
            db_path.exists(),
            "custom db_path {db_path:?} was not honoured by the helper"
        );

        // Abort the cleanup tasks so dropping the tempdir does not leave them
        // ticking on a stale advisory_cache.db path.
        for handle in runtime.cleanup_handles {
            handle.abort();
        }
    }

    /// Holds the tower-lsp `Client` handed to a server that is never initialized,
    /// so requests sent through it fail immediately instead of waiting on a peer.
    struct UninitializedServer(Client);

    #[tower_lsp::async_trait]
    impl LanguageServer for UninitializedServer {
        async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
            Ok(InitializeResult::default())
        }

        async fn shutdown(&self) -> Result<()> {
            Ok(())
        }
    }

    /// Starts an OSV mock that reports `GHSA-vh95-rmgr-6w4m` for version 1.2.5 only.
    async fn osv_server_flagging_1_2_5() -> wiremock::MockServer {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/querybatch"))
            .respond_with(|request: &wiremock::Request| {
                let body: serde_json::Value = request.body_json().unwrap();
                let results: Vec<serde_json::Value> = body["queries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|query| {
                        if query["version"] == "1.2.5" {
                            serde_json::json!({
                                "vulns": [{ "id": "GHSA-vh95-rmgr-6w4m", "modified": "2024-01-01T00:00:00Z" }]
                            })
                        } else {
                            serde_json::json!({ "vulns": [] })
                        }
                    })
                    .collect();
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": results }))
            })
            .mount(&server)
            .await;
        server
    }

    /// Lines of the direct-vulnerability diagnostics built for `deps`.
    async fn vulnerable_lines(deps: &[Dependency], osv_results: &VulnerabilityCache) -> Vec<u32> {
        use crate::cache::MemoryCache;

        let version_cache = MemoryCache::new();
        version_cache
            .insert(
                FileType::Npm.cache_key("minimist"),
                VersionInfo {
                    latest: Some("1.2.8".to_string()),
                    ..Default::default()
                },
            )
            .await;
        create_diagnostics(
            deps,
            &version_cache,
            |name| FileType::Npm.cache_key(name),
            None,
            FileType::Npm,
            VulnSources {
                osv_results,
                transitive: &hashbrown::HashMap::new(),
            },
            &[],
        )
        .await
        .iter()
        .filter(|diagnostic| {
            matches!(&diagnostic.code, Some(NumberOrString::String(code)) if code.ends_with("-vulns"))
        })
        .map(|diagnostic| diagnostic.range.start.line)
        .collect()
    }

    #[tokio::test]
    async fn direct_vulnerabilities_follow_each_declared_version() {
        // Given minimist declared at 1.2.5 in one manifest and at 1.2.8 in another
        // And OSV reports an advisory for 1.2.5 only
        // When the background vulnerability check runs for both manifests
        // Then only the 1.2.5 declaration gets a vulnerability diagnostic
        let server = osv_server_flagging_1_2_5().await;
        let (service, _socket) = tower_lsp::LspService::new(UninitializedServer);
        let client = service.inner().0.clone();
        let osv_client = Arc::new(OsvClient::with_endpoint(server.uri()).unwrap());
        let vuln_cache = Arc::new(VulnerabilityCache::new());
        let documents = Arc::new(DashMap::new());

        let vulnerable = make_dep("minimist", "1.2.5", None);
        let mut patched = make_dep("minimist", "1.2.8", None);
        patched.name_span.line = 1;
        patched.version_span.line = 1;

        for (manifest, dep) in [("a", &vulnerable), ("b", &patched)] {
            DepsyBackend::fetch_vulnerabilities_background(
                vec![dep.clone()],
                FileType::Npm,
                Arc::clone(&osv_client),
                Arc::clone(&vuln_cache),
                client.clone(),
                VulnBgContext {
                    documents: Arc::clone(&documents),
                    uri: Url::parse(&format!("file:///{manifest}/package.json")).unwrap(),
                    lockfile_graph: None,
                },
            )
            .await;
        }

        assert_eq!(
            vulnerable_lines(&[vulnerable, patched], &vuln_cache).await,
            vec![0]
        );
    }

    #[tokio::test]
    async fn one_manifest_declaring_two_versions_keeps_them_apart() {
        // Given one manifest declaring minimist at 1.2.5 and 1.2.8 (pnpm named catalogs)
        // And OSV reports an advisory for 1.2.5 only
        // When the background vulnerability check queries both in one batch
        // Then only the 1.2.5 declaration gets a vulnerability diagnostic
        let server = osv_server_flagging_1_2_5().await;
        let (service, _socket) = tower_lsp::LspService::new(UninitializedServer);
        let vuln_cache = Arc::new(VulnerabilityCache::new());

        let vulnerable = make_dep("minimist", "1.2.5", None);
        let mut patched = make_dep("minimist", "1.2.8", None);
        patched.name_span.line = 1;
        patched.version_span.line = 1;

        DepsyBackend::fetch_vulnerabilities_background(
            vec![vulnerable.clone(), patched.clone()],
            FileType::Npm,
            Arc::new(OsvClient::with_endpoint(server.uri()).unwrap()),
            Arc::clone(&vuln_cache),
            service.inner().0.clone(),
            VulnBgContext {
                documents: Arc::new(DashMap::new()),
                uri: Url::parse("file:///pnpm-workspace.yaml").unwrap(),
                lockfile_graph: None,
            },
        )
        .await;

        assert_eq!(
            vulnerable_lines(&[vulnerable, patched], &vuln_cache).await,
            vec![0]
        );
    }

    /// Lockfile graph where direct dependency `a` pulls minimist 1.2.5.
    fn graph_a_pulling_minimist_1_2_5() -> Arc<crate::parsers::lockfile_graph::LockfileGraph> {
        use crate::parsers::lockfile_graph::{LockfileGraph, LockfilePackage};

        Arc::new(LockfileGraph {
            packages: vec![
                LockfilePackage {
                    name: "a".to_string(),
                    version: "1.0.0".to_string(),
                    dependencies: vec!["minimist".to_string()],
                    is_root: false,
                },
                LockfilePackage {
                    name: "minimist".to_string(),
                    version: "1.2.5".to_string(),
                    dependencies: vec![],
                    is_root: false,
                },
            ],
        })
    }

    #[tokio::test]
    async fn cached_transitive_vulnerabilities_are_attributed_again() {
        // Given direct dependency `a` pulling minimist 1.2.5 through the lockfile
        // And OSV reports an advisory for minimist 1.2.5
        // When the document is processed a second time, with OSV results cached
        // Then the advisory is attributed to `a` again without a new OSV query
        let server = osv_server_flagging_1_2_5().await;
        let (service, _socket) = tower_lsp::LspService::new(UninitializedServer);
        let client = service.inner().0.clone();
        let osv_client = Arc::new(OsvClient::with_endpoint(server.uri()).unwrap());
        let vuln_cache = Arc::new(VulnerabilityCache::new());
        let documents = Arc::new(DashMap::new());
        let uri = Url::parse("file:///app/package.json").unwrap();
        let direct = make_dep("a", "1.0.0", None);
        let graph = graph_a_pulling_minimist_1_2_5();

        for _ in 0..2 {
            // process_document resets the transitive findings on every run.
            documents.insert(
                uri.clone(),
                DocumentState {
                    dependencies: vec![direct.clone()],
                    file_type: FileType::Npm,
                    lockfile_graph: Some(Arc::clone(&graph)),
                    transitive_vulns_by_direct: hashbrown::HashMap::new(),
                },
            );
            DepsyBackend::fetch_vulnerabilities_background(
                vec![direct.clone()],
                FileType::Npm,
                Arc::clone(&osv_client),
                Arc::clone(&vuln_cache),
                client.clone(),
                VulnBgContext {
                    documents: Arc::clone(&documents),
                    uri: uri.clone(),
                    lockfile_graph: Some(Arc::clone(&graph)),
                },
            )
            .await;
        }

        let osv_queries = server.received_requests().await.unwrap_or_default().len();
        let attributed: Vec<String> = documents
            .get(&uri)
            .and_then(|doc| doc.transitive_vulns_by_direct.get("a").cloned())
            .unwrap_or_default()
            .into_iter()
            .map(|finding| finding.vulnerability.id)
            .collect();
        assert_eq!(
            osv_queries, 1,
            "the second run must be served from the cache"
        );
        assert_eq!(attributed, vec!["GHSA-vh95-rmgr-6w4m".to_string()]);
    }

    #[tokio::test]
    async fn cached_transitive_vulnerabilities_survive_an_osv_failure() {
        // Given direct dependency `a` pulling minimist 1.2.5 through the lockfile
        // And the minimist 1.2.5 advisory already in the vulnerability cache
        // When the document is processed again and the OSV query for `a` fails
        // Then the cached advisory is still attributed to `a`
        use crate::vulnerabilities::osv::QueryResult;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/querybatch"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let (service, _socket) = tower_lsp::LspService::new(UninitializedServer);
        let vuln_cache = Arc::new(VulnerabilityCache::new());
        vuln_cache.insert(
            VulnCacheKey::new(FileType::Npm.to_ecosystem(), "minimist", "1.2.5"),
            QueryResult {
                vulnerabilities: vec![Vulnerability {
                    id: "GHSA-vh95-rmgr-6w4m".to_string(),
                    severity: VulnerabilitySeverity::High,
                    description: String::new(),
                    url: None,
                }],
                deprecated: false,
            },
        );
        let documents = Arc::new(DashMap::new());
        let uri = Url::parse("file:///app/package.json").unwrap();
        let direct = make_dep("a", "1.0.0", None);
        let graph = graph_a_pulling_minimist_1_2_5();
        // process_document resets the transitive findings before the check.
        documents.insert(
            uri.clone(),
            DocumentState {
                dependencies: vec![direct.clone()],
                file_type: FileType::Npm,
                lockfile_graph: Some(Arc::clone(&graph)),
                transitive_vulns_by_direct: hashbrown::HashMap::new(),
            },
        );

        DepsyBackend::fetch_vulnerabilities_background(
            vec![direct],
            FileType::Npm,
            Arc::new(OsvClient::with_endpoint(server.uri()).unwrap()),
            Arc::clone(&vuln_cache),
            service.inner().0.clone(),
            VulnBgContext {
                documents: Arc::clone(&documents),
                uri: uri.clone(),
                lockfile_graph: Some(graph),
            },
        )
        .await;

        let osv_queries = server.received_requests().await.unwrap_or_default().len();
        let attributed: Vec<String> = documents
            .get(&uri)
            .and_then(|doc| doc.transitive_vulns_by_direct.get("a").cloned())
            .unwrap_or_default()
            .into_iter()
            .map(|finding| finding.vulnerability.id)
            .collect();
        assert_eq!(osv_queries, 1, "the query for `a` must reach OSV and fail");
        assert_eq!(attributed, vec!["GHSA-vh95-rmgr-6w4m".to_string()]);
    }
}
