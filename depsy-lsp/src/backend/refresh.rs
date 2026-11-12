//! Background refresh of the data behind open documents.
//!
//! Each tick refetches the registry data that expired or failed to load, and
//! queries OSV again for the dependencies whose result expired or never came.
//! Failures back off per package, or per document for OSV, so a registry that
//! is down is not hammered.

use std::any::Any;
use std::collections::BTreeSet;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use futures::stream::StreamExt;
use hashbrown::{HashMap, HashSet};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tower_lsp::lsp_types::{Url, request};

use super::{
    DepsyBackend, FETCH_CONCURRENCY, FetchTarget, ProcessingContext, VulnBgContext,
    configured_registries, dep_cache_key,
};
use crate::cache::ReadCache;
use crate::config::is_package_ignored;
use crate::file_types::FileType;
use crate::parsers::Dependency;
use crate::parsers::lockfile_graph::LockfileGraph;
use crate::providers::inlay_hints::is_local_dependency;
use crate::vulnerabilities::cache::VulnCacheKey;
use crate::vulnerabilities::npm_alias_package;

/// How often open documents are checked for missing or expired data.
pub(super) const REFRESH_INTERVAL: Duration = Duration::from_secs(10);
/// Delay before the first retry of a failed lookup; doubles per failure up to [`MAX_RETRY_DELAY`].
const FIRST_RETRY_DELAY: Duration = Duration::from_secs(10);
/// Longest delay between two retries of a lookup that keeps failing.
const MAX_RETRY_DELAY: Duration = Duration::from_mins(30);

/// Failed lookups by key: when the next attempt is due and the delay to apply if it fails too.
#[derive(Default)]
struct RetryBackoff(HashMap<String, (Instant, Duration)>);

impl RetryBackoff {
    /// Whether `key` failed recently and its next attempt is not due yet at `now`.
    fn is_waiting(&self, key: &str, now: Instant) -> bool {
        self.0.get(key).is_some_and(|(due, _)| *due > now)
    }

    /// Records a failure at `now` and returns the delay until the next attempt.
    fn failed(&mut self, key: &str, now: Instant) -> Duration {
        let delay = self
            .0
            .get(key)
            .map_or(FIRST_RETRY_DELAY, |(_, delay)| *delay);
        self.0.insert(
            key.to_string(),
            (now + delay, (delay * 2).min(MAX_RETRY_DELAY)),
        );
        delay
    }

    /// Forgets the failures of `key`: its next attempt is due whenever it is needed again.
    fn succeeded(&mut self, key: &str) {
        self.0.remove(key);
    }

    /// Forgets the keys `keep` rejects, so entries of closed documents do not pile up.
    fn retain(&mut self, mut keep: impl FnMut(&str) -> bool) {
        self.0.retain(|key, _| keep(key));
    }
}

/// What the registry refresh remembers from one tick to the next.
#[derive(Default)]
struct RefreshState {
    backoff: RetryBackoff,
    /// Cache keys of the packages open documents last rendered without fresh data.
    unfresh: HashSet<String>,
}

/// A package open documents depend on, and the documents to republish when it changes.
struct RefreshTarget {
    fetch: FetchTarget,
    users: BTreeSet<Url>,
}

/// An open document that needs another OSV query.
struct VulnScan {
    uri: Url,
    dependencies: Vec<Dependency>,
    file_type: FileType,
    lockfile_graph: Option<Arc<LockfileGraph>>,
    pass: u64,
}

impl ProcessingContext {
    /// Lists the registry packages of open documents, without local and ignored dependencies.
    fn collect_refresh_targets(&self) -> HashMap<String, RefreshTarget> {
        let ignored = self
            .config
            .read()
            .map(|c| c.ignore.clone())
            .unwrap_or_default();

        let registries = configured_registries(&self.config);
        let mut targets: HashMap<String, RefreshTarget> = HashMap::new();
        for doc in self.documents.iter() {
            for dep in &doc.dependencies {
                // An npm alias is published under another name than the one this
                // pass would fetch.
                if is_local_dependency(dep.declared_spec())
                    || npm_alias_package(doc.file_type.to_ecosystem(), dep).is_some()
                    || is_package_ignored(&dep.name, &ignored)
                {
                    continue;
                }
                targets
                    .entry_ref(dep_cache_key(dep, doc.file_type, &registries).as_str())
                    .or_insert_with(|| RefreshTarget {
                        fetch: FetchTarget::of(dep, doc.file_type, &registries),
                        users: BTreeSet::new(),
                    })
                    .users
                    .insert(doc.key().clone());
            }
        }
        targets
    }

    /// Republishes `uris` and asks the editor to refresh its inlay hints.
    async fn republish(&self, uris: &BTreeSet<Url>) {
        if uris.is_empty() {
            return;
        }
        for uri in uris {
            self.publish_diagnostics(uri).await;
        }
        self.client
            .send_request::<request::InlayHintRefreshRequest>(())
            .await
            .ok();
    }

    /// Refetches the packages of open documents that have no fresh data and republishes their documents.
    ///
    /// Responses are cached and shown as they arrive, so one slow registry does not hold back the
    /// others. A package another code path fetched meanwhile is republished too: the documents
    /// using it were rendered without it. Returns the number of packages fetched here.
    async fn refresh_open_documents(&self, state: &mut RefreshState) -> usize {
        let targets = self.collect_refresh_targets();
        state.backoff.retain(|key| targets.contains_key(key));
        state.unfresh.retain(|key| targets.contains_key(key));

        let now = Instant::now();
        let mut due = Vec::new();
        let mut fetched_elsewhere = BTreeSet::new();
        for (key, target) in &targets {
            if self.version_cache.contains(key).await {
                state.backoff.succeeded(key);
                if state.unfresh.remove(key) {
                    fetched_elsewhere.extend(target.users.iter().cloned());
                }
                continue;
            }
            state.unfresh.insert(key.clone());
            if !state.backoff.is_waiting(key, now) {
                due.push(target.fetch.clone());
            }
        }
        self.republish(&fetched_elsewhere).await;

        let mut refreshed = 0;
        let mut results = pin!(self.fetch_versions(due).ready_chunks(FETCH_CONCURRENCY));
        while let Some(chunk) = results.next().await {
            let mut fetched = Vec::with_capacity(chunk.len());
            let mut uris = BTreeSet::new();
            for (target, result, started) in chunk {
                match result {
                    Ok(info) => {
                        state.backoff.succeeded(&target.key);
                        state.unfresh.remove(&target.key);
                        if let Some(target) = targets.get(&target.key) {
                            uris.extend(target.users.iter().cloned());
                        }
                        fetched.push((target.key, info, started));
                    }
                    Err(e) => {
                        let retry_in = state.backoff.failed(&target.key, Instant::now());
                        tracing::warn!(
                            "Refresh of '{}' failed, retrying in {retry_in:?}: {e}",
                            target.name
                        );
                    }
                }
            }
            if fetched.is_empty() {
                continue;
            }
            refreshed += fetched.len();
            tracing::info!(
                "Refreshed {} packages for {} open documents",
                fetched.len(),
                uris.len()
            );
            self.version_cache.insert_many(fetched).await;
            self.republish(&uris).await;
        }
        refreshed
    }

    /// Whether a dependency of `dependencies` has no live OSV result.
    fn lacks_osv_result(&self, dependencies: &[Dependency], file_type: FileType) -> bool {
        let ecosystem = file_type.to_ecosystem();
        dependencies.iter().any(|dep| {
            !self
                .vuln_cache
                .contains(&VulnCacheKey::for_dependency(ecosystem, dep))
        })
    }

    /// Queries OSV again for open documents with a dependency that has no live result.
    ///
    /// Results expire after a few hours, and the readers drop a vulnerability whose result
    /// expired, so without this a document left open would silently lose its findings.
    async fn rescan_vulnerabilities(&self, backoff: &mut RetryBackoff) {
        let security_enabled = self
            .config
            .read()
            .map(|c| c.security.enabled)
            .unwrap_or(true);
        if !security_enabled {
            return;
        }

        let now = Instant::now();
        let mut open = HashSet::new();
        let mut scans = Vec::new();
        for doc in self.documents.iter() {
            let uri = doc.key();
            open.insert(uri.to_string());
            if backoff.is_waiting(uri.as_str(), now)
                || !self.lacks_osv_result(&doc.dependencies, doc.file_type)
            {
                continue;
            }
            if let Some(pass) = self.doc_passes.current(uri) {
                scans.push(VulnScan {
                    uri: uri.clone(),
                    dependencies: doc.dependencies.clone(),
                    file_type: doc.file_type,
                    lockfile_graph: doc.lockfile_graph.clone(),
                    pass,
                });
            }
        }
        backoff.retain(|uri| open.contains(uri));

        for scan in scans {
            DepsyBackend::fetch_vulnerabilities_background(
                scan.dependencies.clone(),
                scan.file_type,
                Arc::clone(&self.osv_client),
                Arc::clone(&self.vuln_cache),
                self.client.clone(),
                VulnBgContext {
                    documents: Arc::clone(&self.documents),
                    uri: scan.uri.clone(),
                    lockfile_graph: scan.lockfile_graph,
                    doc_passes: Arc::clone(&self.doc_passes),
                    pass: scan.pass,
                },
            )
            .await;
            self.publish_diagnostics(&scan.uri).await;

            if self.lacks_osv_result(&scan.dependencies, scan.file_type) {
                let retry_in = backoff.failed(scan.uri.as_str(), Instant::now());
                tracing::warn!("OSV scan of {} failed, retrying in {retry_in:?}", scan.uri);
            } else {
                backoff.succeeded(scan.uri.as_str());
            }
        }
    }
}

/// Extracts the message of a caught panic.
fn panic_message(panic: &(dyn Any + Send)) -> &str {
    panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("panic without a message")
}

/// Runs `tick` and logs a panic instead of letting it end the refresh task.
async fn survive_panic(tick: impl Future<Output = ()>) {
    if let Err(panic) = AssertUnwindSafe(tick).catch_unwind().await {
        tracing::error!(
            "Background refresh panicked, next tick still runs: {}",
            panic_message(panic.as_ref())
        );
    }
}

/// Spawns the task refreshing the data of open documents every `interval`.
pub(super) fn spawn_refresh_task(ctx: ProcessingContext, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut state = RefreshState::default();
        let mut osv_backoff = RetryBackoff::default();
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            survive_panic(async {
                tokio::join!(
                    ctx.refresh_open_documents(&mut state),
                    ctx.rescan_vulnerabilities(&mut osv_backoff),
                );
            })
            .await;
        }
    })
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;

    use futures::SinkExt;
    use serde_json::{Value, json};
    use tokio::sync::mpsc::UnboundedReceiver;
    use tower_lsp::LanguageServer;
    use tower_lsp::LspService;
    use tower_lsp::jsonrpc::{Request, Response};
    use tower_lsp::lsp_types::{
        InlayHintLabel, InlayHintParams, Position, Range, TextDocumentIdentifier,
        WorkDoneProgressParams,
    };
    use tower_service::Service;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::super::tests::{make_dep, use_npm_registry};
    use super::*;
    use crate::cache::WriteCache;
    use crate::document::DocumentState;
    use crate::registries::VersionInfo;
    use crate::vulnerabilities::cache::VulnerabilityCache;
    use crate::vulnerabilities::osv::OsvClient;

    /// How long a test waits for something it expects to happen; never reached when it passes.
    const PATIENCE: Duration = Duration::from_secs(10);
    /// Long enough to outlast a test, so a package with this delay is still pending at its end.
    const NEVER: Duration = Duration::from_secs(600);
    /// Older than the version cache TTL.
    const EXPIRED: Duration = Duration::from_secs(2 * 60 * 60);

    fn packument(latest: &str) -> Value {
        json!({ "dist-tags": { "latest": latest }, "versions": { latest: {} } })
    }

    async fn mock_package(registry: &MockServer, name: &str, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .respond_with(response)
            .mount(registry)
            .await;
    }

    fn ok_package(latest: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(packument(latest))
    }

    async fn requests_for(registry: &MockServer, name: &str) -> usize {
        let path = format!("/{name}");
        registry
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|request| request.url.path() == path)
            .count()
    }

    fn open_document(backend: &DepsyBackend, uri: &Url, dependencies: Vec<Dependency>) {
        backend.documents.insert(
            uri.clone(),
            DocumentState {
                dependencies,
                file_type: FileType::Npm,
                lockfile_graph: None,
                transitive_vulns_by_direct: hashbrown::HashMap::new(),
            },
        );
    }

    fn manifest_uri(name: &str) -> Url {
        Url::parse(&format!("file:///{name}/package.json")).unwrap()
    }

    /// An initialized service and what it sends the editor; the requests get an empty answer.
    async fn observed_service() -> (LspService<DepsyBackend>, UnboundedReceiver<Request>) {
        observed_service_with(json!({ "advisory_cache": { "enabled": false } })).await
    }

    /// Same as [`observed_service`], initialized with `options` as its settings.
    async fn observed_service_with(
        options: Value,
    ) -> (LspService<DepsyBackend>, UnboundedReceiver<Request>) {
        let (mut service, socket) = LspService::new(DepsyBackend::in_memory);
        let (mut requests, mut responses) = socket.split();
        let (seen, observed) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(request) = requests.next().await {
                if let Some(id) = request.id().cloned() {
                    responses
                        .send(Response::from_ok(id, Value::Null))
                        .await
                        .ok();
                }
                seen.send(request).ok();
            }
        });
        let initialize = Request::build("initialize")
            .params(json!({
                "capabilities": {},
                "initializationOptions": options,
            }))
            .id(1)
            .finish();
        poll_fn(|cx| service.poll_ready(cx)).await.unwrap();
        service.call(initialize).await.unwrap();
        (service, observed)
    }

    /// Waits for a message of `wanted_method` and returns its params.
    async fn next_message(observed: &mut UnboundedReceiver<Request>, wanted_method: &str) -> Value {
        tokio::time::timeout(PATIENCE, async {
            loop {
                let request = observed.recv().await.expect("the service stopped");
                if request.method() == wanted_method {
                    return request.params().cloned().unwrap_or(Value::Null);
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the service never sent {wanted_method}"))
    }

    async fn cached_within_patience(backend: &DepsyBackend, key: &str) {
        tokio::time::timeout(PATIENCE, async {
            while !backend.version_cache.contains(key).await {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{key} was never cached"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn document_passes_and_refreshes_use_the_key_of_the_configured_registry() {
        // Given a project whose npm registry is not the public one
        let registry = MockServer::start().await;
        mock_package(&registry, "lodash", ok_package("2.0.0")).await;
        let url = registry.uri();
        let (service, _socket) = LspService::new(|client| {
            let mut config = crate::config::Config::default();
            config.advisory_cache.enabled = false;
            config.security.enabled = false;
            config.registries.npm.url = url;
            DepsyBackend::with_parts(client, None, crate::cache::HybridCache::in_memory(), config)
        });
        let backend = service.inner();
        let ctx = backend.create_processing_context().await;
        let dir = tempfile::tempdir().unwrap();
        let uri = Url::from_file_path(dir.path().join("package.json")).unwrap();

        // When a manifest using a package of that registry is processed
        ctx.process_document(&uri, r#"{"dependencies": {"lodash": "1.0.0"}}"#)
            .await;

        // Then the row and the refresh target share a key that is not the public one
        let targets = ctx.collect_refresh_targets();
        let keys: Vec<&String> = targets.keys().collect();
        assert_eq!(keys.len(), 1);
        assert_ne!(*keys[0], FileType::Npm.cache_key("lodash"));
        assert!(backend.version_cache.contains(keys[0]).await);
        assert!(
            !backend
                .version_cache
                .contains(&FileType::Npm.cache_key("lodash"))
                .await
        );
    }

    #[test]
    fn retry_backoff_doubles_up_to_its_cap() {
        let mut backoff = RetryBackoff::default();
        let now = Instant::now();

        let delays: Vec<Duration> = (0..10).map(|_| backoff.failed("npm:x", now)).collect();
        assert_eq!(delays[0], FIRST_RETRY_DELAY);
        assert_eq!(delays[1], FIRST_RETRY_DELAY * 2);
        assert_eq!(delays[9], MAX_RETRY_DELAY);

        assert!(backoff.is_waiting("npm:x", now));
        assert!(!backoff.is_waiting("npm:x", now + MAX_RETRY_DELAY));
        assert!(!backoff.is_waiting("npm:other", now));
        backoff.succeeded("npm:x");
        assert!(!backoff.is_waiting("npm:x", now));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_fetch_is_retried_without_reopening_the_document() {
        // Given a registry that fails the first request for `flaky` (a network blip)
        // and one that always fails for `gone`
        let registry = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/flaky"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&registry)
            .await;
        mock_package(&registry, "flaky", ok_package("2.0.0")).await;
        mock_package(&registry, "gone", ResponseTemplate::new(503)).await;
        let (service, _socket) = LspService::new(DepsyBackend::in_memory);
        let backend = service.inner();
        use_npm_registry(backend, &registry).await;
        let ctx = backend.create_processing_context().await;
        let dir = tempfile::tempdir().unwrap();
        let uri = Url::from_file_path(dir.path().join("package.json")).unwrap();
        ctx.process_document(
            &uri,
            r#"{"dependencies": {"flaky": "1.0.0", "gone": "1.0.0"}}"#,
        )
        .await;
        let flaky = FileType::Npm.cache_key("flaky");
        assert!(!backend.version_cache.contains(&flaky).await);

        // When the open documents are refreshed
        let mut state = RefreshState::default();
        let refreshed = ctx.refresh_open_documents(&mut state).await;

        // Then `flaky` is fetched again and cached, with no reopen or edit
        assert_eq!(refreshed, 1);
        assert!(backend.version_cache.contains(&flaky).await);

        // And `gone`, which failed again, waits for its backoff instead of being retried at once
        let before = requests_for(&registry, "gone").await;
        assert_eq!(ctx.refresh_open_documents(&mut state).await, 0);
        assert_eq!(requests_for(&registry, "gone").await, before);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn package_fetched_elsewhere_leaves_the_retry_backoff() {
        // Given an open document whose package failed its last refresh
        let (service, _socket) = LspService::new(DepsyBackend::in_memory);
        let backend = service.inner();
        let ctx = backend.create_processing_context().await;
        open_document(
            backend,
            &manifest_uri("backoff"),
            vec![make_dep("lodash", "1.0.0", None)],
        );
        let key = FileType::Npm.cache_key("lodash");
        let mut state = RefreshState::default();
        let now = Instant::now();
        state.backoff.failed(&key, now);

        // When an edit fetched it meanwhile and the refresher runs
        backend
            .version_cache
            .insert(key.clone(), VersionInfo::default())
            .await;
        assert_eq!(ctx.refresh_open_documents(&mut state).await, 0);

        // Then its backoff is gone, so a later expiry is refetched at once
        assert!(!state.backoff.is_waiting(&key, now));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expired_package_is_refetched_and_replaces_the_old_data() {
        // Given an open document whose package was cached past the TTL
        let registry = MockServer::start().await;
        mock_package(&registry, "lodash", ok_package("2.0.0")).await;
        let (service, _socket) = LspService::new(DepsyBackend::in_memory);
        let backend = service.inner();
        use_npm_registry(backend, &registry).await;
        let ctx = backend.create_processing_context().await;
        open_document(
            backend,
            &manifest_uri("expired"),
            vec![make_dep("lodash", "1.0.0", None)],
        );
        let key = FileType::Npm.cache_key("lodash");
        let old = VersionInfo {
            latest: Some("1.0.0".to_string()),
            ..VersionInfo::default()
        };
        backend
            .version_cache
            .insert_many(vec![(
                key.clone(),
                old,
                std::time::Instant::now() - EXPIRED,
            )])
            .await;
        assert!(!backend.version_cache.contains(&key).await);

        // When the open documents are refreshed
        let refreshed = ctx
            .refresh_open_documents(&mut RefreshState::default())
            .await;

        // Then the registry's answer replaces the expired data
        assert_eq!(refreshed, 1);
        let cached = backend.version_cache.get(&key).await.unwrap();
        assert_eq!(cached.latest.as_deref(), Some("2.0.0"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_and_ignored_dependencies_are_not_refreshed() {
        // Given a document with only a local path and an ignored package
        let registry = MockServer::start().await;
        let (service, _socket) = LspService::new(DepsyBackend::in_memory);
        let backend = service.inner();
        use_npm_registry(backend, &registry).await;
        backend.config.write().unwrap().ignore = vec!["internal-pkg".to_string()];
        let ctx = backend.create_processing_context().await;
        open_document(
            backend,
            &manifest_uri("skipped"),
            vec![
                make_dep("local-pkg", "file:../local-pkg", None),
                make_dep("internal-pkg", "1.0.0", None),
            ],
        );

        // When the open documents are refreshed
        let refreshed = ctx
            .refresh_open_documents(&mut RefreshState::default())
            .await;

        // Then the registry sees no request at all
        assert_eq!(refreshed, 0);
        assert!(registry.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn npm_tag_of_the_package_itself_is_refreshed_and_an_alias_is_not() {
        // Given `npm:latest`, a tag of the declared package, next to an alias of another one
        let registry = MockServer::start().await;
        mock_package(&registry, "lodash", ok_package("4.17.21")).await;
        let (service, _socket) = LspService::new(DepsyBackend::in_memory);
        let backend = service.inner();
        use_npm_registry(backend, &registry).await;
        let ctx = backend.create_processing_context().await;
        open_document(
            backend,
            &manifest_uri("tagged"),
            vec![
                make_dep("lodash", "npm:latest", None),
                make_dep("my-utils", "npm:other@^1.0.0", None),
            ],
        );

        // When the open documents are refreshed
        let refreshed = ctx
            .refresh_open_documents(&mut RefreshState::default())
            .await;

        // Then only the declared package is fetched: the alias's local name is no package
        assert_eq!(refreshed, 1);
        assert_eq!(requests_for(&registry, "lodash").await, 1);
        assert_eq!(registry.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_package_is_requested_again_once_its_backoff_is_due() {
        // Given a package whose retry came due
        let registry = MockServer::start().await;
        mock_package(&registry, "lodash", ResponseTemplate::new(503)).await;
        let (service, _socket) = LspService::new(DepsyBackend::in_memory);
        let backend = service.inner();
        use_npm_registry(backend, &registry).await;
        let ctx = backend.create_processing_context().await;
        open_document(
            backend,
            &manifest_uri("due"),
            vec![make_dep("lodash", "1.0.0", None)],
        );
        let key = FileType::Npm.cache_key("lodash");
        let mut state = RefreshState::default();
        state
            .backoff
            .failed(&key, Instant::now() - FIRST_RETRY_DELAY * 2);

        // When the open documents are refreshed
        ctx.refresh_open_documents(&mut state).await;

        // Then the registry gets the request, and the next attempt waits longer
        assert_eq!(requests_for(&registry, "lodash").await, 1);
        assert!(state.backoff.is_waiting(&key, Instant::now()));
    }

    #[tokio::test]
    async fn closed_document_leaves_the_retry_state() {
        // Given a package that failed its refresh and was never fresh
        let (service, _socket) = LspService::new(DepsyBackend::in_memory);
        let backend = service.inner();
        let ctx = backend.create_processing_context().await;
        let key = FileType::Npm.cache_key("lodash");
        let mut state = RefreshState::default();
        state.backoff.failed(&key, Instant::now());
        state.unfresh.insert(key.clone());

        // When no open document uses it any more and the refresher runs
        ctx.refresh_open_documents(&mut state).await;

        // Then it is forgotten
        assert!(state.backoff.0.is_empty());
        assert!(state.unfresh.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refresh_publishes_diagnostics_and_asks_for_new_inlay_hints() {
        // Given an open document whose package was never fetched
        let registry = MockServer::start().await;
        mock_package(&registry, "lodash", ok_package("2.0.0")).await;
        let (service, mut observed) = observed_service().await;
        let backend = service.inner();
        use_npm_registry(backend, &registry).await;
        let ctx = backend.create_processing_context().await;
        let uri = manifest_uri("publish");
        open_document(backend, &uri, vec![make_dep("lodash", "1.0.0", None)]);

        // When the open documents are refreshed
        ctx.refresh_open_documents(&mut RefreshState::default())
            .await;

        // Then the editor receives both, for that document
        let published = next_message(&mut observed, "textDocument/publishDiagnostics").await;
        assert_eq!(published["uri"], uri.as_str());
        next_message(&mut observed, "workspace/inlayHint/refresh").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deprecation_hidden_from_diagnostics_still_shows_in_the_inlay_hint() {
        // Given a deprecated package and settings that hide deprecation from diagnostics only
        let (service, mut observed) = observed_service_with(json!({
            "advisory_cache": { "enabled": false },
            "deprecated": { "show_diagnostics": false },
        }))
        .await;
        let backend = service.inner();
        backend
            .version_cache
            .insert(
                FileType::Npm.cache_key("left-pad"),
                VersionInfo {
                    latest: Some("1.0.0".to_string()),
                    deprecated: true,
                    ..VersionInfo::default()
                },
            )
            .await;
        let uri = manifest_uri("deprecated");
        open_document(backend, &uri, vec![make_dep("left-pad", "1.0.0", None)]);

        // When the document is rendered
        let ctx = backend.create_processing_context().await;
        ctx.publish_diagnostics(&uri).await;
        let published = next_message(&mut observed, "textDocument/publishDiagnostics").await;
        let hints = backend
            .inlay_hint(InlayHintParams {
                text_document: TextDocumentIdentifier { uri: uri.clone() },
                range: Range::new(Position::new(0, 0), Position::new(1, 0)),
                work_done_progress_params: WorkDoneProgressParams::default(),
            })
            .await
            .unwrap()
            .unwrap_or_default();

        // Then the diagnostics drop the deprecation and the inlay hint keeps it
        assert!(
            !published.to_string().contains("deprecated-package"),
            "got {published}"
        );
        assert_eq!(hints.len(), 1);
        let InlayHintLabel::String(label) = &hints[0].label else {
            panic!("expected a string label");
        };
        assert!(label.contains("Deprecated"), "got {label}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn package_fetched_elsewhere_republishes_the_documents_using_it() {
        // Given a document rendered while its package could not be fetched
        let registry = MockServer::start().await;
        mock_package(&registry, "lodash", ResponseTemplate::new(503)).await;
        let (service, mut observed) = observed_service().await;
        let backend = service.inner();
        use_npm_registry(backend, &registry).await;
        let ctx = backend.create_processing_context().await;
        let uri = manifest_uri("elsewhere");
        open_document(backend, &uri, vec![make_dep("lodash", "1.0.0", None)]);
        let mut state = RefreshState::default();
        ctx.refresh_open_documents(&mut state).await;

        // When another code path caches the package
        backend
            .version_cache
            .insert(FileType::Npm.cache_key("lodash"), VersionInfo::default())
            .await;
        let refreshed = ctx.refresh_open_documents(&mut state).await;

        // Then the document is republished, though this refresh fetched nothing
        assert_eq!(refreshed, 0);
        let published = next_message(&mut observed, "textDocument/publishDiagnostics").await;
        assert_eq!(published["uri"], uri.as_str());
        next_message(&mut observed, "workspace/inlayHint/refresh").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_package_does_not_hold_back_the_others() {
        // Given a document whose first package answers at once and second never does
        let registry = MockServer::start().await;
        mock_package(&registry, "fast", ok_package("2.0.0")).await;
        mock_package(&registry, "slow", ok_package("2.0.0").set_delay(NEVER)).await;
        let (service, mut observed) = observed_service().await;
        let backend = service.inner();
        use_npm_registry(backend, &registry).await;
        let ctx = backend.create_processing_context().await;
        let uri = manifest_uri("chunks");
        open_document(
            backend,
            &uri,
            vec![
                make_dep("fast", "1.0.0", None),
                make_dep("slow", "1.0.0", None),
            ],
        );

        // When the open documents are refreshed
        let refresh = tokio::spawn(async move {
            ctx.refresh_open_documents(&mut RefreshState::default())
                .await
        });

        // Then the fast package is cached and published while the slow one is pending
        let published = next_message(&mut observed, "textDocument/publishDiagnostics").await;
        assert_eq!(published["uri"], uri.as_str());
        assert!(
            backend
                .version_cache
                .contains(&FileType::Npm.cache_key("fast"))
                .await
        );
        assert!(
            !backend
                .version_cache
                .contains(&FileType::Npm.cache_key("slow"))
                .await
        );
        refresh.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refresh_task_fetches_on_its_own() {
        // Given an open document whose package was never fetched
        let registry = MockServer::start().await;
        mock_package(&registry, "lodash", ok_package("2.0.0")).await;
        let (service, _socket) = LspService::new(DepsyBackend::in_memory);
        let backend = service.inner();
        use_npm_registry(backend, &registry).await;
        let ctx = backend.create_processing_context().await;
        open_document(
            backend,
            &manifest_uri("task"),
            vec![make_dep("lodash", "1.0.0", None)],
        );

        // When the refresh task runs
        let task = spawn_refresh_task(ctx, Duration::from_millis(5));

        // Then the package gets cached without any request from the editor
        cached_within_patience(backend, &FileType::Npm.cache_key("lodash")).await;
        task.abort();
    }

    #[tokio::test]
    async fn panicking_tick_does_not_escape() {
        survive_panic(async { panic!("registry parser bug") }).await;
    }

    #[test]
    fn panic_message_reads_both_payload_types() {
        let literal: Box<dyn Any + Send> = Box::new("literal");
        let formatted: Box<dyn Any + Send> = Box::new("formatted".to_string());

        assert_eq!(panic_message(literal.as_ref()), "literal");
        assert_eq!(panic_message(formatted.as_ref()), "formatted");
    }

    /// A context whose OSV client talks to `osv`, with security enabled and an empty result cache.
    async fn context_with_osv(backend: &DepsyBackend, osv: &MockServer) -> ProcessingContext {
        backend.config.write().unwrap().security.enabled = true;
        let mut ctx = backend.create_processing_context().await;
        ctx.osv_client = Arc::new(OsvClient::with_endpoint(osv.uri()).unwrap());
        ctx.vuln_cache = Arc::new(VulnerabilityCache::with_ttl(3600));
        ctx
    }

    async fn mock_osv(osv: &MockServer, response: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path("/querybatch"))
            .respond_with(response)
            .mount(osv)
            .await;
    }

    async fn osv_requests(osv: &MockServer) -> usize {
        osv.received_requests().await.unwrap_or_default().len()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn osv_result_past_its_ttl_is_queried_again() {
        // Given an open document whose OSV result is gone
        let osv = MockServer::start().await;
        mock_osv(
            &osv,
            ResponseTemplate::new(200).set_body_json(json!({ "results": [{ "vulns": [] }] })),
        )
        .await;
        let (service, _socket) = LspService::new(DepsyBackend::in_memory);
        let backend = service.inner();
        let ctx = context_with_osv(backend, &osv).await;
        let uri = manifest_uri("rescan");
        let dep = make_dep("lodash", "1.0.0", None);
        open_document(backend, &uri, vec![dep.clone()]);
        backend.doc_passes.claim(&uri);
        let mut backoff = RetryBackoff::default();

        // When the vulnerabilities are rescanned
        ctx.rescan_vulnerabilities(&mut backoff).await;

        // Then OSV is queried and its answer kept
        assert_eq!(osv_requests(&osv).await, 1);
        let key = VulnCacheKey::for_dependency(FileType::Npm.to_ecosystem(), &dep);
        assert!(ctx.vuln_cache.contains(&key));

        // And a document with live results costs no further request
        ctx.rescan_vulnerabilities(&mut backoff).await;
        assert_eq!(osv_requests(&osv).await, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_osv_scan_backs_off() {
        // Given an OSV service that is down
        let osv = MockServer::start().await;
        mock_osv(&osv, ResponseTemplate::new(503)).await;
        let (service, _socket) = LspService::new(DepsyBackend::in_memory);
        let backend = service.inner();
        let ctx = context_with_osv(backend, &osv).await;
        let uri = manifest_uri("osv-down");
        open_document(backend, &uri, vec![make_dep("lodash", "1.0.0", None)]);
        backend.doc_passes.claim(&uri);
        let mut backoff = RetryBackoff::default();

        // When the vulnerabilities are rescanned twice
        ctx.rescan_vulnerabilities(&mut backoff).await;
        let requests = osv_requests(&osv).await;
        assert!(requests > 0);
        ctx.rescan_vulnerabilities(&mut backoff).await;

        // Then the second rescan waits for the backoff
        assert_eq!(osv_requests(&osv).await, requests);
        assert!(backoff.is_waiting(uri.as_str(), Instant::now()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disabled_security_scan_stays_off() {
        // Given a document without OSV results and security scanning turned off
        let osv = MockServer::start().await;
        let (service, _socket) = LspService::new(DepsyBackend::in_memory);
        let backend = service.inner();
        let ctx = context_with_osv(backend, &osv).await;
        backend.config.write().unwrap().security.enabled = false;
        let uri = manifest_uri("osv-off");
        open_document(backend, &uri, vec![make_dep("lodash", "1.0.0", None)]);
        backend.doc_passes.claim(&uri);

        // When the vulnerabilities are rescanned
        ctx.rescan_vulnerabilities(&mut RetryBackoff::default())
            .await;

        // Then OSV sees no request
        assert_eq!(osv_requests(&osv).await, 0);
    }
}
