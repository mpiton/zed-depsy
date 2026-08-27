<claude-mem-context>
# Recent Activity

### Feb 9, 2026

| ID | Time | T | Title | Read |
|----|------|---|-------|------|
| #1911 | 12:30 PM | 🔵 | Complete Configuration and Parser Code Exploration Findings | ~625 |
| #1910 | " | 🔵 | Cache Architecture with String Key-Value Storage | ~487 |

</claude-mem-context>

## Async cache API (issue #235)

The `ReadCache` and `WriteCache` traits are async (AFIT, `#[allow(async_fn_in_trait)]`),
matching the `crate::registries::Registry` pattern.

`SqliteCache` impls wrap rusqlite work in `tokio::task::spawn_blocking` so blocking
DB calls do not stall the tokio runtime. `MemoryCache` and `HybridCache` are async
in signature but do no blocking work internally.

Notes:
- `spawn_blocking` tasks are NOT cancelable. A dropped future may still complete
  the underlying DB operation.
- `init_schema`, `pool_state`, `cache_dir`, and the `SqliteCache` constructors
  remain synchronous (called once at startup or for cheap monitoring).
- Tests use `#[tokio::test]`. Tests that need a multi-threaded runtime use
  `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`.