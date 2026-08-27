//! Custom SQLite connection manager for r2d2 connection pool
//!
//! Replaces `r2d2_sqlite::SqliteConnectionManager` with a lightweight
//! implementation that internalizes PRAGMA configuration.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

/// Nanoseconds in one second — used to convert `ttl_secs` to the same unit as
/// `inserted_at` when computing expiration in SQL queries.
///
/// Centralised here so both the version cache (`cache::sqlite`) and the
/// advisory cache (`cache::advisory::sqlite`) share the same definition.
pub(crate) const NANOS_PER_SEC: i64 = 1_000_000_000;

/// Connection manager for SQLite databases used with r2d2 connection pooling.
pub struct SqliteConnectionManager {
    path: PathBuf,
    pragma_busy_timeout_ms: u32,
    pragma_cache_size_kb: i64,
}

impl SqliteConnectionManager {
    /// Create a file-based connection manager with custom PRAGMA settings.
    pub fn file_with_config(
        path: impl AsRef<Path>,
        busy_timeout_ms: u32,
        cache_size_kb: i64,
    ) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            pragma_busy_timeout_ms: busy_timeout_ms,
            pragma_cache_size_kb: cache_size_kb.max(1),
        }
    }

    /// Create an in-memory connection manager for testing with shared in-memory DBs.
    ///
    /// The `uri` should be a SQLite URI like `file:memdb0?mode=memory&cache=shared`.
    #[cfg(test)]
    pub fn in_memory(uri: &str) -> Self {
        Self {
            path: PathBuf::from(uri),
            pragma_busy_timeout_ms: 5000,
            pragma_cache_size_kb: 2000,
        }
    }
}

impl r2d2::ManageConnection for SqliteConnectionManager {
    type Connection = Connection;
    type Error = rusqlite::Error;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let conn = Connection::open(&self.path)?;
        let pragma = format!(
            "PRAGMA busy_timeout={};PRAGMA synchronous=NORMAL;PRAGMA cache_size=-{};",
            self.pragma_busy_timeout_ms, self.pragma_cache_size_kb
        );
        conn.execute_batch(&pragma)?;
        Ok(conn)
    }

    fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        conn.query_row("SELECT 1", [], |_| Ok(()))
    }

    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2d2::ManageConnection;

    #[test]
    fn test_connect_applies_pragmas() {
        let manager = SqliteConnectionManager::in_memory(":memory:");
        let conn = manager.connect().unwrap();

        let busy_timeout: u32 = conn
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();
        assert_eq!(busy_timeout, 5000);

        let synchronous: i32 = conn
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap();
        assert_eq!(synchronous, 1); // NORMAL = 1
    }

    #[test]
    fn test_is_valid() {
        let manager = SqliteConnectionManager::in_memory(":memory:");
        let mut conn = manager.connect().unwrap();
        assert!(manager.is_valid(&mut conn).is_ok());
    }

    #[test]
    fn test_has_broken() {
        let manager = SqliteConnectionManager::in_memory(":memory:");
        let mut conn = manager.connect().unwrap();
        assert!(!manager.has_broken(&mut conn));
    }

    #[test]
    fn test_file_with_config_clamps_negative_cache_size() {
        let manager = SqliteConnectionManager::file_with_config(":memory:", 1000, -5);
        assert_eq!(manager.pragma_cache_size_kb, 1);
    }

    #[test]
    fn test_pool_integration() {
        let manager = SqliteConnectionManager::in_memory(":memory:");
        let pool = r2d2::Pool::builder().max_size(2).build(manager).unwrap();
        let conn = pool.get().unwrap();
        conn.execute_batch("CREATE TABLE test (id INTEGER)")
            .unwrap();
        conn.execute("INSERT INTO test VALUES (?)", [42]).unwrap();
        let val: i32 = conn
            .query_row("SELECT id FROM test", [], |row| row.get(0))
            .unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn test_custom_config_values() {
        let manager = SqliteConnectionManager::file_with_config(":memory:", 3000, 8000);
        let conn = manager.connect().unwrap();

        let busy_timeout: u32 = conn
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();
        assert_eq!(busy_timeout, 3000);
    }

    #[test]
    fn nanos_per_sec_is_one_billion() {
        assert_eq!(super::NANOS_PER_SEC, 1_000_000_000);
    }
}
