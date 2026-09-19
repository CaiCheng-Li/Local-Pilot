//! Small SQLite access layer: one writer connection plus a bounded reader pool,
//! WAL journaling, and ordered schema migrations recorded in `schema_migrations`.
//!
//! All calls run on the blocking thread pool so async request handlers never
//! block the runtime, and no global mutex is held across unrelated work.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use rusqlite::{Connection, OpenFlags};

use crate::error::{LpError, LpResult};

pub struct Migration {
    pub version: u32,
    pub name: &'static str,
    pub sql: &'static str,
}

struct Inner {
    path: PathBuf,
    writer: Mutex<Connection>,
    readers: Mutex<Vec<Connection>>,
    max_readers: usize,
}

#[derive(Clone)]
pub struct Db {
    inner: Arc<Inner>,
}

fn open_conn(path: &Path) -> LpResult<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )?;
    conn.busy_timeout(std::time::Duration::from_secs(10))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    Ok(conn)
}

impl Db {
    /// Open (creating if needed) and migrate a database file.
    pub fn open(path: &Path, migrations: &[Migration]) -> LpResult<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(LpError::internal)?;
        }
        let writer = open_conn(path)?;
        writer.pragma_update(None, "journal_mode", "WAL")?;
        run_migrations(&writer, migrations)?;
        Ok(Self {
            inner: Arc::new(Inner {
                path: path.to_path_buf(),
                writer: Mutex::new(writer),
                readers: Mutex::new(Vec::new()),
                max_readers: 4,
            }),
        })
    }

    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// Synchronous write (for callers already on a blocking thread).
    pub fn write_sync<T>(&self, f: impl FnOnce(&mut Connection) -> LpResult<T>) -> LpResult<T> {
        let mut conn = self.inner.writer.lock();
        f(&mut conn)
    }

    /// Synchronous read using a pooled reader connection.
    pub fn read_sync<T>(&self, f: impl FnOnce(&Connection) -> LpResult<T>) -> LpResult<T> {
        let conn = {
            let mut pool = self.inner.readers.lock();
            pool.pop()
        };
        let conn = match conn {
            Some(c) => c,
            None => {
                let c = open_conn(&self.inner.path)?;
                c.pragma_update(None, "query_only", "ON")?;
                c
            }
        };
        let result = f(&conn);
        let mut pool = self.inner.readers.lock();
        if pool.len() < self.inner.max_readers {
            pool.push(conn);
        }
        result
    }

    pub async fn write<T, F>(&self, f: F) -> LpResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> LpResult<T> + Send + 'static,
    {
        let db = self.clone();
        tokio::task::spawn_blocking(move || db.write_sync(f))
            .await
            .map_err(|e| LpError::internal(format!("db task: {e}")))?
    }

    pub async fn read<T, F>(&self, f: F) -> LpResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> LpResult<T> + Send + 'static,
    {
        let db = self.clone();
        tokio::task::spawn_blocking(move || db.read_sync(f))
            .await
            .map_err(|e| LpError::internal(format!("db task: {e}")))?
    }

    /// Run a quick integrity check (used at startup).
    pub fn quick_check(&self) -> LpResult<bool> {
        self.read_sync(|c| {
            let r: String = c.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
            Ok(r == "ok")
        })
    }

    /// Approximate on-disk size in bytes (main file + WAL).
    pub fn size_bytes(&self) -> u64 {
        let main = std::fs::metadata(&self.inner.path)
            .map(|m| m.len())
            .unwrap_or(0);
        let wal = std::fs::metadata(self.inner.path.with_extension("db-wal"))
            .map(|m| m.len())
            .unwrap_or(0);
        main + wal
    }
}

fn run_migrations(conn: &Connection, migrations: &[Migration]) -> LpResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at INTEGER NOT NULL
        );",
    )?;
    let current: u32 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |r| r.get(0),
    )?;
    let newest = migrations.iter().map(|m| m.version).max().unwrap_or(0);
    if current > newest {
        return Err(LpError::new(
            crate::ErrorCode::ConfigFault,
            format!("database schema version {current} is newer than this build ({newest})"),
        ));
    }
    for m in migrations.iter().filter(|m| m.version > current) {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let res = conn.execute_batch(m.sql).and_then(|_| {
            conn.execute(
                "INSERT INTO schema_migrations(version, name, applied_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![m.version, m.name, crate::time::now_ms()],
            )
        });
        match res {
            Ok(_) => conn.execute_batch("COMMIT")?,
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(LpError::internal(format!(
                    "migration {} failed: {e}",
                    m.name
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIGS: &[Migration] = &[
        Migration {
            version: 1,
            name: "init",
            sql: "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);",
        },
        Migration {
            version: 2,
            name: "add",
            sql: "ALTER TABLE t ADD COLUMN w TEXT;",
        },
    ];

    #[tokio::test]
    async fn migrates_and_reads() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.db");
        let db = Db::open(&p, MIGS).unwrap();
        db.write(|c| {
            c.execute("INSERT INTO t(v, w) VALUES ('a', 'b')", [])?;
            Ok(())
        })
        .await
        .unwrap();
        let n: i64 = db
            .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(n, 1);
        drop(db);
        // Re-open is idempotent.
        let db = Db::open(&p, MIGS).unwrap();
        assert!(db.quick_check().unwrap());
        // FTS5 is available in the bundled build.
        db.write(|c| {
            c.execute_batch("CREATE VIRTUAL TABLE f USING fts5(name)")?;
            Ok(())
        })
        .await
        .unwrap();
    }
}
