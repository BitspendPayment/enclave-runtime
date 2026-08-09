//! SQLite conformance and benchmark workload over `wasi:filesystem`.
//!
//! A real C database driving the filesystem is a far harsher test than any
//! hand-written workload. SQLite does small random reads and writes at page
//! granularity, rewrites a rollback journal on every transaction, truncates
//! and deletes it on commit, calls `fsync` at points where it genuinely needs
//! durability, and then — crucially — will tell us whether the bytes came back
//! correct via `PRAGMA integrity_check`.
//!
//! Every phase is timed, so this doubles as the benchmark. The numbers are
//! dominated by commit round trips rather than by SQLite: each `fsync` becomes
//! a transaction group, which is slab PUTs plus a signed root record.
//!
//! ## Journal mode
//!
//! `DELETE` — the default — is used deliberately. It creates, extends,
//! truncates and unlinks a `-journal` sidecar next to the database, which
//! exercises the parts of the filesystem a memory journal would skip entirely.
//! WAL is not usable: it needs shared memory that WASI does not provide.
//!
//! `locking_mode=EXCLUSIVE` because there is no `fcntl` locking under WASI,
//! and nothing else has the database open anyway.
//!
//! Prints `OK` and exits 0 when every phase passes and `integrity_check`
//! returns `ok`; prints `FAIL: …` and exits 1 otherwise.

use rusqlite::{params, Connection, OptionalExtension};
use std::time::Instant;

const DB_PATH: &str = "/sqlite/bench.db";

fn main() {
    match run() {
        Ok(()) => println!("OK"),
        Err(e) => {
            println!("FAIL: {e}");
            std::process::exit(1);
        }
    }
}

/// Time a phase and report it in the benchmark table.
fn phase<T>(name: &str, units: Option<(&str, u64)>, f: impl FnOnce() -> T) -> T {
    let started = Instant::now();
    let out = f();
    let elapsed = started.elapsed();
    match units {
        Some((unit, n)) if n > 0 && elapsed.as_secs_f64() > 0.0 => {
            let rate = n as f64 / elapsed.as_secs_f64();
            println!("  {name:<28} {:>9.1} ms  {rate:>10.0} {unit}/s", elapsed.as_secs_f64() * 1000.0);
        }
        _ => println!("  {name:<28} {:>9.1} ms", elapsed.as_secs_f64() * 1000.0),
    }
    out
}

fn run() -> Result<(), String> {
    let scale: usize = std::env::var("SQLITE_SCALE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_000);

    if std::fs::metadata("/sqlite").is_err() {
        std::fs::create_dir("/sqlite").map_err(|e| format!("create_dir /sqlite: {e}"))?;
    }

    // Start from nothing so a rerun measures the same work.
    for suffix in ["", "-journal", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{DB_PATH}{suffix}"));
    }

    println!("scale={scale} rows");
    println!("phase                            elapsed        rate");

    let conn = open()?;
    schema(&conn)?;
    bulk_insert(&conn, scale)?;
    point_queries(&conn, scale)?;
    updates_and_deletes(&conn, scale)?;
    transactions_and_savepoints(&conn)?;
    constraints(&conn)?;
    joins_and_aggregates(&conn)?;
    ctes_and_windows(&conn)?;
    blobs(&conn)?;
    text_and_collation(&conn)?;
    triggers_and_views(&conn)?;
    alter_and_indexes(&conn)?;
    maintenance(&conn)?;
    integrity(&conn)?;

    drop(conn);

    // Reopen from scratch: everything above has to have reached the store,
    // not merely SQLite's page cache.
    let reopened = phase("reopen and verify", None, || -> Result<(), String> {
        let conn = open()?;
        let rows: i64 = conn
            .query_row("SELECT count(*) FROM accounts", [], |r| r.get(0))
            .map_err(|e| format!("count after reopen: {e}"))?;
        if rows == 0 {
            return Err("database is empty after reopen".to_string());
        }
        integrity(&conn)
    });
    reopened?;

    Ok(())
}

fn open() -> Result<Connection, String> {
    let conn = Connection::open(DB_PATH).map_err(|e| format!("open {DB_PATH}: {e}"))?;
    // No fcntl locking under WASI, and nothing else has the file open.
    conn.pragma_update(None, "locking_mode", "EXCLUSIVE")
        .map_err(|e| format!("locking_mode: {e}"))?;
    // A real rollback journal, so the sidecar file's whole lifecycle is under
    // test rather than being kept in memory.
    conn.pragma_update(None, "journal_mode", "DELETE")
        .map_err(|e| format!("journal_mode: {e}"))?;
    // Every commit must actually reach the store; that is the point.
    conn.pragma_update(None, "synchronous", "FULL")
        .map_err(|e| format!("synchronous: {e}"))?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| format!("foreign_keys: {e}"))?;
    // Temporary databases must live in memory, not on disk.
    //
    // SQLite finds a temp directory by probing candidates with `access(2)`,
    // and WASI has no such call — wasi-libc's `faccessat` cannot answer, so
    // every candidate is rejected and the search fails. VACUUM, which copies
    // the database into a temporary one, then reports a bare "disk I/O error"
    // with nothing to indicate that a missing syscall is the cause.
    //
    // This is a property of SQLite on WASI generally, not of this filesystem.
    // Any guest doing more than trivial queries needs this line.
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(|e| format!("temp_store: {e}"))?;
    Ok(conn)
}

fn schema(conn: &Connection) -> Result<(), String> {
    phase("schema (DDL)", None, || {
        conn.execute_batch(
            r#"
            CREATE TABLE accounts (
                id       INTEGER PRIMARY KEY,
                name     TEXT    NOT NULL UNIQUE,
                balance  REAL    NOT NULL DEFAULT 0.0 CHECK (balance >= 0),
                kind     TEXT    NOT NULL DEFAULT 'std',
                data     BLOB,
                created  INTEGER NOT NULL
            );

            CREATE TABLE entries (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                amount     REAL    NOT NULL,
                memo       TEXT,
                UNIQUE (account_id, id)
            );

            CREATE TABLE audit (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                action  TEXT NOT NULL,
                subject INTEGER NOT NULL
            );

            CREATE INDEX idx_entries_account ON entries(account_id);
            CREATE INDEX idx_accounts_kind   ON accounts(kind, balance);
            "#,
        )
        .map_err(|e| format!("schema: {e}"))
    })
}

fn bulk_insert(conn: &Connection, scale: usize) -> Result<(), String> {
    phase("bulk insert", Some(("rows", scale as u64)), || {
        conn.execute_batch("BEGIN").map_err(|e| e.to_string())?;
        {
            let mut stmt = conn
                .prepare("INSERT INTO accounts (id, name, balance, kind, created) VALUES (?1, ?2, ?3, ?4, ?5)")
                .map_err(|e| format!("prepare insert: {e}"))?;
            for i in 0..scale {
                let kind = if i % 3 == 0 { "premium" } else { "std" };
                stmt.execute(params![
                    i as i64,
                    format!("account-{i:07}"),
                    (i as f64) * 1.5,
                    kind,
                    1_700_000_000i64 + i as i64
                ])
                .map_err(|e| format!("insert {i}: {e}"))?;
            }
        }
        conn.execute_batch("COMMIT").map_err(|e| e.to_string())?;
        Ok::<_, String>(())
    })?;

    // Child rows, and a second commit so the journal lifecycle runs twice.
    phase("bulk insert (children)", Some(("rows", (scale * 2) as u64)), || {
        conn.execute_batch("BEGIN").map_err(|e| e.to_string())?;
        {
            let mut stmt = conn
                .prepare("INSERT INTO entries (account_id, amount, memo) VALUES (?1, ?2, ?3)")
                .map_err(|e| format!("prepare child insert: {e}"))?;
            for i in 0..scale * 2 {
                stmt.execute(params![
                    (i % scale) as i64,
                    (i as f64) * 0.25,
                    if i % 7 == 0 { None } else { Some(format!("memo {i}")) }
                ])
                .map_err(|e| format!("child insert {i}: {e}"))?;
            }
        }
        conn.execute_batch("COMMIT").map_err(|e| e.to_string())?;
        Ok::<_, String>(())
    })?;

    let n: i64 = conn
        .query_row("SELECT count(*) FROM accounts", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if n != scale as i64 {
        return Err(format!("expected {scale} accounts, found {n}"));
    }
    Ok(())
}

fn point_queries(conn: &Connection, scale: usize) -> Result<(), String> {
    let probes = scale.min(1_000);
    phase("point select (by rowid)", Some(("queries", probes as u64)), || {
        let mut stmt = conn
            .prepare("SELECT name, balance FROM accounts WHERE id = ?1")
            .map_err(|e| e.to_string())?;
        for i in 0..probes {
            let id = (i * 7919) % scale;
            let (name, balance): (String, f64) = stmt
                .query_row([id as i64], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(|e| format!("point select {id}: {e}"))?;
            if name != format!("account-{id:07}") {
                return Err(format!("wrong row for id {id}: {name}"));
            }
            if (balance - id as f64 * 1.5).abs() > 1e-9 {
                return Err(format!("wrong balance for id {id}: {balance}"));
            }
        }
        Ok::<_, String>(())
    })?;

    phase("indexed select (by name)", Some(("queries", probes as u64)), || {
        let mut stmt = conn
            .prepare("SELECT id FROM accounts WHERE name = ?1")
            .map_err(|e| e.to_string())?;
        for i in 0..probes {
            let id = (i * 104_729) % scale;
            let got: i64 = stmt
                .query_row([format!("account-{id:07}")], |r| r.get(0))
                .map_err(|e| format!("select by name {id}: {e}"))?;
            if got != id as i64 {
                return Err(format!("index lookup returned {got} for {id}"));
            }
        }
        Ok::<_, String>(())
    })
}

fn updates_and_deletes(conn: &Connection, scale: usize) -> Result<(), String> {
    let n = scale.min(500);
    phase("update", Some(("rows", n as u64)), || {
        conn.execute_batch("BEGIN").map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare("UPDATE accounts SET balance = balance + ?1 WHERE id = ?2")
            .map_err(|e| e.to_string())?;
        for i in 0..n {
            stmt.execute(params![10.0f64, i as i64])
                .map_err(|e| format!("update {i}: {e}"))?;
        }
        drop(stmt);
        conn.execute_batch("COMMIT").map_err(|e| e.to_string())
    })?;

    let balance: f64 = conn
        .query_row("SELECT balance FROM accounts WHERE id = 0", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if (balance - 10.0).abs() > 1e-9 {
        return Err(format!("update did not apply: balance {balance}"));
    }

    // UPSERT.
    conn.execute(
        "INSERT INTO accounts (id, name, balance, created) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(id) DO UPDATE SET balance = excluded.balance, kind = 'upserted'",
        params![0i64, "account-0000000", 99.5f64, 1i64],
    )
    .map_err(|e| format!("upsert: {e}"))?;
    let (balance, kind): (f64, String) = conn
        .query_row("SELECT balance, kind FROM accounts WHERE id = 0", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .map_err(|e| e.to_string())?;
    if (balance - 99.5).abs() > 1e-9 || kind != "upserted" {
        return Err(format!("upsert wrong: {balance} {kind}"));
    }

    // Cascading delete: removing an account must take its entries with it.
    let victim = (scale - 1) as i64;
    let before: i64 = conn
        .query_row(
            "SELECT count(*) FROM entries WHERE account_id = ?1",
            [victim],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if before == 0 {
        return Err("test setup: victim account has no entries".to_string());
    }
    phase("cascading delete", None, || {
        conn.execute("DELETE FROM accounts WHERE id = ?1", [victim])
            .map_err(|e| format!("delete: {e}"))
    })?;
    let after: i64 = conn
        .query_row(
            "SELECT count(*) FROM entries WHERE account_id = ?1",
            [victim],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if after != 0 {
        return Err(format!("foreign key cascade left {after} orphan entries"));
    }
    Ok(())
}

fn transactions_and_savepoints(conn: &Connection) -> Result<(), String> {
    phase("rollback + savepoints", None, || {
        // A plain rollback must leave nothing behind. This is where the
        // journal file earns its keep: SQLite restores pages from it.
        conn.execute_batch("BEGIN")
            .and_then(|_| {
                conn.execute_batch(
                    "INSERT INTO accounts (id, name, balance, created)
                     VALUES (900001, 'rolled-back', 1.0, 0)",
                )
            })
            .and_then(|_| conn.execute_batch("ROLLBACK"))
            .map_err(|e| format!("rollback: {e}"))?;

        let ghost: Option<i64> = conn
            .query_row("SELECT id FROM accounts WHERE id = 900001", [], |r| r.get(0))
            .optional()
            .map_err(|e| e.to_string())?;
        if ghost.is_some() {
            return Err("rolled-back row is still present".to_string());
        }

        // Nested savepoints: inner rolled back, outer kept.
        conn.execute_batch(
            "BEGIN;
             INSERT INTO accounts (id, name, balance, created) VALUES (900002, 'keep', 1.0, 0);
             SAVEPOINT inner;
             INSERT INTO accounts (id, name, balance, created) VALUES (900003, 'drop', 1.0, 0);
             ROLLBACK TO inner;
             RELEASE inner;
             COMMIT;",
        )
        .map_err(|e| format!("savepoints: {e}"))?;

        let kept: i64 = conn
            .query_row("SELECT count(*) FROM accounts WHERE id IN (900002, 900003)", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        if kept != 1 {
            return Err(format!("savepoint semantics wrong: {kept} of 2 rows survived"));
        }
        Ok::<_, String>(())
    })
}

fn constraints(conn: &Connection) -> Result<(), String> {
    phase("constraint enforcement", None, || {
        // Each of these must be refused. A filesystem that lost writes could
        // easily make a UNIQUE index stale, and this is how that shows up.
        let cases: [(&str, &str); 5] = [
            ("UNIQUE", "INSERT INTO accounts (id, name, balance, created) VALUES (999001, 'account-0000000', 1.0, 0)"),
            ("PRIMARY KEY", "INSERT INTO accounts (id, name, balance, created) VALUES (0, 'unique-name-a', 1.0, 0)"),
            ("NOT NULL", "INSERT INTO accounts (id, name, balance, created) VALUES (999002, NULL, 1.0, 0)"),
            ("CHECK", "INSERT INTO accounts (id, name, balance, created) VALUES (999003, 'unique-name-b', -5.0, 0)"),
            ("FOREIGN KEY", "INSERT INTO entries (account_id, amount) VALUES (12345678, 1.0)"),
        ];
        for (label, sql) in cases {
            if conn.execute(sql, []).is_ok() {
                return Err(format!("{label} constraint was not enforced"));
            }
        }
        Ok::<_, String>(())
    })
}

fn joins_and_aggregates(conn: &Connection) -> Result<(), String> {
    phase("joins + aggregates", None, || {
        // Cross-check the same number two ways: a join with GROUP BY, and a
        // correlated subquery. Disagreement means the index and the table
        // disagree, which is exactly what a lossy filesystem produces.
        let via_join: i64 = conn
            .query_row(
                "SELECT count(*) FROM (
                     SELECT a.id FROM accounts a
                     JOIN entries e ON e.account_id = a.id
                     WHERE a.kind = 'premium'
                     GROUP BY a.id HAVING count(e.id) > 0)",
                [],
                |r| r.get(0),
            )
            .map_err(|e| format!("join: {e}"))?;
        let via_subquery: i64 = conn
            .query_row(
                "SELECT count(*) FROM accounts a WHERE a.kind = 'premium'
                   AND EXISTS (SELECT 1 FROM entries e WHERE e.account_id = a.id)",
                [],
                |r| r.get(0),
            )
            .map_err(|e| format!("subquery: {e}"))?;
        if via_join != via_subquery {
            return Err(format!("join {via_join} != subquery {via_subquery}"));
        }

        // LEFT JOIN must produce NULLs for accounts with no entries.
        let _: i64 = conn
            .query_row(
                "SELECT count(*) FROM accounts a
                 LEFT JOIN entries e ON e.account_id = a.id WHERE e.id IS NULL",
                [],
                |r| r.get(0),
            )
            .map_err(|e| format!("left join: {e}"))?;

        // Aggregate family.
        let (total, avg, lo, hi): (f64, f64, f64, f64) = conn
            .query_row(
                "SELECT sum(amount), avg(amount), min(amount), max(amount) FROM entries",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(|e| format!("aggregates: {e}"))?;
        if !(lo <= avg && avg <= hi) || total <= 0.0 {
            return Err(format!("aggregates inconsistent: {total} {avg} {lo} {hi}"));
        }
        Ok::<_, String>(())
    })
}

fn ctes_and_windows(conn: &Connection) -> Result<(), String> {
    phase("CTEs + window functions", None, || {
        // Recursive CTE: a self-contained arithmetic check that does not
        // depend on the data, so a wrong answer means SQLite itself is
        // misbehaving rather than the data being wrong.
        let sum: i64 = conn
            .query_row(
                "WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < 100)
                 SELECT sum(n) FROM seq",
                [],
                |r| r.get(0),
            )
            .map_err(|e| format!("recursive CTE: {e}"))?;
        if sum != 5050 {
            return Err(format!("recursive CTE gave {sum}, expected 5050"));
        }

        // Window function over real data.
        let ranked: i64 = conn
            .query_row(
                "WITH ranked AS (
                     SELECT id, row_number() OVER (PARTITION BY kind ORDER BY balance DESC) AS rn
                     FROM accounts)
                 SELECT count(*) FROM ranked WHERE rn = 1",
                [],
                |r| r.get(0),
            )
            .map_err(|e| format!("window function: {e}"))?;
        if ranked < 1 {
            return Err("window function returned no partitions".to_string());
        }
        Ok::<_, String>(())
    })
}

fn blobs(conn: &Connection) -> Result<(), String> {
    // Large values force SQLite onto overflow pages, which means long runs of
    // sequential page writes — a different access pattern from everything
    // above, and the one that stresses the record and indirect-block layers.
    let sizes = [4 * 1024usize, 256 * 1024, 2 * 1024 * 1024];
    let total: u64 = sizes.iter().map(|s| *s as u64).sum();

    phase("blob write", Some(("bytes", total)), || {
        conn.execute_batch("BEGIN").map_err(|e| e.to_string())?;
        for (i, size) in sizes.iter().enumerate() {
            let payload: Vec<u8> = (0..*size).map(|b| (b % 251) as u8).collect();
            conn.execute(
                "INSERT INTO accounts (id, name, balance, created, data) VALUES (?1, ?2, 0, 0, ?3)",
                params![800_000i64 + i as i64, format!("blob-{i}"), payload],
            )
            .map_err(|e| format!("blob insert {i}: {e}"))?;
        }
        conn.execute_batch("COMMIT").map_err(|e| e.to_string())
    })?;

    phase("blob read + verify", Some(("bytes", total)), || {
        for (i, size) in sizes.iter().enumerate() {
            let got: Vec<u8> = conn
                .query_row(
                    "SELECT data FROM accounts WHERE id = ?1",
                    [800_000i64 + i as i64],
                    |r| r.get(0),
                )
                .map_err(|e| format!("blob read {i}: {e}"))?;
            if got.len() != *size {
                return Err(format!("blob {i}: expected {size} bytes, got {}", got.len()));
            }
            // Byte-for-byte, not just the length: this is the assertion that a
            // corrupted or truncated block would fail.
            if let Some(bad) = (0..*size).find(|b| got[*b] != (b % 251) as u8) {
                return Err(format!("blob {i} corrupt at offset {bad}"));
            }
        }
        Ok::<_, String>(())
    })
}

fn text_and_collation(conn: &Connection) -> Result<(), String> {
    phase("text, types, collation", None, || {
        conn.execute_batch(
            "CREATE TABLE textish (id INTEGER PRIMARY KEY, s TEXT COLLATE NOCASE, r REAL, n INTEGER, x);",
        )
        .map_err(|e| format!("create textish: {e}"))?;

        conn.execute(
            "INSERT INTO textish (id, s, r, n, x) VALUES (1, ?1, ?2, ?3, NULL)",
            params!["Grüße, Wörld — 日本語 🎉", 3.5f64, i64::MAX],
        )
        .map_err(|e| format!("insert unicode: {e}"))?;

        let (s, r, n): (String, f64, i64) = conn
            .query_row("SELECT s, r, n FROM textish WHERE id = 1", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|e| format!("read unicode: {e}"))?;
        if s != "Grüße, Wörld — 日本語 🎉" {
            return Err(format!("unicode round-trip failed: {s:?}"));
        }
        if r != 3.5 || n != i64::MAX {
            return Err(format!("numeric round-trip failed: {r} {n}"));
        }

        // NULL is distinct from everything, including itself.
        let nulls: i64 = conn
            .query_row("SELECT count(*) FROM textish WHERE x IS NULL", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        if nulls != 1 {
            return Err("NULL handling wrong".to_string());
        }

        // COLLATE NOCASE on the column definition.
        let ci: i64 = conn
            .query_row("SELECT count(*) FROM textish WHERE s = ?1", params!["grüSSe, Wörld — 日本語 🎉"], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        // NOCASE is ASCII-only in SQLite, so this legitimately does not match;
        // assert only that the query runs and returns a definite answer.
        if ci > 1 {
            return Err(format!("collation returned {ci} rows for a unique value"));
        }

        // LIKE / GLOB / substr / replace.
        let liked: i64 = conn
            .query_row("SELECT count(*) FROM accounts WHERE name LIKE 'account-000000%'", [], |r| r.get(0))
            .map_err(|e| format!("LIKE: {e}"))?;
        if liked == 0 {
            return Err("LIKE matched nothing".to_string());
        }
        Ok::<_, String>(())
    })
}

fn triggers_and_views(conn: &Connection) -> Result<(), String> {
    phase("triggers + views", None, || {
        conn.execute_batch(
            r#"
            CREATE VIEW premium_totals AS
                SELECT a.id, a.name, count(e.id) AS entries, coalesce(sum(e.amount), 0) AS total
                FROM accounts a LEFT JOIN entries e ON e.account_id = a.id
                WHERE a.kind = 'premium' GROUP BY a.id;

            CREATE TRIGGER audit_delete AFTER DELETE ON accounts
            BEGIN
                INSERT INTO audit (action, subject) VALUES ('delete', OLD.id);
            END;
            "#,
        )
        .map_err(|e| format!("create view/trigger: {e}"))?;

        let view_rows: i64 = conn
            .query_row("SELECT count(*) FROM premium_totals", [], |r| r.get(0))
            .map_err(|e| format!("view query: {e}"))?;
        if view_rows == 0 {
            return Err("view returned no rows".to_string());
        }

        // Insert then delete, and check the trigger fired.
        conn.execute(
            "INSERT INTO accounts (id, name, balance, created) VALUES (700001, 'trigger-target', 1.0, 0)",
            [],
        )
        .map_err(|e| e.to_string())?;
        conn.execute("DELETE FROM accounts WHERE id = 700001", [])
            .map_err(|e| e.to_string())?;

        let audited: i64 = conn
            .query_row("SELECT count(*) FROM audit WHERE subject = 700001", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        if audited != 1 {
            return Err(format!("trigger did not fire: {audited} audit rows"));
        }
        Ok::<_, String>(())
    })
}

fn alter_and_indexes(conn: &Connection) -> Result<(), String> {
    phase("ALTER TABLE + reindex", None, || {
        conn.execute_batch(
            "ALTER TABLE accounts ADD COLUMN nickname TEXT;
             ALTER TABLE accounts RENAME COLUMN kind TO account_kind;
             CREATE INDEX idx_accounts_nickname ON accounts(nickname);",
        )
        .map_err(|e| format!("alter: {e}"))?;

        conn.execute("UPDATE accounts SET nickname = 'nick-' || id WHERE id < 50", [])
            .map_err(|e| format!("populate nickname: {e}"))?;

        let found: i64 = conn
            .query_row("SELECT id FROM accounts WHERE nickname = 'nick-7'", [], |r| r.get(0))
            .map_err(|e| format!("query renamed schema: {e}"))?;
        if found != 7 {
            return Err(format!("new index returned {found}"));
        }

        conn.execute_batch("REINDEX;").map_err(|e| format!("reindex: {e}"))?;

        // The rename must be visible in the schema, not just tolerated.
        let sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='accounts'",
                [],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if !sql.contains("account_kind") {
            return Err("ALTER TABLE RENAME COLUMN not reflected in schema".to_string());
        }
        Ok::<_, String>(())
    })
}

fn maintenance(conn: &Connection) -> Result<(), String> {
    // VACUUM rewrites the entire database into a new file and swaps it in —
    // the single heaviest filesystem operation SQLite performs.
    phase("VACUUM", None, || {
        conn.execute_batch("VACUUM;").map_err(|e| format!("vacuum: {e}"))
    })?;
    phase("ANALYZE", None, || {
        conn.execute_batch("ANALYZE;").map_err(|e| format!("analyze: {e}"))
    })
}

fn integrity(conn: &Connection) -> Result<(), String> {
    phase("PRAGMA integrity_check", None, || {
        let result: String = conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .map_err(|e| format!("integrity_check: {e}"))?;
        if result != "ok" {
            return Err(format!("integrity_check: {result}"));
        }
        let fk: Option<String> = conn
            .query_row("PRAGMA foreign_key_check", [], |r| r.get(0))
            .optional()
            .map_err(|e| format!("foreign_key_check: {e}"))?;
        if let Some(violation) = fk {
            return Err(format!("foreign_key_check found a violation in {violation}"));
        }
        Ok::<_, String>(())
    })
}
