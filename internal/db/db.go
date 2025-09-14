package db

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

// Open opens (and creates if missing) the SQLite database and applies migrations.
func Open(path string) (*sql.DB, error) {
    // Use DSN params for better durability and concurrency.
    dsn := fmt.Sprintf("file:%s?_foreign_keys=on&_busy_timeout=5000", path)
    sqldb, err := sql.Open("sqlite3", dsn)
    if err != nil {
        return nil, err
    }
    if _, err := sqldb.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;`); err != nil {
        _ = sqldb.Close()
        return nil, err
    }
    if err := migrate(sqldb); err != nil {
        _ = sqldb.Close()
        return nil, err
    }
    return sqldb, nil
}

func migrate(db *sql.DB) error {
    stmts := []string{
        // Requests (access log)
        `CREATE TABLE IF NOT EXISTS request_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_unix INTEGER NOT NULL,
            ts TEXT NOT NULL,
            remote_addr TEXT,
            xff TEXT,
            method TEXT,
            path TEXT,
            protocol TEXT,
            status INTEGER,
            bytes_sent INTEGER,
            referer TEXT,
            user_agent TEXT,
            raw_line TEXT
        );`,
        `CREATE INDEX IF NOT EXISTS idx_request_ts ON request_events(ts_unix);`,
        `CREATE INDEX IF NOT EXISTS idx_request_status ON request_events(status);`,
        `CREATE INDEX IF NOT EXISTS idx_request_path ON request_events(path);`,

        // Errors (error log)
        `CREATE TABLE IF NOT EXISTS error_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_unix INTEGER NOT NULL,
            ts TEXT NOT NULL,
            level TEXT,
            pid INTEGER,
            tid INTEGER,
            message TEXT,
            raw_line TEXT
        );`,
        `CREATE INDEX IF NOT EXISTS idx_error_ts ON error_events(ts_unix);`,
        `CREATE INDEX IF NOT EXISTS idx_error_level ON error_events(level);`,

        // Import state per-log (active file only for now)
        `CREATE TABLE IF NOT EXISTS import_state (
            log_name TEXT PRIMARY KEY,
            inode INTEGER,
            position INTEGER,
            last_mtime INTEGER,
            last_size INTEGER,
            updated_at INTEGER NOT NULL
        );`,
    }
    for _, s := range stmts {
        if _, err := db.Exec(s); err != nil {
            return err
        }
    }
    return nil
}

