package db

import (
    "database/sql"
    "fmt"
    "strings"
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
        // Other indexes for requests

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
    // Create unique indexes with automatic deduplication if needed
    if err := createUniqueIndexWithDedupe(db, `CREATE UNIQUE INDEX IF NOT EXISTS uq_request_raw ON request_events(raw_line);`, "request_events"); err != nil {
        return err
    }
    if err := createUniqueIndexWithDedupe(db, `CREATE UNIQUE INDEX IF NOT EXISTS uq_error_raw ON error_events(raw_line);`, "error_events"); err != nil {
        return err
    }
    return nil
}

func createUniqueIndexWithDedupe(db *sql.DB, createStmt, table string) error {
    if _, err := db.Exec(createStmt); err != nil {
        e := strings.ToLower(err.Error())
        if strings.Contains(e, "unique") {
            var del string
            switch table {
            case "request_events":
                del = `DELETE FROM request_events WHERE id NOT IN (SELECT MIN(id) FROM request_events GROUP BY raw_line)`
            case "error_events":
                del = `DELETE FROM error_events WHERE id NOT IN (SELECT MIN(id) FROM error_events GROUP BY raw_line)`
            default:
                return err
            }
            if _, derr := db.Exec(del); derr != nil {
                return fmt.Errorf("dedupe %s: %w", table, derr)
            }
            if _, err2 := db.Exec(createStmt); err2 != nil {
                return fmt.Errorf("create unique index on %s after dedupe: %w", table, err2)
            }
            return nil
        }
        return err
    }
    return nil
}
