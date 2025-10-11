# Database

## Engine & Pragmas
SQLite is used with:
- WAL mode for concurrent reads during writes.
- `_foreign_keys=on` DSN param plus explicit `PRAGMA foreign_keys=ON` (future‑proof; no current FKs).
- `_busy_timeout=5000` to tolerate writer contention.
- `synchronous=NORMAL` tradeoff (durable enough for append‑only ingestion with acceptable speed).

## Schema Summary
Tables:
- request_events
- error_events
- import_state

### request_events
```
id INTEGER PRIMARY KEY AUTOINCREMENT
ts_unix INTEGER NOT NULL        -- seconds since epoch (UTC)
ts TEXT NOT NULL                -- RFC3339 UTC ISO string
remote_addr TEXT NULL          -- normalized per IP policy
xff TEXT NULL                  -- normalized X-Forwarded-For (comma list)
method TEXT NULL
path TEXT NULL
protocol TEXT NULL
status INTEGER NULL
bytes_sent INTEGER NULL
referer TEXT NULL
user_agent TEXT NULL
host TEXT NULL                 -- added via migration helper
raw_line TEXT                  -- original log line (used for dedupe)
```
Indexes:
- idx_request_ts (ts_unix)
- idx_request_status (status)
- idx_request_path (path)
- idx_request_ua (user_agent)
- idx_request_host (host)
- uq_request_raw UNIQUE(raw_line) (deduplication)

### error_events
```
id INTEGER PRIMARY KEY AUTOINCREMENT
ts_unix INTEGER NOT NULL
ts TEXT NOT NULL
level TEXT NULL
pid INTEGER NULL
tid INTEGER NULL
message TEXT NULL
raw_line TEXT
```
Indexes:
- idx_error_ts (ts_unix)
- idx_error_level (level)
- uq_error_raw UNIQUE(raw_line)

### import_state
Tracks incremental tail positions per logical log name (e.g., "access", "error").
```
log_name TEXT PRIMARY KEY
inode INTEGER
position INTEGER
last_mtime INTEGER
last_size INTEGER
updated_at INTEGER NOT NULL
```

## Migrations
At Open():
1. Core CREATE TABLE/INDEX statements executed idempotently.
2. `addColumnIfNotExists` checks PRAGMA table_info for missing columns (currently adds host).
3. `createUniqueIndexWithDedupe` attempts to CREATE UNIQUE; on failure (duplicate rows) executes a delete keeping MIN(id) per raw_line then retries.

## Deduplication Strategy
Duplicates (e.g. importer restart before state persisted) prevented by unique index on raw_line. Insert statements use `INSERT OR IGNORE` so collisions become no‑ops.

## Host Column Migration
Older DBs lacking `host` column are upgraded transparently; subsequent queries and index rely on it.

## Null vs Empty Semantics
Unparsed lines: method/path/protocol remain NULL; UI/API often filters them out unless `include_unparsed=true` (requests endpoint). Distinct host lists treat NULL/empty as 'Unknown'.

## Query Patterns
- Time range filtering always anchors on `ts_unix BETWEEN ? AND ?` with additional AND predicates.
- Time series bucket key computed as `((ts_unix + tzOff)/bucket)*bucket` enabling timezone shifting without converting all rows.
- Top lists use GROUP BY + ORDER BY count DESC with LIMIT parameter clamped to safe bounds.

## Performance Notes
- For typical personal log volumes, indexes provide sufficient selectivity.
- Consider adding composite indexes (host+ts_unix, status+ts_unix) if range scans grow.
- Vacuum/analyze left to user operational routines if DB grows large.

## Data Retention
No automatic pruning. External tooling or future feature could DELETE old rows by ts_unix threshold.

