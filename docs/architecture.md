# Architecture

## Overview
Logtool ingests web server (nginx or Caddy) access/error logs into a local SQLite database and exposes an HTTP JSON API plus a static dashboard UI. It is intentionally self‑contained: a single SQLite file, no external services, and minimal dependencies.

```
   +------------------+          +------------------+        +-------------------+
   |  Access/Error    |  tail    |  Importer CLI    |  SQL   |   SQLite (WAL)    |
   |  Logs (nginx/    +--------->+  (incremental)   +------->+  request/error    |
   |  caddy)          |          |                  |        |  tables + state   |
   +------------------+          +------------------+        +-------------------+
                                                             ^            |
                                                             |            | queries
                                                             |            v
                                                     +---------------------------+
                                                     |  HTTP Server (webapi)     |
                                                     |  JSON API + static UI     |
                                                     +-------------+-------------+
                                                                   |
                                                                   v
                                                          Browser / API Clients
```

### Binaries
- cmd/importer: Incrementally ingests logs using inode+offset tracking.
- cmd/server: Serves JSON endpoints, does aggregations/time series, GitHub OAuth/Bearer/Basic auth, static file serving.
- cmd/parsecheck (utility): Assists with regex / parsing validation.

### Core Packages
- internal/db: Connection setup, migrations, schema evolution helpers (column add, dedupe unique indexes).
- internal/importer: Parsing, IP privacy normalization, incremental & backfill ingestion.
- internal/webapi: HTTP routing, auth (GitHub OAuth, Bearer, Basic), session cookies, query parsing, aggregations, classification helpers.
- internal/util: Hashing for IP policies (SHA256 + salt) (see Hasher interface expectation in importer).

## Data Flow
1. Importer opens DB (same schema) and calls ImportAccess / ImportError for each log file (active / rotated or backfill files).
2. Each new line is parsed; structured fields inserted with INSERT OR IGNORE (dedupe on raw_line unique index).
3. For unparsed lines a fallback timestamp and raw_line are stored; method/path remain NULL to allow filtering.
4. Server endpoints query with time bounds (from/to or duration) and build aggregations (COUNT, GROUP BY, bucketing with integer division).
5. UI polls summary + time series + top lists and composes dashboard.

## Concurrency & Durability
- SQLite in WAL mode (PRAGMA journal_mode=WAL) enables concurrent readers while importer writes.
- Busy timeout (5s) reduces transient lock errors.
- Migrations are idempotent; column additions (e.g., host) happen at startup for both importer/server.

## Virtual Host Awareness
Host header captured (if available) and indexed (idx_request_host) enabling multi‑tenant filtering via `?host=` queries.

## Time Handling
All timestamps stored twice: ts_unix (INTEGER seconds, UTC) and ts (ISO8601 RFC3339 string). Bucketing offsets support client timezone shift by applying an additive offset before division, then subtracting after.

## Extensibility Considerations
- Additional log formats: implement parse<Format>Access / Error and extend AccessFormat enum + dispatcher.
- Additional aggregations: mirror existing handlers (see handleTopPaths, handleStatus) with new SELECT/GROUP BY.
- Alternative storage: abstract db layer (currently tightly bound to SQLite SQL strings).

