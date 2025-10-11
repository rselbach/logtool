# Importer

## Goals
- Parse and ingest access & error logs incrementally (tailing) with rotation resilience.
- Support multiple formats (nginx combined + XFF + host; Caddy JSON access lines and plaintext errors).
- Enforce IP privacy via configurable policy.
- Ensure idempotency and deduplicate repeated lines.
- Allow historical backfill from plain or .gz files without disturbing incremental state.

## Entry Points
- `ImportAccess(db, logName, path, format, policy, hasher)`
- `ImportError(db, logName, path, format)`
- `ImportAccessFiles(db, files, format, policy, hasher)` (backfill)
- `ImportErrorFiles(db, files, format)` (backfill)

## Incremental State Tracking
State persisted per logical log name in `import_state` capturing inode, byte position, last_mtime, last_size, updated_at.
Algorithm (withIncrementalRead):
1. Stat file to get inode/size/mtime.
2. Fetch previous state: if inode matches and previous position <= current size, seek to that position; else (rotation/truncation) start at 0.
3. Stream new lines until EOF, tracking current byte offset.
4. After processing, upsert state with new position (even if zero, rotation case).

## Rotation Handling
If inode differs from stored inode or previous position > current size (truncate), importer treats it as new file and begins from start; previous file lines already deduped via unique raw_line index.

## Access Log Parsing
### nginx Format
Regex: `^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\"]*?)\s+(\S+)"\s+(\d{3})\s+(\d+|-)\s+"([^"]*)"\s+"([^"]*)"\s+"([^"]*)"(?:\s+"([^"]*)")?$`
Captures: remote_addr, time, method, path, protocol, status, bytes, referer, user_agent, xff, host(optional).
Time layout: `02/Jan/2006:15:04:05 -0700`.

### Caddy Format
Structured JSON payload tab‑delimited within unified log lines. Split on first 5 tab columns, parse timestamp, ensure logger contains `http.log.access`, then unmarshal JSON segment for request fields.

Unparsed lines (regex miss or malformed JSON) fall back to timestamp heuristics and insert minimal row (raw_line only).

## Error Log Parsing
### nginx
Regex: `^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[([a-z]+)\] (\d+)#(\d+): (.*)$`
Time layout: `2006/01/02 15:04:05`.

### Caddy
Tab‑delimited; parse timestamp, level, logger, message remainder (concatenate extra columns). If message empty, store stripped ANSI full line.

## IP Privacy Policies
Enum IPPolicy: store, mask, hash, drop.
Behavior:
- store: retain canonical text form.
- mask: IPv4 zero last octet; IPv6 zero lower 8 bytes (keep /64). Unrecognized tokens dropped.
- hash: SHA256 (via provided Hasher) of exact string, prefixed `h:`; preserves ability to count unique IPs without reversal.
- drop: replace with empty string (NULL stored for remote_addr, but XFF list entries become empty segments removed on normalization).

X-Forwarded-For normalization splits on commas, applies normalization per element, rejoins with ", ".

## Deduplication & Idempotency
All inserts use `INSERT OR IGNORE` relying on unique index on raw_line. Re‑reading previously imported content (e.g., due to rotation race) results in zero RowsAffected.

## Backfill
Backfill helpers expand globs, open files (gzip supported by suffix), and bulk insert inside a single transaction for performance. They intentionally do NOT update `import_state` (avoid interfering with live tail offsets). Order of files is deterministic (sorted by path) for reproducibility.

## Fallback Timestamp Logic
If parsing fails, heuristics attempt to extract recognizable timestamp fragments (regex bracket/time patterns) else use current UTC. Ensures chronological ordering approximates original line arrival.

## Error Handling Strategy
Parsing errors do not abort ingestion (line-level tolerance). Only IO, DB, or statement prepare errors bubble up aborting the import.

## Extending Formats
To add a new format:
1. Add new AccessFormat constant + ParseAccessFormat switch.
2. Implement parse<Format>Access / parse<Format>Error returning (record,bool).
3. Extend dispatchers parseAccessLine / parseErrorLine.
4. Provide fallback time extraction if needed.

