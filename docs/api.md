# HTTP API

Base path examples assume server binary launched with `--db monitor.db --static ./web/dist --addr :8080` and reachable at `http://localhost:8080`.

Authentication (if configured) may require:
- Basic: `Authorization: Basic base64(user:pass)`
- Bearer: `Authorization: Bearer <token>` (token string provided in config)
- Session cookie: Form POST to /login obtains signed cookie, then subsequent browser requests authenticated.

All responses are JSON (Content-Type: application/json) except /login (HTML) and /health (plain text).

## Common Query Parameters
- Time range: `from`, `to` (unix seconds or RFC3339) OR `dur` (duration shorthand like `5m`, `2h`, `1d`). If `dur` provided and `to` omitted, `to=now`.
- Host filter: `host=` (value 'Unknown' matches NULL/empty host rows).
- Bucket selection (time series): `bucket=minute|hour|day` (default hour); `tz=+HH:MM` offset for bucketing alignment.
- Limits: `limit` (varies per endpoint) clamped to safe ranges.

## Endpoints
### GET /health
Liveness probe. Returns 200 + body `ok`.

### GET /api/summary
Returns aggregate counts over range.
```
{
  "from": 1696876800,
  "to": 1697481600,
  "requests": 12345,
  "unique_remote": 456,
  "errors": 12,
  "last_request": "2025-10-11T14:05:03Z"
}
```

### GET /api/hosts
Returns distinct hosts (NULL/empty -> "Unknown") ordered lexicographically.
```
["Unknown","example.com","api.example.com"]
```

### GET /api/timeseries/requests
Time buckets of request counts.
```
[{"t":"2025-10-11T10:00:00Z","count":120}, ...]
```
Parameters: bucket, tz, (range params), host.

### GET /api/timeseries/errors
Analogous for error_events (no host filter currently applied to errors table).

### GET /api/top/paths
Top request paths.
```
[{"path":"/","count":500}, ...]
```
Query: limit (1-100), host, range.

### GET /api/top/referrers
Top referrers. Query: `include_empty=true` optionally includes empty referrer as empty string.
```
[{"referrer":"https://example.com","count":42}]
```

### GET /api/top/ua
Top raw User-Agent strings. Query: `include_empty=true` to include empties.
```
[{"ua":"Mozilla/5.0 ...","count":300}]
```

### GET /api/top/ua_families
UA grouped into coarse families (Chrome, Firefox, Bot, curl, etc.) with heuristic classifier.
```
[{"family":"Chrome","count":250}, ...]
```

### GET /api/top/hosts
Top hosts by request count (grouping NULL/empty into "Unknown").
```
[{"host":"example.com","count":900}]
```

### GET /api/status
Distribution by HTTP status code.
```
[{"status":200,"count":10000},{"status":404,"count":32}]
```

### GET /api/requests
Paginated raw request rows (newest first).
Query params:
- limit (1-1000, default 100)
- offset (pagination)
- method, status=NNN filter
- path_like (SQL LIKE pattern, e.g. `/api/%`)
- include_unparsed=true to include rows lacking parsed method/path
- (range params, host)
Response rows:
```
{
  "ts": "2025-10-11T14:03:00Z",
  "remote": "203.0.113.0",
  "xff": "198.51.100.0, 203.0.113.0",
  "method": "GET",
  "path": "/",
  "proto": "HTTP/1.1",
  "status": 200,
  "bytes": 5123,
  "referer": "https://example.com",
  "ua": "Mozilla/5.0 ..."
}
```
Absent optional fields omitted or empty string as defined by query SELECT COALESCE logic.

### GET /api/errors
Error event rows (newest first). Query params: limit, offset, level, (range params). Response rows include ts, level, pid, tid, message.

### GET /api/debug/dbinfo
Diagnostics for database content and import state.
Example:
```
{
  "db_path": "/abs/path/monitor.db",
  "requests": {"total":12000,"parsed":11800,"unparsed":200,"min_unix":...,"max_unix":...,"min_iso":"...","max_iso":"..."},
  "errors": {"total":42,...},
  "import_state": [{"log_name":"access","inode":123,"position":45678,...}]
}
```
Useful to confirm ingestion progress and time spans.

## Error Handling
- 400 Bad Request: validation / parsing error (invalid durations, etc.). Body contains error string.
- 401 Unauthorized: when auth required and missing/invalid.
- 405 Method Not Allowed: improper method (e.g., POST to a GET endpoint).

## CORS
If server configured with CORS enabled, responses include permissive headers allowing cross-site GET usage.

## Pagination Strategy
Simple limit/offset. For large datasets, a future improvement could return a next cursor (ts_unix,id) to avoid deep offset scans.

