# Logtool

> **Disclaimer:** This project was conceived for my personal environment and may not be suitable for other deployments without thorough review and customization.

Logtool ingests web server access and error logs into a local SQLite database and exposes a dashboard and JSON API for exploring traffic trends, error rates, and top sources. The importer CLI tails nginx combined logs or Caddy JSON logs incrementally, normalizes IPs according to configurable privacy policies, and deduplicates entries using inode/offset tracking.

## Quick Start

```bash
make build
./bin/importer --path /var/log/nginx/access.log --format nginx --policy mask
./bin/server --db monitor.db --static ./web/dist
```

Visit the dashboard at `http://localhost:8080/` to select ranges (including Go duration strings like `5m`, `2h`, or `1d`), review summaries, and drill into recent requests or errors. The server supports optional basic auth, bearer tokens, or form login with HMAC-signed session cookies configured via flags or environment variables.

## Configuration Highlights

- **Importer flags:** `--path` (repeatable), `--format` (`nginx` or `caddy`), `--policy` (`store`, `mask`, `hash`, `drop`), `--backfill` duration, and `--state-db` for tracking offsets.
- **Server flags:** `--db`, `--listen`, `--tls-cert/key`, `--bearer`, `--basic-user/pass`, `--login-user`, `--login-pass-hash`, and `--session-secret`.
- **API endpoints:** `/api/summary`, `/api/timeseries/{requests,errors}`, `/api/top/{paths,referrers,ua,ua_families}`, `/api/status`, `/api/requests`, `/api/errors`, `/api/hosts`, and `/api/debug/dbinfo`.
- **Host filtering:** All API endpoints support optional `?host=` query parameter to filter by virtual host. The `/api/hosts` endpoint returns a list of distinct hosts for the selected time range. For nginx logs to capture host information, include `$http_host` in your log format (e.g., `log_format logtool '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for" "$http_host"';`). Caddy JSON logs automatically include host information.

See `make help` for additional build targets and use `go test ./...` to run the suite.
