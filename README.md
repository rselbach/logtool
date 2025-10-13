# Logtool

> **Disclaimer:** This project was conceived for my personal environment and may not be suitable for other deployments without thorough review and customization.

Logtool ingests web server access and error logs into a local SQLite database and exposes a dashboard and JSON API for exploring traffic trends, error rates, and top sources. The importer CLI tails nginx combined logs or Caddy JSON logs incrementally, normalizes IPs according to configurable privacy policies, and deduplicates entries using inode/offset tracking.

## Quick Start

```bash
make build
./bin/importer --path /var/log/nginx/access.log --format nginx --policy mask
./bin/server --db monitor.db --static ./web/dist
```

Visit the dashboard at `http://localhost:8080/` to select ranges (including Go duration strings like `5m`, `2h`, or `1d`), review summaries, and drill into recent requests or errors. The server supports GitHub OAuth for interactive login, plus optional basic auth and bearer tokens for API clients.

## Authentication

### OAuth (Interactive Login)
Choose GitHub or Apple for browser-based access:

**GitHub OAuth:**
1. Create OAuth App at https://github.com/settings/developers
2. Configure: `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_CALLBACK_URL`

**Apple OAuth:**
1. Create Services ID at https://developer.apple.com/account/resources/identifiers
2. Download .p8 key file
3. Configure: `APPLE_CLIENT_ID`, `APPLE_TEAM_ID`, `APPLE_KEY_ID`, `APPLE_PRIVATE_KEY_FILE`, `APPLE_CALLBACK_URL`

Both require session config:
```bash
LOGTOOL_SESSION_SECRET=$(openssl rand -base64 32)
LOGTOOL_SECURE_COOKIES=true  # For HTTPS
```

**Important:** OAuth login requires an email allowlist. Configure allowed emails or patterns:
```bash
# Allow specific emails
LOGTOOL_EMAIL_ALLOWLIST=alice@example.com,bob@example.com

# Allow domain patterns
LOGTOOL_EMAIL_ALLOWLIST=*@example.com,admin@*.example.com
```

Without an allowlist configured, all OAuth login attempts will be denied.

### Bearer Tokens (API Clients)
For automation and programmatic access:
```bash
LOGTOOL_TOKEN=your_secret_token
# Or multiple tokens:
LOGTOOL_TOKENS=token1,token2,token3
```

Use with: `curl -H "Authorization: Bearer your_secret_token" https://your-domain.com/api/summary`

### Basic Auth (Alternative)
```bash
LOGTOOL_USER=username
LOGTOOL_PASS=password
```

See [docs/auth_security.md](docs/auth_security.md) for detailed authentication and security information.

## Configuration Highlights

- **Importer flags:** `--path` (repeatable), `--format` (`nginx` or `caddy`), `--policy` (`store`, `mask`, `hash`, `drop`), `--backfill` duration, and `--state-db` for tracking offsets.
- **Server flags:** `--db`, `--addr`, `--static`, `--auth-user/pass`, `--auth-token`, and `--session-secret`. Most configuration done via environment variables.
- **API endpoints:** `/api/summary`, `/api/timeseries/{requests,errors}`, `/api/top/{paths,referrers,ua,ua_families}`, `/api/status`, `/api/requests`, `/api/errors`, `/api/hosts`, and `/api/debug/dbinfo`.
- **Host filtering:** All API endpoints support optional `?host=` query parameter to filter by virtual host. The `/api/hosts` endpoint returns a list of distinct hosts for the selected time range. For nginx logs to capture host information, include `$http_host` in your log format (e.g., `log_format logtool '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for" "$http_host"';`). Caddy JSON logs automatically include host information.

See `make help` for additional build targets and use `go test ./...` to run the suite.
