# Deployment & Operations

## Build
Use Makefile targets:
- `make build` (all binaries to ./bin)
- `make build-server`, `make build-importer` (selective)

## Install Targets
- `make install` (PREFIX=/usr/local default) copies binaries & UI assets.
- `make systemd-install` installs unit files & env examples.
- `make systemd-config` writes drop-in overrides (for edits without touching unit).
- `make systemd-enable` enables & starts services.
- `make nginx-install` installs reverse proxy config for TLS/hostname routing.

## Runtime Invocation Examples
Importer (periodic or timer):
```
./bin/logtool-importer --db /var/lib/logtool/monitor.db \
  --access /var/log/nginx/access.log --format nginx --ip-policy mask
```
Server (with GitHub OAuth):
```
export GITHUB_CLIENT_ID=your_client_id
export GITHUB_CLIENT_SECRET=your_client_secret
export GITHUB_CALLBACK_URL=https://your-domain.com/auth/github/callback
export LOGTOOL_SESSION_SECRET=$(openssl rand -base64 32)
export LOGTOOL_SECURE_COOKIES=true

./bin/logtool-server --db /var/lib/logtool/monitor.db \
  --static /usr/local/share/logtool/web --addr :8080
```

Server (with Bearer token for API-only):
```
./bin/logtool-server --db /var/lib/logtool/monitor.db \
  --static /usr/local/share/logtool/web --addr :8080 \
  --auth-token your_secret_token
```

## Environment Variables

### Server
**GitHub OAuth (recommended for interactive login):**
- `GITHUB_CLIENT_ID` - GitHub OAuth app client ID
- `GITHUB_CLIENT_SECRET` - GitHub OAuth app client secret
- `GITHUB_CALLBACK_URL` - OAuth callback URL (e.g., `https://domain.com/auth/github/callback`)
- `LOGTOOL_SESSION_SECRET` - Random secret for signing session cookies (base64 encoded)
- `LOGTOOL_SESSION_TTL` - Session duration (default: `12h`)
- `LOGTOOL_SECURE_COOKIES` - Set to `true` for HTTPS deployments

**API Authentication:**
- `LOGTOOL_TOKEN` or `LOGTOOL_TOKENS` - Bearer token(s) for API clients
- `LOGTOOL_USER`, `LOGTOOL_PASS` - Basic auth credentials

**General:**
- `LOGTOOL_DB` - Database path
- `LOGTOOL_STATIC` - Static UI directory path

### Importer
- `LOGTOOL_DB`, `LOGTOOL_ACCESS`, `LOGTOOL_ERROR`, `LOGTOOL_FORMAT`
- `IP_SALT` - Salt for hash IP policy

## Scheduling Importer
Recommended: systemd timer or cron running importer every minute or 5 minutes; importer performs incremental tail and exits quickly.

## Log Rotation
Ensure rotation retains inode differences (standard logrotate). Importer detects truncation/rotation and restarts from beginning of new file while dedupe prevents duplicates.

## Database Location
Prefer dedicated directory with backups (e.g., nightly copy). WAL mode creates `-wal` and `-shm` sidecar files—include them for hot backup consistency or checkpoint then copy main file.

## Backfill Procedure
1. Stop periodic importer temporarily.
2. Run `logtool-importer --access 'access.log*' --format nginx --backfill` (if such flag added; currently use dedicated backfill CLI integration if present) or use a custom tool invoking ImportAccessFiles.
3. Resume periodic importer.

## Monitoring
- /health endpoint for liveness.
- /api/debug/dbinfo to verify ingestion span & import_state.
- External metrics can be derived by querying summary/time series endpoints.

## Scaling Considerations
- SQLite should handle moderate personal traffic volumes; if DB size or write contention grows, splitting importer invocations or migrating to a server RDBMS would need substantive refactor.
- UI static files served directly; for high volume deploy behind nginx with caching and gzip.

## Upgrades & Migrations
Startup handles additive column migrations and dedupe of unique indexes. For destructive/complex migrations, manual SQL scripts would be required (none currently implemented).

## Backup & Restore
Cold backup: stop importer & server, copy DB file(s).
Hot backup: `sqlite3 monitor.db ".backup backup.db"` (ensure sqlite3 installed). Include verifying `.schema` after restore.

## Security Deployment Notes

### HTTPS/TLS Setup (Required for GitHub OAuth)
1. **Terminate TLS at nginx** using the provided config (`deploy/nginx/logtool.conf`)
2. **Enable secure cookies** by setting `LOGTOOL_SECURE_COOKIES=true`
3. **Configure GitHub OAuth callback** to use HTTPS URL
4. **Set HSTS header** in nginx for additional security

Example nginx configuration snippet:
```nginx
server {
  listen 443 ssl http2;
  server_name your-domain.com;
  
  ssl_certificate /path/to/fullchain.pem;
  ssl_certificate_key /path/to/privkey.pem;
  
  add_header Strict-Transport-Security "max-age=31536000" always;
  
  location /monitor/ {
    proxy_pass http://127.0.0.1:8080/;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

### GitHub OAuth App Configuration
1. Go to https://github.com/settings/developers
2. Create new OAuth App with:
   - Homepage URL: `https://your-domain.com`
   - Callback URL: `https://your-domain.com/auth/github/callback` (adjust for proxy path)
3. Copy Client ID and generate Client Secret
4. Configure in `/etc/logtool/server.env` (see `deploy/systemd/server.env.example`)

### Additional Security
- Restrict file permissions on SQLite DB and config files
- Limit firewall to expose only nginx (port 443), not backend server directly
- Periodically rotate bearer tokens and session secrets (requires restart)
- Keep dependencies updated with `go get -u && go mod tidy`

