# Deployment & Operations

## Build
Use Makefile targets:
- `make build` (all binaries to ./bin)
- `make build-server`, `make build-importer`, `make build-pwhash` (selective)

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
Server:
```
./bin/logtool-server --db /var/lib/logtool/monitor.db \
  --static /usr/local/share/logtool/web --addr :8080 \
  --basic-user admin --basic-pass '...'
```
Password hash generation:
```
./bin/logtool-pwhash
```

## Environment Variables (typical)
- LOGTOOL_DB, LOGTOOL_ACCESS, LOGTOOL_ERROR, LOGTOOL_FORMAT
- IP_SALT (salt for hash policy) passed to hasher

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
- Terminate TLS at nginx (nginx-install target). Ensure proper HSTS and secure cookie flags if served over HTTPS (could patch code to add Secure attribute).
- Limit firewall to expose only server port or proxy.

