Logtool — Simple Site Monitoring (SQLite)

Components in this repo:
- `cmd/importer`: Go CLI that imports `nginx` `access.log` and `error.log` into a local SQLite DB.
- `internal/db`: DB open + auto-migrations.
- `internal/importer`: Incremental log readers + parsers.
- `cmd/server`: Minimal JSON web API on top of the DB (for the future dashboard).

Quick start
- Build: `go build ./cmd/importer`
- Run: `./importer -access ./access.log -error ./error.log -db ./monitor.db`

Web server
- Build: `go build ./cmd/server`
- Run: `./server -db ./monitor.db -addr :8080 -tz +00:00 -cors=true -static ./web/dist`
  - Add Basic Auth (recommended for public networks):
    - `./server -db ./monitor.db -addr :8080 -static ./web/dist -auth-user alice -auth-pass 's3cret'`
    - Or via env: `LOGTOOL_USER=alice LOGTOOL_PASS=s3cret ./server ...`
  - Or Bearer token auth (good for API access or reverse proxy headers):
    - Single token: `./server ... -auth-token 'mytoken123'`
    - Multiple tokens: `./server ... -auth-token 't1,t2,t3'`
    - From file: `./server ... -auth-token-file ./tokens.txt` (one token per line, `#` comments allowed)
    - Env vars: `LOGTOOL_TOKEN=tok`, or `LOGTOOL_TOKENS=t1,t2`
  - Or Login screen (form-based session auth):
    - Generate bcrypt hash: `go run ./cmd/pwhash -password 'your-strong-pass'` (copy `$2b$...`)
    - Start: `./server ... -login-user alice -login-hash '$2b$12$...' -session-secret 'randomBase64' -session-ttl 12h`
    - Env: `LOGTOOL_LOGIN_USER`, `LOGTOOL_LOGIN_HASH`, `LOGTOOL_SESSION_SECRET`, `LOGTOOL_SESSION_TTL`
- Endpoints (GET):
  - `/health` → `ok`
  - `/api/summary?from=...&to=...` → totals snapshot
  - `/api/timeseries/requests?from=...&to=...&bucket=hour|day|minute&tz=-04:00` → list of `{t,count}`
  - `/api/timeseries/errors?from=...&to=...&bucket=...&tz=...`
  - `/api/top/paths?from=...&to=...&limit=10`
  - `/api/top/referrers?from=...&to=...&limit=10&include_empty=false`
  - `/api/status?from=...&to=...` → per-status counts
- `/api/requests?from=...&to=...&limit=100&offset=0&method=GET&status=200&path_like=/blog%25`
  - Add `include_unparsed=true` to include rows from lines the parser couldn't fully understand (hidden by default).
  - `/api/errors?from=...&to=...&limit=100&offset=0&level=warn`

Notes
- `from`/`to` accept unix seconds or RFC3339 (`2025-09-13T00:00:00Z`). Defaults: last 7 days.
- `tz` offsets only affect bucketing boundaries (e.g., start of hour/day); responses return UTC timestamps.
 - If Basic Auth is enabled, the browser will prompt once and then reuse credentials for API calls and static files.
 - If Bearer is enabled, send `Authorization: Bearer <token>` on requests. Examples:
   - `curl -H 'Authorization: Bearer mytoken123' http://localhost:8080/api/summary`
   - With the UI behind a reverse proxy, you can inject the header using `proxy_set_header Authorization 'Bearer mytoken123';`
 - If Login is enabled, `/login` serves a minimal sign-in form and sets an HttpOnly, HMAC-signed cookie. Use a long random `-session-secret` in production.

CLI utility
- `cmd/pwhash`: prints a bcrypt hash for a given password.
  - Examples:
    - `go run ./cmd/pwhash -password 'My#Str0ng#Pass'`
    - `echo -n 'My#Str0ng#Pass' | go run ./cmd/pwhash`

Nginx alternative (proxy auth)
- You can also place the server behind Nginx and protect it with `auth_basic`. Example:

```
location /monitor/ {
    proxy_pass http://127.0.0.1:8080/;
    auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/.htpasswd; # create with: htpasswd -c /etc/nginx/.htpasswd alice
}
```

Nginx reverse proxy (full example)
- See `deploy/nginx/logtool.conf` for a complete server block with two protection options:
  - Use Logtool’s own login page (/login) and sessions; or
  - Protect via Nginx Basic Auth or inject a Bearer token for all requests.
  - Adjust `server_name`, TLS cert paths, and location prefix (`/monitor/`).

Frontend
- Static files live under `web/dist`. When you run the server with `-static ./web/dist`, visit `http://localhost:8080/` for the dashboard.
- The UI is vanilla HTML/JS/CSS and uses the JSON endpoints directly. It supports quick range presets, auto bucket sizing (minute/hour/day), and client-local timezone bucketing.
- Charts use a vendored `Chart.js` UMD build (`web/dist/vendor/chart.umd.min.js`) so no CDN is required. To update:
  - `curl -L -o web/dist/vendor/chart.umd.min.js https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js`

Systemd service
- Files in `deploy/systemd/`:
  - `logtool-server.service`: unit to run the server as a hardened systemd service.
  - `server.env.example`: sample environment file for `/etc/logtool/server.env`.
  - `logtool-importer.service`: oneshot importer runner.
  - `logtool-importer.timer`: schedules the importer every 5 minutes.
  - `importer.env.example`: sample env for `/etc/logtool/importer.env`.
- Install (as root):
  - `install -Dm644 deploy/systemd/logtool-server.service /etc/systemd/system/logtool-server.service`
  - `install -Dm644 deploy/systemd/server.env.example /etc/logtool/server.env`
  - Install binaries and UI assets:
    - `go build -o /usr/local/bin/logtool-server ./cmd/server`
    - `install -d /usr/share/logtool/web/dist && cp -r web/dist/* /usr/share/logtool/web/dist/`
  - Edit `/etc/logtool/server.env` to set auth and paths.
  - `systemctl daemon-reload`
  - `systemctl enable --now logtool-server`
- Defaults:
  - Binds on `:8080`, stores DB under `/var/lib/logtool/monitor.db`, serves static UI from `/usr/share/logtool/web/dist`.
  - Uses `DynamicUser=yes` with `StateDirectory=logtool` and hardened sandbox; only `/var/lib/logtool` is writable.
  - Override ports/paths by editing `ExecStart=` in the unit or setting corresponding env vars and replacing `ExecStart` with an environment-aware version.

Makefile helpers
- Common tasks:
  - Build: `make build` (outputs into `./bin/`)
  - Install binaries+UI: `sudo make install`
  - Install systemd units: `sudo make systemd-install && sudo make systemd-enable`
  - Install nginx sample: `sudo make nginx-install && sudo systemctl reload nginx`
- Variables you can override: `PREFIX`, `BINDIR`, `SHAREDIR`, `SYSTEMD_DIR`, `ETC_DIR`.

Systemd timer for importer (replaces cron)
- Build and install importer binary:
  - `go build -o /usr/local/bin/logtool-importer ./cmd/importer`
- Install units + env:
  - `install -Dm644 deploy/systemd/logtool-importer.service /etc/systemd/system/logtool-importer.service`
  - `install -Dm644 deploy/systemd/logtool-importer.timer /etc/systemd/system/logtool-importer.timer`
  - `install -Dm644 deploy/systemd/importer.env.example /etc/logtool/importer.env`
  - Edit `/etc/logtool/importer.env` to point to your nginx logs and desired IP policy.
- Enable and start:
  - `systemctl daemon-reload`
  - `systemctl enable --now logtool-importer.timer`
  - Check: `systemctl status logtool-importer.timer` and `journalctl -u logtool-importer -f`
- Permissions note:
  - If nginx logs are `640 root:adm`, grant the importer read access by either:
    - Adding `SupplementaryGroups=adm` to `logtool-importer.service`, or
    - Running as `User=www-data`/`User=nginx` (uncomment in the unit), or
    - Setting ACLs (e.g., `setfacl -m g:adm:r /var/log/nginx/access.log /var/log/nginx/error.log`).

Flags
- `-db`: SQLite database path (default `./monitor.db`).
- `-access`: Access log path (default `./access.log`).
- `-error`: Error log path (default `./error.log`).
- `-ip-policy`: `store|mask|hash|drop` (default `mask`).
- `-ip-salt`: salt for `hash` policy (env `IP_SALT` also honored).

Notes
- Import is incremental: it records byte offsets + inodes in `import_state` to avoid re-reading lines across runs and handle truncation/rotation (active file only initially).
- Access format assumed: Combined Log Format plus `"$http_x_forwarded_for"` as a final quoted field.
  Example: `IP - - [time] "METHOD PATH PROTO" status bytes "referer" "ua" "xff"`
- Error format assumed: `YYYY/MM/DD HH:MM:SS [level] pid#tid: message`.

Future work
- Backfill rotated logs (optionally `.1` / dated / gz files).
- Web API + dashboard frontend on top of this schema.
- More parsers (timings, upstreams) if emitted by your `log_format`.
