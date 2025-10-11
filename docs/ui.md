# Web UI

## Purpose
Provides a dashboard visualization for imported traffic: summary metrics, time series charts, and top-N tables (paths, referrers, user agents, hosts, status distribution).

## Serving
Static assets delivered from directory passed via `--static` (e.g., `./web/dist`). Server binary maps HTTP requests for static files (implementation not shown in provided snippets but assumed in cmd/server). Unmatched API paths fall back appropriately (root path likely serves index.html for SPA patterns if implemented).

## Data Sources
UI fetches JSON from endpoints in `internal/webapi`:
- /api/summary for header stats
- /api/timeseries/requests & /api/timeseries/errors for chart lines
- /api/top/* endpoints supply tables
- /api/status for status code histogram
- /api/hosts for host filter dropdown
- /api/requests / /api/errors for detailed tables/log viewers

## Time Controls
Users can adjust duration (dur=) or explicit from/to to update all widgets; UI should coordinate queries with consistent time range (client caches last selection). Bucket size adjustable (minute/hour/day) for time series resolution.

## Host Filtering
Host selector applies ?host= param to all request-based endpoints (requests/time series/top lists). Option 'Unknown' maps to null/empty host records.

## Authentication UX
If session login configured, navigating to protected endpoint without session cookie triggers redirect to /login (server adds ?next= original path). After successful login, user returns to dashboard.

For Basic/Bearer auth configurations, UI likely prompts via browser (Basic) or stores token locally (Bearer) and sets Authorization header on fetches.

## Error Handling
UI should gracefully handle 401 (show login link or message), 400 (display validation error), and network failures (retry/backoff). /api/debug/dbinfo can inform user if DB empty (e.g., show onboarding instructions to run importer).

## Performance Considerations
Aggregate endpoints return compact JSON; pagination on /api/requests and /api/errors avoids large payloads. UI may implement polling or manual refresh; if polling, consider conditional frequency (e.g., slow down when tab hidden).

## Extensibility
Adding a new top-N endpoint requires:
1. Server handler (pattern handleTopX) returning JSON rows.
2. UI component to fetch and render table.
3. Optional inclusion in summary metrics or filters.

## Theming
Static login page uses dark theme inline styles; UI should maintain compatible design tokens for consistency.

