package webapi

import (
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "database/sql"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "strconv"
    "strings"
    "time"

    "golang.org/x/crypto/bcrypt"
)

type Server struct {
    db           *sql.DB
    defaultTZ    string
    enableCORS   bool
    basicUser    string
    basicPass    string
    bearerTokens map[string]struct{}
    // Form login (session cookie)
    loginUser    string
    passwordHash string // bcrypt hash string
    sessionSecret []byte
    sessionTTL   time.Duration
    cookieName   string
}

func New(db *sql.DB, defaultTZ string, enableCORS bool, basicUser, basicPass string, bearer []string) *Server {
    m := make(map[string]struct{})
    for _, t := range bearer {
        if tt := strings.TrimSpace(t); tt != "" { m[tt] = struct{}{} }
    }
    return &Server{db: db, defaultTZ: defaultTZ, enableCORS: enableCORS, basicUser: basicUser, basicPass: basicPass, bearerTokens: m, cookieName: "logtool_session", sessionTTL: 12 * time.Hour}
}

func (s *Server) RegisterRoutes(mux *http.ServeMux) {
    mux.HandleFunc("/health", s.wrap(s.handleHealth))
    mux.HandleFunc("/api/summary", s.wrap(s.handleSummary))
    mux.HandleFunc("/api/timeseries/requests", s.wrap(s.handleTSRequests))
    mux.HandleFunc("/api/timeseries/errors", s.wrap(s.handleTSErrors))
    mux.HandleFunc("/api/top/paths", s.wrap(s.handleTopPaths))
    mux.HandleFunc("/api/top/referrers", s.wrap(s.handleTopReferrers))
    mux.HandleFunc("/api/status", s.wrap(s.handleStatus))
    mux.HandleFunc("/api/requests", s.wrap(s.handleRequests))
    mux.HandleFunc("/api/errors", s.wrap(s.handleErrors))
    // Session login/logout (not wrapped to avoid redirect loops)
    mux.HandleFunc("/login", s.handleLogin)
    mux.HandleFunc("/logout", s.handleLogout)
}

func (s *Server) wrap(h func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if s.enableCORS {
            w.Header().Set("Access-Control-Allow-Origin", "*")
            w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
            w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
            if r.Method == http.MethodOptions {
                w.WriteHeader(http.StatusNoContent)
                return
            }
        }
        if s.authEnabled() {
            if !s.requireAuth(w, r, false) { return }
        }
        if r.Method == http.MethodHead {
            w.WriteHeader(http.StatusOK)
            return
        }
        if err := h(w, r); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
        }
    }
}

// Protect wraps an http.Handler with the same auth and CORS behavior as wrap.
func (s *Server) Protect(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if s.enableCORS {
            w.Header().Set("Access-Control-Allow-Origin", "*")
            w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
            w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
            if r.Method == http.MethodOptions {
                w.WriteHeader(http.StatusNoContent)
                return
            }
        }
        if s.authEnabled() {
            if !s.requireAuth(w, r, true) { return }
        }
        next.ServeHTTP(w, r)
    })
}

func (s *Server) requireBasicAuth(w http.ResponseWriter, r *http.Request) bool {
    user, pass, ok := r.BasicAuth()
    if !ok || user != s.basicUser || pass != s.basicPass {
        w.Header().Set("WWW-Authenticate", "Basic realm=\"Logtool\"")
        http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
        return false
    }
    return true
}

func (s *Server) authEnabled() bool {
    return s.basicUser != "" || len(s.bearerTokens) > 0 || s.passwordHash != ""
}

func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request, redirect bool) bool {
    // Accept either Bearer token or Basic auth when configured.
    if len(s.bearerTokens) > 0 {
        if auth := r.Header.Get("Authorization"); auth != "" {
            if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
                tok := strings.TrimSpace(auth[len("Bearer "):])
                if _, ok := s.bearerTokens[tok]; ok {
                    return true
                }
            }
        }
    }
    if s.basicUser != "" {
        if s.requireBasicAuth(w, r) { return true }
    }
    // Session cookie auth
    if s.passwordHash != "" {
        if s.verifySessionCookie(r) { return true }
        if redirect && r.Method == http.MethodGet {
            http.Redirect(w, r, "/login?next="+urlQueryEscape(r.URL.String()), http.StatusFound)
            return false
        }
    }
    // Send appropriate header for API clients
    if len(s.bearerTokens) > 0 {
        w.Header().Set("WWW-Authenticate", "Bearer realm=\"Logtool\"")
    } else if s.basicUser != "" {
        w.Header().Set("WWW-Authenticate", "Basic realm=\"Logtool\"")
    }
    http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
    return false
}

// --- Session login ---
func (s *Server) SetLogin(user, bcryptHash string, secret []byte, ttl time.Duration) {
    s.loginUser = user
    s.passwordHash = bcryptHash
    if len(secret) == 0 {
        secret = make([]byte, 32)
        _, _ = rand.Read(secret)
    }
    s.sessionSecret = secret
    if ttl > 0 { s.sessionTTL = ttl }
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
    if s.passwordHash == "" || s.loginUser == "" {
        http.Error(w, "login not configured", http.StatusNotFound)
        return
    }
    switch r.Method {
    case http.MethodGet:
        // Serve minimal login page
        next := r.URL.Query().Get("next")
        io.WriteString(w, loginPage(next))
    case http.MethodPost:
        if err := r.ParseForm(); err != nil {
            http.Error(w, "invalid form", http.StatusBadRequest)
            return
        }
        user := strings.TrimSpace(r.FormValue("username"))
        pass := r.FormValue("password")
        if user != s.loginUser {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        if err := bcrypt.CompareHashAndPassword([]byte(s.passwordHash), []byte(pass)); err != nil {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        // Issue session cookie
        s.setSessionCookie(w, user, s.sessionTTL)
        next := r.FormValue("next")
        if next == "" { next = "/" }
        http.Redirect(w, r, next, http.StatusFound)
    default:
        w.WriteHeader(http.StatusMethodNotAllowed)
    }
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
    // Expire cookie
    http.SetCookie(w, &http.Cookie{Name: s.cookieName, Value: "", Path: "/", HttpOnly: true, Expires: time.Unix(0,0), MaxAge: -1, SameSite: http.SameSiteLaxMode})
    http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, user string, ttl time.Duration) {
    exp := time.Now().Add(ttl).Unix()
    nonce := make([]byte, 16)
    _, _ = rand.Read(nonce)
    payload := fmt.Sprintf("v1|%d|%s|%s", exp, user, base64.RawURLEncoding.EncodeToString(nonce))
    mac := hmac.New(sha256.New, s.sessionSecret)
    mac.Write([]byte(payload))
    sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
    val := base64.RawURLEncoding.EncodeToString([]byte(payload+"|"+sig))
    http.SetCookie(w, &http.Cookie{Name: s.cookieName, Value: val, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func (s *Server) verifySessionCookie(r *http.Request) bool {
    c, err := r.Cookie(s.cookieName)
    if err != nil || c.Value == "" { return false }
    raw, err := base64.RawURLEncoding.DecodeString(c.Value)
    if err != nil { return false }
    parts := strings.Split(string(raw), "|")
    if len(parts) != 5 || parts[0] != "v1" { return false }
    // v1|exp|user|nonce|sig
    expStr, user, nonce, sig := parts[1], parts[2], parts[3], parts[4]
    exp, err := strconv.ParseInt(expStr, 10, 64)
    if err != nil || time.Now().Unix() >= exp { return false }
    payload := strings.Join(parts[:4], "|")
    mac := hmac.New(sha256.New, s.sessionSecret)
    mac.Write([]byte(payload))
    expected := mac.Sum(nil)
    got, err := base64.RawURLEncoding.DecodeString(sig)
    if err != nil { return false }
    if !hmac.Equal(expected, got) { return false }
    _ = user; _ = nonce // currently unused beyond presence
    return true
}

func urlQueryEscape(s string) string {
    // Minimal escape for query component (no external deps)
    return strings.ReplaceAll(strings.ReplaceAll(s, " ", "+"), "\n", "")
}

func loginPage(next string) string {
    return "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Logtool Login</title>" +
        "<style>:root{--bg:#0f1115;--panel:#171a21;--muted:#9aa3b2;--fg:#e8ecf1;--accent:#5aa6ff}html,body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui;-webkit-font-smoothing:antialiased} .wrap{display:flex;min-height:100vh;align-items:center;justify-content:center;padding:24px} .card{background:var(--panel);border:1px solid #242a35;border-radius:12px;padding:20px;max-width:360px;width:100%} h1{margin:0 0 12px 0;font-size:18px} label{display:block;font-size:12px;color:var(--muted);margin:10px 0 4px} input{width:100%;padding:10px 12px;border-radius:8px;border:1px solid #2a2f3a;background:#0f131b;color:var(--fg)} button{margin-top:14px;width:100%;padding:10px 12px;border-radius:8px;border:1px solid #2a2f3a;background:var(--accent);color:#0b1018;cursor:pointer;font-weight:600} .muted{color:var(--muted);font-size:12px;margin-top:8px;text-align:center}</style></head>" +
        "<body><div class=wrap><form class=card method=post action=/login>" +
        "<h1>Logtool — Sign in</h1>" +
        "<input type=hidden name=next value=\""+htmlEscape(next)+"\">" +
        "<label>Username</label><input name=username autocomplete=username autofocus required>" +
        "<label>Password</label><input type=password name=password autocomplete=current-password required>" +
        "<button type=submit>Sign in</button>" +
        "<div class=muted>Access restricted</div>" +
        "</form></div></body></html>"
}

func htmlEscape(s string) string {
    r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;")
    return r.Replace(s)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) error {
    w.WriteHeader(http.StatusOK)
    _, _ = w.Write([]byte("ok"))
    return nil
}

// Helpers
func writeJSON(w http.ResponseWriter, v interface{}) error {
    w.Header().Set("Content-Type", "application/json")
    enc := json.NewEncoder(w)
    enc.SetIndent("", " ")
    return enc.Encode(v)
}

func (s *Server) parseRange(r *http.Request) (from, to int64, err error) {
    // Accept `from`, `to` as RFC3339 or unix seconds. Defaults: from=now-7d, to=now.
    now := time.Now().UTC().Unix()
    fromStr := strings.TrimSpace(r.URL.Query().Get("from"))
    toStr := strings.TrimSpace(r.URL.Query().Get("to"))
    if toStr == "" { to = now } else { to, err = parseTimeParam(toStr); if err != nil { return } }
    if fromStr == "" { from = to - 7*86400 } else { from, err = parseTimeParam(fromStr); if err != nil { return } }
    if from > to { from, to = to-1, to }
    return
}

func parseTimeParam(s string) (int64, error) {
    if s == "" { return 0, fmt.Errorf("empty time") }
    if n, err := strconv.ParseInt(s, 10, 64); err == nil { return n, nil }
    // Try RFC3339
    if t, err := time.Parse(time.RFC3339, s); err == nil { return t.UTC().Unix(), nil }
    return 0, fmt.Errorf("invalid time: %s", s)
}

func (s *Server) parseBucket(r *http.Request) (bucketSec int64, tzOffset int64) {
    bucket := r.URL.Query().Get("bucket")
    switch bucket {
    case "minute": bucketSec = 60
    case "day": bucketSec = 86400
    default: bucketSec = 3600 // hour
    }
    tz := r.URL.Query().Get("tz")
    if tz == "" { tz = s.defaultTZ }
    tzOffset = parseTZOffsetSeconds(tz) // may be 0
    return
}

func parseTZOffsetSeconds(tz string) int64 {
    tz = strings.TrimSpace(tz)
    if tz == "" || tz == "Z" || tz == "+00:00" || tz == "-00:00" { return 0 }
    sign := int64(1)
    if tz[0] == '-' { sign = -1 }
    nums := strings.Split(strings.Trim(tz, "+-"), ":")
    if len(nums) != 2 { return 0 }
    h, _ := strconv.ParseInt(nums[0], 10, 64)
    m, _ := strconv.ParseInt(nums[1], 10, 64)
    return sign * (h*3600 + m*60)
}

// Summary aggregates basic info for a quick dashboard header.
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) error {
    from, to, err := s.parseRange(r)
    if err != nil { return err }
    type Summary struct {
        From int64 `json:"from"`
        To int64 `json:"to"`
        Requests int64 `json:"requests"`
        UniqueRemote int64 `json:"unique_remote"`
        Errors int64 `json:"errors"`
        LastRequest *string `json:"last_request,omitempty"`
    }
    var sum Summary
    sum.From, sum.To = from, to
    // Requests count
    row := s.db.QueryRow(`SELECT COUNT(*) FROM request_events WHERE ts_unix BETWEEN ? AND ?`, from, to)
    _ = row.Scan(&sum.Requests)
    // Unique (approx depends on policy)
    row = s.db.QueryRow(`SELECT COUNT(DISTINCT COALESCE(remote_addr, '')) FROM request_events WHERE ts_unix BETWEEN ? AND ?`, from, to)
    _ = row.Scan(&sum.UniqueRemote)
    // Errors count
    row = s.db.QueryRow(`SELECT COUNT(*) FROM error_events WHERE ts_unix BETWEEN ? AND ?`, from, to)
    _ = row.Scan(&sum.Errors)
    // Last request timestamp
    var last string
    row = s.db.QueryRow(`SELECT ts FROM request_events ORDER BY ts_unix DESC LIMIT 1`)
    if err := row.Scan(&last); err == nil { sum.LastRequest = &last }
    return writeJSON(w, sum)
}

// Time series of request counts.
func (s *Server) handleTSRequests(w http.ResponseWriter, r *http.Request) error {
    from, to, err := s.parseRange(r)
    if err != nil { return err }
    bucket, tzOff := s.parseBucket(r)
    // bucket_key = ((ts_unix + tzOff)/bucket)*bucket
    rows, err := s.db.Query(`SELECT ((ts_unix + ?)/?)*? AS b, COUNT(*) FROM request_events WHERE ts_unix BETWEEN ? AND ? GROUP BY b ORDER BY b`, tzOff, bucket, bucket, from, to)
    if err != nil { return err }
    defer rows.Close()
    type Point struct { T string `json:"t"`; Count int64 `json:"count"` }
    var out []Point
    for rows.Next() {
        var b int64
        var c int64
        if err := rows.Scan(&b, &c); err != nil { return err }
        // Convert back to UTC ISO start time by subtracting tzOff
        t := time.Unix(b - tzOff, 0).UTC().Format(time.RFC3339)
        out = append(out, Point{T: t, Count: c})
    }
    return writeJSON(w, out)
}

func (s *Server) handleTSErrors(w http.ResponseWriter, r *http.Request) error {
    from, to, err := s.parseRange(r)
    if err != nil { return err }
    bucket, tzOff := s.parseBucket(r)
    rows, err := s.db.Query(`SELECT ((ts_unix + ?)/?)*? AS b, COUNT(*) FROM error_events WHERE ts_unix BETWEEN ? AND ? GROUP BY b ORDER BY b`, tzOff, bucket, bucket, from, to)
    if err != nil { return err }
    defer rows.Close()
    type Point struct { T string `json:"t"`; Count int64 `json:"count"` }
    var out []Point
    for rows.Next() {
        var b, c int64
        if err := rows.Scan(&b, &c); err != nil { return err }
        t := time.Unix(b - tzOff, 0).UTC().Format(time.RFC3339)
        out = append(out, Point{T: t, Count: c})
    }
    return writeJSON(w, out)
}

func (s *Server) handleTopPaths(w http.ResponseWriter, r *http.Request) error {
    from, to, err := s.parseRange(r)
    if err != nil { return err }
    limit := clampInt(r.URL.Query().Get("limit"), 10, 1, 100)
    rows, err := s.db.Query(`SELECT path, COUNT(*) as c FROM request_events WHERE ts_unix BETWEEN ? AND ? AND path IS NOT NULL AND path != '' GROUP BY path ORDER BY c DESC LIMIT ?`, from, to, limit)
    if err != nil { return err }
    defer rows.Close()
    type Row struct { Path string `json:"path"`; Count int64 `json:"count"` }
    var out []Row
    for rows.Next() {
        var p string; var c int64
        if err := rows.Scan(&p, &c); err != nil { return err }
        out = append(out, Row{Path: p, Count: c})
    }
    return writeJSON(w, out)
}

func (s *Server) handleTopReferrers(w http.ResponseWriter, r *http.Request) error {
    from, to, err := s.parseRange(r)
    if err != nil { return err }
    limit := clampInt(r.URL.Query().Get("limit"), 10, 1, 100)
    includeEmpty := r.URL.Query().Get("include_empty") == "true"
    var rows *sql.Rows
    if includeEmpty {
        rows, err = s.db.Query(`SELECT COALESCE(referer, '') AS ref, COUNT(*) as c FROM request_events WHERE ts_unix BETWEEN ? AND ? GROUP BY ref ORDER BY c DESC LIMIT ?`, from, to, limit)
    } else {
        rows, err = s.db.Query(`SELECT referer AS ref, COUNT(*) as c FROM request_events WHERE ts_unix BETWEEN ? AND ? AND referer IS NOT NULL AND referer != '' GROUP BY ref ORDER BY c DESC LIMIT ?`, from, to, limit)
    }
    if err != nil { return err }
    defer rows.Close()
    type Row struct { Referrer string `json:"referrer"`; Count int64 `json:"count"` }
    var out []Row
    for rows.Next() {
        var ref string; var c int64
        if err := rows.Scan(&ref, &c); err != nil { return err }
        out = append(out, Row{Referrer: ref, Count: c})
    }
    return writeJSON(w, out)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) error {
    from, to, err := s.parseRange(r)
    if err != nil { return err }
    rows, err := s.db.Query(`SELECT COALESCE(status, 0) AS status, COUNT(*) FROM request_events WHERE ts_unix BETWEEN ? AND ? GROUP BY COALESCE(status, 0) ORDER BY status`, from, to)
    if err != nil { return err }
    defer rows.Close()
    type Row struct { Status int `json:"status"`; Count int64 `json:"count"` }
    var out []Row
    for rows.Next() {
        var status int; var c int64
        if err := rows.Scan(&status, &c); err != nil { return err }
        out = append(out, Row{Status: status, Count: c})
    }
    return writeJSON(w, out)
}

func (s *Server) handleRequests(w http.ResponseWriter, r *http.Request) error {
    from, to, err := s.parseRange(r)
    if err != nil { return err }
    limit := clampInt(r.URL.Query().Get("limit"), 100, 1, 1000)
    offset := clampInt(r.URL.Query().Get("offset"), 0, 0, 1000000)
    method := strings.TrimSpace(r.URL.Query().Get("method"))
    status := r.URL.Query().Get("status")
    pathLike := strings.TrimSpace(r.URL.Query().Get("path_like"))
    includeUnparsed := r.URL.Query().Get("include_unparsed") == "true"
    // Build WHERE dynamically with args
    where := "ts_unix BETWEEN ? AND ?"
    args := []interface{}{from, to}
    if !includeUnparsed {
        // Hide rows created from unparsed lines (which have empty method/path)
        where += " AND method IS NOT NULL AND method != '' AND path IS NOT NULL AND path != ''"
    }
    if method != "" { where += " AND method = ?"; args = append(args, method) }
    if status != "" { if n, err := strconv.Atoi(status); err == nil { where += " AND status = ?"; args = append(args, n) } }
    if pathLike != "" { where += " AND path LIKE ?"; args = append(args, pathLike) }
    q := fmt.Sprintf(`SELECT ts,
                             COALESCE(remote_addr, '') AS remote_addr,
                             xff,
                             COALESCE(method, '') AS method,
                             COALESCE(path, '') AS path,
                             COALESCE(protocol, '') AS protocol,
                             COALESCE(status, 0) AS status,
                             COALESCE(bytes_sent, 0) AS bytes_sent,
                             referer,
                             user_agent
                      FROM request_events WHERE %s ORDER BY ts_unix DESC LIMIT ? OFFSET ?`, where)
    args = append(args, limit, offset)
    rows, err := s.db.Query(q, args...)
    if err != nil { return err }
    defer rows.Close()
    type Row struct {
        TS string `json:"ts"`
        Remote string `json:"remote"`
        XFF *string `json:"xff,omitempty"`
        Method string `json:"method"`
        Path string `json:"path"`
        Proto string `json:"proto"`
        Status int `json:"status"`
        Bytes int `json:"bytes"`
        Referer *string `json:"referer,omitempty"`
        UA *string `json:"ua,omitempty"`
    }
    var out []Row
    for rows.Next() {
        var rr Row
        var xff, ref, ua sql.NullString
        var remote sql.NullString
        if err := rows.Scan(&rr.TS, &remote, &xff, &rr.Method, &rr.Path, &rr.Proto, &rr.Status, &rr.Bytes, &ref, &ua); err != nil { return err }
        rr.Remote = remote.String
        if xff.Valid { s := xff.String; rr.XFF = &s }
        if ref.Valid { s := ref.String; rr.Referer = &s }
        if ua.Valid { s := ua.String; rr.UA = &s }
        out = append(out, rr)
    }
    return writeJSON(w, out)
}

func (s *Server) handleErrors(w http.ResponseWriter, r *http.Request) error {
    from, to, err := s.parseRange(r)
    if err != nil { return err }
    limit := clampInt(r.URL.Query().Get("limit"), 100, 1, 1000)
    offset := clampInt(r.URL.Query().Get("offset"), 0, 0, 1000000)
    level := strings.TrimSpace(r.URL.Query().Get("level"))
    where := "ts_unix BETWEEN ? AND ?"
    args := []interface{}{from, to}
    if level != "" { where += " AND level = ?"; args = append(args, level) }
    q := fmt.Sprintf(`SELECT ts,
                             COALESCE(level, '') AS level,
                             COALESCE(pid, 0) AS pid,
                             COALESCE(tid, 0) AS tid,
                             COALESCE(message, '') AS message
                      FROM error_events WHERE %s ORDER BY ts_unix DESC LIMIT ? OFFSET ?`, where)
    args = append(args, limit, offset)
    rows, err := s.db.Query(q, args...)
    if err != nil { return err }
    defer rows.Close()
    type Row struct { TS string `json:"ts"`; Level string `json:"level"`; PID int `json:"pid"`; TID int `json:"tid"`; Message string `json:"message"` }
    var out []Row
    for rows.Next() {
        var rr Row
        if err := rows.Scan(&rr.TS, &rr.Level, &rr.PID, &rr.TID, &rr.Message); err != nil { return err }
        out = append(out, rr)
    }
    return writeJSON(w, out)
}

func clampInt(s string, def, min, max int) int {
    if s == "" { return def }
    n, err := strconv.Atoi(s)
    if err != nil { return def }
    if n < min { return min }
    if n > max { return max }
    return n
}
