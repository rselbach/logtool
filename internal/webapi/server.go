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
	"math"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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
	loginUser     string
	passwordHash  string // bcrypt hash string
	sessionSecret []byte
	sessionTTL    time.Duration
	cookieName    string
}

func New(db *sql.DB, defaultTZ string, enableCORS bool, basicUser, basicPass string, bearer []string) *Server {
	m := make(map[string]struct{})
	for _, t := range bearer {
		if tt := strings.TrimSpace(t); tt != "" {
			m[tt] = struct{}{}
		}
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
	mux.HandleFunc("/api/top/ua", s.wrap(s.handleTopUA))
	mux.HandleFunc("/api/top/ua_families", s.wrap(s.handleTopUAFamilies))
	mux.HandleFunc("/api/status", s.wrap(s.handleStatus))
	mux.HandleFunc("/api/requests", s.wrap(s.handleRequests))
	mux.HandleFunc("/api/errors", s.wrap(s.handleErrors))
	mux.HandleFunc("/api/debug/dbinfo", s.wrap(s.handleDebugDBInfo))
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
			if !s.requireAuth(w, r, false) {
				return
			}
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
			if !s.requireAuth(w, r, true) {
				return
			}
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
		if s.requireBasicAuth(w, r) {
			return true
		}
	}
	// Session cookie auth
	if s.passwordHash != "" {
		if s.verifySessionCookie(r) {
			return true
		}
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
	if ttl > 0 {
		s.sessionTTL = ttl
	}
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
		if next == "" {
			next = "/"
		}
		http.Redirect(w, r, next, http.StatusFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Expire cookie
	http.SetCookie(w, &http.Cookie{Name: s.cookieName, Value: "", Path: "/", HttpOnly: true, Expires: time.Unix(0, 0), MaxAge: -1, SameSite: http.SameSiteLaxMode})
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
	val := base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + sig))
	http.SetCookie(w, &http.Cookie{Name: s.cookieName, Value: val, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func (s *Server) verifySessionCookie(r *http.Request) bool {
	c, err := r.Cookie(s.cookieName)
	if err != nil || c.Value == "" {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 5 || parts[0] != "v1" {
		return false
	}
	// v1|exp|user|nonce|sig
	expStr, user, nonce, sig := parts[1], parts[2], parts[3], parts[4]
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return false
	}
	payload := strings.Join(parts[:4], "|")
	mac := hmac.New(sha256.New, s.sessionSecret)
	mac.Write([]byte(payload))
	expected := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	if !hmac.Equal(expected, got) {
		return false
	}
	_ = user
	_ = nonce // currently unused beyond presence
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
		"<input type=hidden name=next value=\"" + htmlEscape(next) + "\">" +
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
	// Ensure empty slices/maps encode as [] / {} (not null)
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Slice:
		if rv.IsNil() {
			v = reflect.MakeSlice(rv.Type(), 0, 0).Interface()
		}
	case reflect.Map:
		if rv.IsNil() {
			v = reflect.MakeMap(rv.Type()).Interface()
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	return enc.Encode(v)
}

func (s *Server) parseRange(r *http.Request) (from, to int64, err error) {
	// Accept `from`, `to` as RFC3339 or unix seconds. Defaults: from=now-7d, to=now.
	now := time.Now().UTC().Unix()
	fromStr := strings.TrimSpace(r.URL.Query().Get("from"))
	toStr := strings.TrimSpace(r.URL.Query().Get("to"))
	durStr := strings.TrimSpace(r.URL.Query().Get("dur"))
	if durStr != "" {
		dur, derr := parseDurationParam(durStr)
		if derr != nil {
			return 0, 0, fmt.Errorf("invalid duration: %w", derr)
		}
		if toStr == "" {
			to = now
		} else {
			to, err = parseTimeParam(toStr)
			if err != nil {
				return 0, 0, err
			}
		}
		span := int64(dur / time.Second)
		if span <= 0 {
			span = 1
		}
		from = to - span
		if from < 0 {
			from = 0
		}
		if from > to {
			from, to = to-1, to
		}
		return
	}
	if toStr == "" {
		to = now
	} else {
		to, err = parseTimeParam(toStr)
		if err != nil {
			return
		}
	}
	if fromStr == "" {
		from = to - 7*86400
	} else {
		from, err = parseTimeParam(fromStr)
		if err != nil {
			return
		}
	}
	if from > to {
		from, to = to-1, to
	}
	return
}

func parseTimeParam(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty time")
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	// Try RFC3339
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC().Unix(), nil
	}
	return 0, fmt.Errorf("invalid time: %s", s)
}

func parseDurationParam(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if s[0] == '+' {
		s = s[1:]
	}
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if s[0] == '-' {
		return 0, fmt.Errorf("duration must be positive")
	}
	units := map[string]time.Duration{
		"ns":   time.Nanosecond,
		"us":   time.Microsecond,
		"µs":   time.Microsecond,
		"μs":   time.Microsecond,
		"ms":   time.Millisecond,
		"s":    time.Second,
		"m":    time.Minute,
		"h":    time.Hour,
		"d":    24 * time.Hour,
		"day":  24 * time.Hour,
		"w":    7 * 24 * time.Hour,
		"week": 7 * 24 * time.Hour,
	}
	rest := s
	var total float64
	for len(rest) > 0 {
		numEnd := 0
		dotCount := 0
		for numEnd < len(rest) {
			r, size := utf8.DecodeRuneInString(rest[numEnd:])
			if unicode.IsDigit(r) {
				numEnd += size
				continue
			}
			if r == '.' {
				dotCount++
				if dotCount > 1 {
					return 0, fmt.Errorf("invalid duration: %s", s)
				}
				numEnd += size
				continue
			}
			break
		}
		if numEnd == 0 {
			return 0, fmt.Errorf("invalid duration: %s", s)
		}
		valueStr := rest[:numEnd]
		value, err := strconv.ParseFloat(valueStr, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration: %s", s)
		}
		rest = rest[numEnd:]
		if len(rest) == 0 {
			return 0, fmt.Errorf("missing duration unit in %s", s)
		}
		unitEnd := 0
		for unitEnd < len(rest) {
			r, size := utf8.DecodeRuneInString(rest[unitEnd:])
			if unicode.IsLetter(r) {
				unitEnd += size
				continue
			}
			break
		}
		if unitEnd == 0 {
			return 0, fmt.Errorf("invalid duration: %s", s)
		}
		unit := rest[:unitEnd]
		rest = rest[unitEnd:]
		unitLower := strings.ToLower(unit)
		switch unitLower {
		case "µs", "μs":
			unitLower = "us"
		}
		base, ok := units[unitLower]
		if !ok {
			return 0, fmt.Errorf("unsupported duration unit: %s", unit)
		}
		total += value * float64(base)
	}
	if total <= 0 {
		return 0, fmt.Errorf("duration must be positive")
	}
	if total > float64(math.MaxInt64) {
		return 0, fmt.Errorf("duration too large")
	}
	ns := math.Round(total)
	if ns <= 0 {
		return 0, fmt.Errorf("duration must be positive")
	}
	return time.Duration(ns), nil
}

func (s *Server) parseBucket(r *http.Request) (bucketSec int64, tzOffset int64) {
	bucket := r.URL.Query().Get("bucket")
	switch bucket {
	case "minute":
		bucketSec = 60
	case "day":
		bucketSec = 86400
	default:
		bucketSec = 3600 // hour
	}
	tz := r.URL.Query().Get("tz")
	if tz == "" {
		tz = s.defaultTZ
	}
	tzOffset = parseTZOffsetSeconds(tz) // may be 0
	return
}

func parseTZOffsetSeconds(tz string) int64 {
	tz = strings.TrimSpace(tz)
	if tz == "" || tz == "Z" || tz == "+00:00" || tz == "-00:00" {
		return 0
	}
	sign := int64(1)
	if tz[0] == '-' {
		sign = -1
	}
	nums := strings.Split(strings.Trim(tz, "+-"), ":")
	if len(nums) != 2 {
		return 0
	}
	h, _ := strconv.ParseInt(nums[0], 10, 64)
	m, _ := strconv.ParseInt(nums[1], 10, 64)
	return sign * (h*3600 + m*60)
}

// Summary aggregates basic info for a quick dashboard header.
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) error {
	from, to, err := s.parseRange(r)
	if err != nil {
		return err
	}
	type Summary struct {
		From         int64   `json:"from"`
		To           int64   `json:"to"`
		Requests     int64   `json:"requests"`
		UniqueRemote int64   `json:"unique_remote"`
		Errors       int64   `json:"errors"`
		LastRequest  *string `json:"last_request,omitempty"`
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
	if err := row.Scan(&last); err == nil {
		sum.LastRequest = &last
	}
	return writeJSON(w, sum)
}

// Time series of request counts.
func (s *Server) handleTSRequests(w http.ResponseWriter, r *http.Request) error {
	from, to, err := s.parseRange(r)
	if err != nil {
		return err
	}
	bucket, tzOff := s.parseBucket(r)
	// bucket_key = ((ts_unix + tzOff)/bucket)*bucket
	rows, err := s.db.Query(`SELECT ((ts_unix + ?)/?)*? AS b, COUNT(*) FROM request_events WHERE ts_unix BETWEEN ? AND ? GROUP BY b ORDER BY b`, tzOff, bucket, bucket, from, to)
	if err != nil {
		return err
	}
	defer rows.Close()
	type Point struct {
		T     string `json:"t"`
		Count int64  `json:"count"`
	}
	var out []Point
	for rows.Next() {
		var b int64
		var c int64
		if err := rows.Scan(&b, &c); err != nil {
			return err
		}
		// Convert back to UTC ISO start time by subtracting tzOff
		t := time.Unix(b-tzOff, 0).UTC().Format(time.RFC3339)
		out = append(out, Point{T: t, Count: c})
	}
	return writeJSON(w, out)
}

func (s *Server) handleTSErrors(w http.ResponseWriter, r *http.Request) error {
	from, to, err := s.parseRange(r)
	if err != nil {
		return err
	}
	bucket, tzOff := s.parseBucket(r)
	rows, err := s.db.Query(`SELECT ((ts_unix + ?)/?)*? AS b, COUNT(*) FROM error_events WHERE ts_unix BETWEEN ? AND ? GROUP BY b ORDER BY b`, tzOff, bucket, bucket, from, to)
	if err != nil {
		return err
	}
	defer rows.Close()
	type Point struct {
		T     string `json:"t"`
		Count int64  `json:"count"`
	}
	var out []Point
	for rows.Next() {
		var b, c int64
		if err := rows.Scan(&b, &c); err != nil {
			return err
		}
		t := time.Unix(b-tzOff, 0).UTC().Format(time.RFC3339)
		out = append(out, Point{T: t, Count: c})
	}
	return writeJSON(w, out)
}

func (s *Server) handleTopPaths(w http.ResponseWriter, r *http.Request) error {
	from, to, err := s.parseRange(r)
	if err != nil {
		return err
	}
	limit := clampInt(r.URL.Query().Get("limit"), 10, 1, 100)
	rows, err := s.db.Query(`SELECT path, COUNT(*) as c FROM request_events WHERE ts_unix BETWEEN ? AND ? AND path IS NOT NULL AND path != '' GROUP BY path ORDER BY c DESC LIMIT ?`, from, to, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	type Row struct {
		Path  string `json:"path"`
		Count int64  `json:"count"`
	}
	var out []Row
	for rows.Next() {
		var p string
		var c int64
		if err := rows.Scan(&p, &c); err != nil {
			return err
		}
		out = append(out, Row{Path: p, Count: c})
	}
	return writeJSON(w, out)
}

func (s *Server) handleTopReferrers(w http.ResponseWriter, r *http.Request) error {
	from, to, err := s.parseRange(r)
	if err != nil {
		return err
	}
	limit := clampInt(r.URL.Query().Get("limit"), 10, 1, 100)
	includeEmpty := r.URL.Query().Get("include_empty") == "true"
	var rows *sql.Rows
	if includeEmpty {
		rows, err = s.db.Query(`SELECT COALESCE(referer, '') AS ref, COUNT(*) as c FROM request_events WHERE ts_unix BETWEEN ? AND ? GROUP BY ref ORDER BY c DESC LIMIT ?`, from, to, limit)
	} else {
		rows, err = s.db.Query(`SELECT referer AS ref, COUNT(*) as c FROM request_events WHERE ts_unix BETWEEN ? AND ? AND referer IS NOT NULL AND referer != '' GROUP BY ref ORDER BY c DESC LIMIT ?`, from, to, limit)
	}
	if err != nil {
		return err
	}
	defer rows.Close()
	type Row struct {
		Referrer string `json:"referrer"`
		Count    int64  `json:"count"`
	}
	var out []Row
	for rows.Next() {
		var ref string
		var c int64
		if err := rows.Scan(&ref, &c); err != nil {
			return err
		}
		out = append(out, Row{Referrer: ref, Count: c})
	}
	return writeJSON(w, out)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) error {
	from, to, err := s.parseRange(r)
	if err != nil {
		return err
	}
	rows, err := s.db.Query(`SELECT COALESCE(status, 0) AS status, COUNT(*) FROM request_events WHERE ts_unix BETWEEN ? AND ? GROUP BY COALESCE(status, 0) ORDER BY status`, from, to)
	if err != nil {
		return err
	}
	defer rows.Close()
	type Row struct {
		Status int   `json:"status"`
		Count  int64 `json:"count"`
	}
	var out []Row
	for rows.Next() {
		var status int
		var c int64
		if err := rows.Scan(&status, &c); err != nil {
			return err
		}
		out = append(out, Row{Status: status, Count: c})
	}
	return writeJSON(w, out)
}

func (s *Server) handleRequests(w http.ResponseWriter, r *http.Request) error {
	from, to, err := s.parseRange(r)
	if err != nil {
		return err
	}
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
	if method != "" {
		where += " AND method = ?"
		args = append(args, method)
	}
	if status != "" {
		if n, err := strconv.Atoi(status); err == nil {
			where += " AND status = ?"
			args = append(args, n)
		}
	}
	if pathLike != "" {
		where += " AND path LIKE ?"
		args = append(args, pathLike)
	}
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
	if err != nil {
		return err
	}
	defer rows.Close()
	type Row struct {
		TS      string  `json:"ts"`
		Remote  string  `json:"remote"`
		XFF     *string `json:"xff,omitempty"`
		Method  string  `json:"method"`
		Path    string  `json:"path"`
		Proto   string  `json:"proto"`
		Status  int     `json:"status"`
		Bytes   int     `json:"bytes"`
		Referer *string `json:"referer,omitempty"`
		UA      *string `json:"ua,omitempty"`
	}
	var out []Row
	for rows.Next() {
		var rr Row
		var xff, ref, ua sql.NullString
		var remote sql.NullString
		if err := rows.Scan(&rr.TS, &remote, &xff, &rr.Method, &rr.Path, &rr.Proto, &rr.Status, &rr.Bytes, &ref, &ua); err != nil {
			return err
		}
		rr.Remote = remote.String
		if xff.Valid {
			s := xff.String
			rr.XFF = &s
		}
		if ref.Valid {
			s := ref.String
			rr.Referer = &s
		}
		if ua.Valid {
			s := ua.String
			rr.UA = &s
		}
		out = append(out, rr)
	}
	return writeJSON(w, out)
}

func (s *Server) handleErrors(w http.ResponseWriter, r *http.Request) error {
	from, to, err := s.parseRange(r)
	if err != nil {
		return err
	}
	limit := clampInt(r.URL.Query().Get("limit"), 100, 1, 1000)
	offset := clampInt(r.URL.Query().Get("offset"), 0, 0, 1000000)
	level := strings.TrimSpace(r.URL.Query().Get("level"))
	where := "ts_unix BETWEEN ? AND ?"
	args := []interface{}{from, to}
	if level != "" {
		where += " AND level = ?"
		args = append(args, level)
	}
	q := fmt.Sprintf(`SELECT ts,
                             COALESCE(level, '') AS level,
                             COALESCE(pid, 0) AS pid,
                             COALESCE(tid, 0) AS tid,
                             COALESCE(message, '') AS message
                      FROM error_events WHERE %s ORDER BY ts_unix DESC LIMIT ? OFFSET ?`, where)
	args = append(args, limit, offset)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	type Row struct {
		TS      string `json:"ts"`
		Level   string `json:"level"`
		PID     int    `json:"pid"`
		TID     int    `json:"tid"`
		Message string `json:"message"`
	}
	var out []Row
	for rows.Next() {
		var rr Row
		if err := rows.Scan(&rr.TS, &rr.Level, &rr.PID, &rr.TID, &rr.Message); err != nil {
			return err
		}
		out = append(out, rr)
	}
	return writeJSON(w, out)
}

// Top raw user agents (exact strings)
func (s *Server) handleTopUA(w http.ResponseWriter, r *http.Request) error {
	from, to, err := s.parseRange(r)
	if err != nil {
		return err
	}
	limit := clampInt(r.URL.Query().Get("limit"), 20, 1, 200)
	includeEmpty := r.URL.Query().Get("include_empty") == "true"
	var rows *sql.Rows
	if includeEmpty {
		rows, err = s.db.Query(`SELECT COALESCE(user_agent, '') AS ua, COUNT(*) as c FROM request_events WHERE ts_unix BETWEEN ? AND ? GROUP BY ua ORDER BY c DESC LIMIT ?`, from, to, limit)
	} else {
		rows, err = s.db.Query(`SELECT user_agent AS ua, COUNT(*) as c FROM request_events WHERE ts_unix BETWEEN ? AND ? AND user_agent IS NOT NULL AND user_agent != '' GROUP BY ua ORDER BY c DESC LIMIT ?`, from, to, limit)
	}
	if err != nil {
		return err
	}
	defer rows.Close()
	type Row struct {
		UA    string `json:"ua"`
		Count int64  `json:"count"`
	}
	var out []Row
	for rows.Next() {
		var ua string
		var c int64
		if err := rows.Scan(&ua, &c); err != nil {
			return err
		}
		out = append(out, Row{UA: ua, Count: c})
	}
	return writeJSON(w, out)
}

// Top UA families (simple classification)
func (s *Server) handleTopUAFamilies(w http.ResponseWriter, r *http.Request) error {
	from, to, err := s.parseRange(r)
	if err != nil {
		return err
	}
	limit := clampInt(r.URL.Query().Get("limit"), 20, 1, 200)
	rows, err := s.db.Query(`SELECT user_agent FROM request_events WHERE ts_unix BETWEEN ? AND ? AND user_agent IS NOT NULL AND user_agent != ''`, from, to)
	if err != nil {
		return err
	}
	defer rows.Close()
	counts := map[string]int64{}
	for rows.Next() {
		var ua string
		if err := rows.Scan(&ua); err != nil {
			return err
		}
		fam := classifyUAFamily(ua)
		counts[fam]++
	}
	type Row struct {
		Family string `json:"family"`
		Count  int64  `json:"count"`
	}
	var items []Row
	for k, v := range counts {
		items = append(items, Row{Family: k, Count: v})
	}
	// sort by count desc
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Family < items[j].Family
		}
		return items[i].Count > items[j].Count
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return writeJSON(w, items)
}

// Debug: return DB path and basic counts/ranges to help diagnose empty results.
func (s *Server) handleDebugDBInfo(w http.ResponseWriter, r *http.Request) error {
	// Resolve DB file path via PRAGMA database_list
	var dbPath string
	if rows, err := s.db.Query(`PRAGMA database_list;`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var seq int
			var name, file string
			if err := rows.Scan(&seq, &name, &file); err == nil {
				if name == "main" {
					dbPath = file
				}
			}
		}
	}
	type Range struct {
		Total    int64   `json:"total"`
		Parsed   int64   `json:"parsed,omitempty"`
		Unparsed int64   `json:"unparsed,omitempty"`
		MinUnix  int64   `json:"min_unix"`
		MaxUnix  int64   `json:"max_unix"`
		MinISO   *string `json:"min_iso,omitempty"`
		MaxISO   *string `json:"max_iso,omitempty"`
	}
	var req, errr Range
	// Requests
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM request_events`).Scan(&req.Total)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM request_events WHERE method IS NOT NULL AND method != '' AND path IS NOT NULL AND path != ''`).Scan(&req.Parsed)
	req.Unparsed = req.Total - req.Parsed
	_ = s.db.QueryRow(`SELECT COALESCE(MIN(ts_unix),0), COALESCE(MAX(ts_unix),0) FROM request_events`).Scan(&req.MinUnix, &req.MaxUnix)
	if req.MinUnix > 0 {
		s := time.Unix(req.MinUnix, 0).UTC().Format(time.RFC3339)
		req.MinISO = &s
	}
	if req.MaxUnix > 0 {
		s := time.Unix(req.MaxUnix, 0).UTC().Format(time.RFC3339)
		req.MaxISO = &s
	}
	// Errors
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM error_events`).Scan(&errr.Total)
	_ = s.db.QueryRow(`SELECT COALESCE(MIN(ts_unix),0), COALESCE(MAX(ts_unix),0) FROM error_events`).Scan(&errr.MinUnix, &errr.MaxUnix)
	if errr.MinUnix > 0 {
		s2 := time.Unix(errr.MinUnix, 0).UTC().Format(time.RFC3339)
		errr.MinISO = &s2
	}
	if errr.MaxUnix > 0 {
		s2 := time.Unix(errr.MaxUnix, 0).UTC().Format(time.RFC3339)
		errr.MaxISO = &s2
	}

	// Import state
	type ImportState struct {
		LogName   string `json:"log_name"`
		Inode     int64  `json:"inode"`
		Position  int64  `json:"position"`
		LastMtime int64  `json:"last_mtime"`
		LastSize  int64  `json:"last_size"`
		UpdatedAt int64  `json:"updated_at"`
	}
	var states []ImportState
	if rows, err := s.db.Query(`SELECT log_name, COALESCE(inode,0), COALESCE(position,0), COALESCE(last_mtime,0), COALESCE(last_size,0), COALESCE(updated_at,0) FROM import_state ORDER BY log_name`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var st ImportState
			if scanErr := rows.Scan(&st.LogName, &st.Inode, &st.Position, &st.LastMtime, &st.LastSize, &st.UpdatedAt); scanErr == nil {
				states = append(states, st)
			}
		}
	}
	resp := map[string]interface{}{
		"db_path":      dbPath,
		"requests":     req,
		"errors":       errr,
		"import_state": states,
	}
	return writeJSON(w, resp)
}

func clampInt(s string, def, min, max int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

// classifyUAFamily maps a User-Agent string to a coarse family label.
// Kept lightweight to avoid heavy UA parsing dependencies.
func classifyUAFamily(ua string) string {
	if ua == "" {
		return "(none)"
	}
	s := strings.ToLower(ua)
	// Libraries/bots
	if strings.Contains(s, "curl/") || s == "curl" {
		return "curl"
	}
	if strings.Contains(s, "wget/") || s == "wget" {
		return "wget"
	}
	if strings.Contains(s, "python-requests") || strings.Contains(s, "requests/") {
		return "python-requests"
	}
	if strings.Contains(s, "go-http-client") {
		return "Go-http-client"
	}
	if strings.Contains(s, "wordpress/") {
		return "WordPress"
	}
	if strings.Contains(s, "rss") || strings.Contains(s, "feed") {
		return "Feed Reader"
	}
	if strings.Contains(s, "bot") || strings.Contains(s, "spider") || strings.Contains(s, "crawler") {
		return "Bot"
	}
	// Browsers
	if strings.Contains(s, "edg/") || strings.Contains(s, "edge/") {
		return "Edge"
	}
	if strings.Contains(s, "chrome/") && !strings.Contains(s, "chromium") {
		return "Chrome"
	}
	if strings.Contains(s, "chromium") {
		return "Chromium"
	}
	if strings.Contains(s, "firefox/") {
		return "Firefox"
	}
	if strings.Contains(s, "safari/") {
		if strings.Contains(s, "mobile/") || strings.Contains(s, "iphone") || strings.Contains(s, "ipad") {
			return "Mobile Safari"
		}
		return "Safari"
	}
	if strings.Contains(s, "opera") || strings.Contains(s, "opr/") {
		return "Opera"
	}
	// Fallback: first token
	t := ua
	if i := strings.IndexAny(t, " /"); i > 0 {
		t = t[:i]
	}
	if len(t) > 32 {
		t = t[:32]
	}
	return t
}
