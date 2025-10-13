package webapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

const (
	sessionCookieVersion = "v2"
	oauthCookieTTL       = 5 * time.Minute
)

type Server struct {
	db             *sql.DB
	defaultTZ      string
	enableCORS     bool
	basicUser      string
	basicPass      string
	bearerTokens   map[string]struct{}
	sessionSecret  []byte
	sessionTTL     time.Duration
	cookieName     string
	oauthConfig    *oauth2.Config
	httpClient     *http.Client
	secureCookies  bool
	appleConfig    *appleOAuthConfig
	jwksCache      *jwksCache
	allowedEmails  map[string]struct{}
	allowedPattern []wildcardPattern
}

type appleOAuthConfig struct {
	clientID    string
	teamID      string
	keyID       string
	privateKey  *ecdsa.PrivateKey
	callbackURL string
	scopes      []string
}

type jwksCache struct {
	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey
	expires time.Time
	ttl     time.Duration
}

type sessionInfo struct {
	User  string
	Email string
}

type sessionCtxKey struct{}

type wildcardPattern struct {
	original string
	prefix   string
	suffix   string
	matchAll bool
}

func compileWildcard(pattern string) wildcardPattern {
	p := wildcardPattern{original: pattern}
	if pattern == "*" {
		p.matchAll = true
		return p
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		p.prefix = pattern
		return p
	}
	p.prefix = parts[0]
	p.suffix = parts[len(parts)-1]
	return p
}

func (w wildcardPattern) match(email string) bool {
	if w.matchAll {
		return true
	}
	if w.prefix != "" && !strings.HasPrefix(email, w.prefix) {
		return false
	}
	if w.suffix != "" && !strings.HasSuffix(email, w.suffix) {
		return false
	}
	if w.prefix == "" && w.suffix == "" {
		return false
	}
	return true
}

func New(db *sql.DB, defaultTZ string, enableCORS bool, basicUser, basicPass string, bearer []string) *Server {
	m := make(map[string]struct{})
	for _, t := range bearer {
		if tt := strings.TrimSpace(t); tt != "" {
			m[tt] = struct{}{}
		}
	}
	return &Server{
		db:           db,
		defaultTZ:    defaultTZ,
		enableCORS:   enableCORS,
		basicUser:    basicUser,
		basicPass:    basicPass,
		bearerTokens: m,
		cookieName:   "logtool_session",
		sessionTTL:   12 * time.Hour,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

// SetGitHubOAuth configures GitHub OAuth for interactive browser login.
// Requires clientID, clientSecret from GitHub OAuth App settings, and
// callbackURL matching the registered OAuth callback.
// Must call SetSessionConfig separately to enable session cookies.
func (s *Server) SetGitHubOAuth(clientID, clientSecret, callbackURL string) {
	if clientID == "" || clientSecret == "" || callbackURL == "" {
		return
	}
	s.oauthConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  callbackURL,
		Scopes:       []string{"user:email"},
		Endpoint:     github.Endpoint,
	}
}

// SetSecureCookies enables the Secure flag on cookies, requiring HTTPS.
// Should be enabled when TLS is terminated at a reverse proxy or when
// the server is accessed via HTTPS. Required for Apple OAuth.
func (s *Server) SetSecureCookies(secure bool) {
	s.secureCookies = secure
}

// SetEmailAllowlist configures email address filtering for OAuth login.
// Patterns supports exact matches and single wildcard patterns like
// "*@example.com" or "admin@*". Without an allowlist configured,
// all OAuth login attempts are denied.
func (s *Server) SetEmailAllowlist(emails []string) {
	if len(emails) == 0 {
		s.allowedEmails = nil
		s.allowedPattern = nil
		return
	}
	exact := make(map[string]struct{}, len(emails))
	patterns := make([]wildcardPattern, 0)
	for _, e := range emails {
		ee := strings.TrimSpace(strings.ToLower(e))
		if ee == "" {
			continue
		}
		if !strings.ContainsRune(ee, '*') {
			exact[ee] = struct{}{}
			continue
		}
		patterns = append(patterns, compileWildcard(ee))
	}
	if len(exact) == 0 {
		s.allowedEmails = nil
	} else {
		s.allowedEmails = exact
	}
	if len(patterns) == 0 {
		s.allowedPattern = nil
	} else {
		s.allowedPattern = patterns
	}
}

func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", s.wrap(s.handleHealth))
	mux.HandleFunc("/api/summary", s.wrap(s.handleSummary))
	mux.HandleFunc("/api/hosts", s.wrap(s.handleHosts))
	mux.HandleFunc("/api/timeseries/requests", s.wrap(s.handleTSRequests))
	mux.HandleFunc("/api/timeseries/errors", s.wrap(s.handleTSErrors))
	mux.HandleFunc("/api/top/paths", s.wrap(s.handleTopPaths))
	mux.HandleFunc("/api/top/referrers", s.wrap(s.handleTopReferrers))
	mux.HandleFunc("/api/top/ua", s.wrap(s.handleTopUA))
	mux.HandleFunc("/api/top/ua_families", s.wrap(s.handleTopUAFamilies))
	mux.HandleFunc("/api/top/hosts", s.wrap(s.handleTopHosts))
	mux.HandleFunc("/api/status", s.wrap(s.handleStatus))
	mux.HandleFunc("/api/requests", s.wrap(s.handleRequests))
	mux.HandleFunc("/api/errors", s.wrap(s.handleErrors))
	mux.HandleFunc("/api/debug/dbinfo", s.wrap(s.handleDebugDBInfo))
	mux.HandleFunc("/api/session", s.wrap(s.handleSessionInfo))
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/auth/github/login", s.handleGitHubLogin)
	mux.HandleFunc("/auth/github/callback", s.handleGitHubCallback)
	mux.HandleFunc("/auth/apple/login", s.handleAppleLogin)
	mux.HandleFunc("/auth/apple/callback", s.handleAppleCallback)
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
		var sess *sessionInfo
		if s.authEnabled() {
			var ok bool
			sess, ok = s.requireAuth(w, r, false)
			if !ok {
				return
			}
			if sess != nil {
				r = r.WithContext(context.WithValue(r.Context(), sessionCtxKey{}, sess))
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
// Protect wraps an http.Handler with authentication middleware.
// Requests must provide valid credentials via Bearer token, Basic auth,
// or a valid session cookie. Returns 401 Unauthorized for missing/invalid
// credentials.
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
		var sess *sessionInfo
		if s.authEnabled() {
			var ok bool
			sess, ok = s.requireAuth(w, r, true)
			if !ok {
				return
			}
			if sess != nil {
				r = r.WithContext(context.WithValue(r.Context(), sessionCtxKey{}, sess))
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
	return s.basicUser != "" || len(s.bearerTokens) > 0 || s.oauthConfig != nil || s.appleConfig != nil
}

func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request, redirect bool) (*sessionInfo, bool) {
	if len(s.bearerTokens) > 0 {
		if auth := r.Header.Get("Authorization"); auth != "" {
			if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
				tok := strings.TrimSpace(auth[len("Bearer "):])
				if _, ok := s.bearerTokens[tok]; ok {
					return nil, true
				}
			}
		}
	}
	if s.basicUser != "" {
		if s.requireBasicAuth(w, r) {
			if user, _, ok := r.BasicAuth(); ok {
				return &sessionInfo{User: "basic:" + user, Email: user}, true
			}
			return &sessionInfo{User: "basic:" + s.basicUser, Email: s.basicUser}, true
		}
	}
	if s.oauthConfig != nil || s.appleConfig != nil {
		if sess, ok := s.verifySessionCookie(r); ok {
			return sess, true
		}
		if redirect && r.Method == http.MethodGet {
			http.Redirect(w, r, "/login?next="+urlQueryEscape(r.URL.String()), http.StatusFound)
			return nil, false
		}
	}
	if len(s.bearerTokens) > 0 {
		w.Header().Set("WWW-Authenticate", "Bearer realm=\"Logtool\"")
	} else if s.basicUser != "" {
		w.Header().Set("WWW-Authenticate", "Basic realm=\"Logtool\"")
	}
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	return nil, false
}

// SetSessionConfig enables session cookie authentication with HMAC signing.
// The secret must be at least 32 bytes for security. TTL determines how
// long session cookies remain valid. Required for OAuth (GitHub/Apple) login.
// If secret is empty, generates a random 32-byte secret (sessions won't
// survive server restart).
func (s *Server) SetSessionConfig(secret []byte, ttl time.Duration) {
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
	if s.oauthConfig == nil && s.appleConfig == nil {
		http.Error(w, "login not configured", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	next := r.URL.Query().Get("next")
	io.WriteString(w, oauthLoginPage(next, s.oauthConfig != nil, s.appleConfig != nil))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, user, email string, ttl time.Duration) {
	exp := time.Now().Add(ttl).Unix()
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	userB64 := base64.RawURLEncoding.EncodeToString([]byte(user))
	emailB64 := base64.RawURLEncoding.EncodeToString([]byte(email))
	payload := fmt.Sprintf("v2|%d|%s|%s|%s", exp, userB64, emailB64, base64.RawURLEncoding.EncodeToString(nonce))
	mac := hmac.New(sha256.New, s.sessionSecret)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	val := base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + sig))
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

func (s *Server) verifySessionCookie(r *http.Request) (*sessionInfo, bool) {
	c, err := r.Cookie(s.cookieName)
	if err != nil || c.Value == "" {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil, false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) < 5 {
		return nil, false
	}
	sig := parts[len(parts)-1]
	payloadParts := parts[:len(parts)-1]
	payload := strings.Join(payloadParts, "|")
	if len(payloadParts) < 4 {
		return nil, false
	}
	expStr := payloadParts[1]
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return nil, false
	}
	mac := hmac.New(sha256.New, s.sessionSecret)
	mac.Write([]byte(payload))
	expected := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return nil, false
	}
	if !hmac.Equal(expected, got) {
		return nil, false
	}
	version := payloadParts[0]
	switch version {
	case "v1":
		if len(payloadParts) != 4 {
			return nil, false
		}
		user := payloadParts[2]
		return &sessionInfo{User: user}, true
	case "v2":
		if len(payloadParts) != 5 {
			return nil, false
		}
		userEnc := payloadParts[2]
		emailEnc := payloadParts[3]
		userBytes, err := base64.RawURLEncoding.DecodeString(userEnc)
		if err != nil {
			return nil, false
		}
		emailBytes, err := base64.RawURLEncoding.DecodeString(emailEnc)
		if err != nil {
			return nil, false
		}
		return &sessionInfo{User: string(userBytes), Email: string(emailBytes)}, true
	default:
		return nil, false
	}
}

func sessionFromContext(ctx context.Context) (*sessionInfo, bool) {
	info, ok := ctx.Value(sessionCtxKey{}).(*sessionInfo)
	if !ok || info == nil {
		return nil, false
	}
	return info, true
}

func (s *Server) handleSessionInfo(w http.ResponseWriter, r *http.Request) error {
	info, ok := sessionFromContext(r.Context())
	resp := struct {
		User      string `json:"user"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}{}
	if ok {
		resp.User = info.User
		resp.Email = info.Email
		if email := strings.TrimSpace(strings.ToLower(info.Email)); email != "" {
			sum := md5.Sum([]byte(email))
			resp.AvatarURL = fmt.Sprintf("https://www.gravatar.com/avatar/%x?s=64&d=identicon", sum)
		}
	}
	return writeJSON(w, resp)
}

func (s *Server) emailAllowed(email string) bool {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return false
	}
	if len(s.allowedEmails) > 0 {
		if _, ok := s.allowedEmails[email]; ok {
			return true
		}
	}
	for _, p := range s.allowedPattern {
		if p.match(email) {
			return true
		}
	}
	return false
}

func urlQueryEscape(s string) string {
	// Minimal escape for query component (no external deps)
	return strings.ReplaceAll(strings.ReplaceAll(s, " ", "+"), "\n", "")
}

func oauthLoginPage(next string, hasGitHub, hasApple bool) string {
	if next == "" {
		next = "/"
	}
	html := "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Logtool Login</title>" +
		"<style>:root{--bg:#0f1115;--panel:#171a21;--muted:#9aa3b2;--fg:#e8ecf1;--accent:#5aa6ff;--apple:#000}html,body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui;-webkit-font-smoothing:antialiased} .wrap{display:flex;min-height:100vh;align-items:center;justify-content:center;padding:24px} .card{background:var(--panel);border:1px solid #242a35;border-radius:12px;padding:20px;max-width:360px;width:100%} h1{margin:0 0 12px 0;font-size:18px} a.button{margin-top:14px;width:100%;padding:10px 12px;border-radius:8px;border:1px solid #2a2f3a;background:var(--accent);color:#0b1018;cursor:pointer;font-weight:600;text-decoration:none;display:block;text-align:center} a.button.apple{background:var(--apple);color:#fff} .muted{color:var(--muted);font-size:12px;margin-top:8px;text-align:center}</style></head>" +
		"<body><div class=wrap><div class=card>" +
		"<h1>Logtool — Sign in</h1>"
	if hasGitHub {
		html += "<a href=\"/auth/github/login?next=" + htmlEscape(urlQueryEscape(next)) + "\" class=button>Sign in with GitHub</a>"
	}
	if hasApple {
		html += "<a href=\"/auth/apple/login?next=" + htmlEscape(urlQueryEscape(next)) + "\" class=\"button apple\">Sign in with Apple</a>"
	}
	html += "<div class=muted>Access restricted</div>" +
		"</div></div></body></html>"
	return html
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;")
	return r.Replace(s)
}

func generatePKCEPair() (verifier, challenge string) {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return
}

func generateState() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

func (s *Server) setOAuthCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	s.setOAuthCookieWithSameSite(w, name, value, ttl, http.SameSiteLaxMode)
}

func (s *Server) setOAuthCookieWithSameSite(w http.ResponseWriter, name, value string, ttl time.Duration, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: sameSite,
		MaxAge:   int(ttl.Seconds()),
	})
}

func (s *Server) getOAuthCookie(r *http.Request, name string) (string, bool) {
	c, err := r.Cookie(name)
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

func (s *Server) clearOAuthCookies(w http.ResponseWriter) {
	s.clearOAuthCookie(w, "oauth_state")
	s.clearOAuthCookie(w, "oauth_verifier")
	s.clearOAuthCookie(w, "oauth_nonce")
	s.clearOAuthCookie(w, "oauth_next")
}

func (s *Server) clearOAuthCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies,
		MaxAge:   -1,
	})
}

func (s *Server) handleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	if s.oauthConfig == nil {
		http.Error(w, "GitHub OAuth not configured", http.StatusNotFound)
		return
	}
	next := r.URL.Query().Get("next")
	if next == "" {
		next = "/"
	}
	state := generateState()
	verifier, challenge := generatePKCEPair()
	s.setOAuthCookie(w, "oauth_state", state, oauthCookieTTL)
	s.setOAuthCookie(w, "oauth_verifier", verifier, oauthCookieTTL)
	s.setOAuthCookie(w, "oauth_next", next, oauthCookieTTL)
	authURL := s.oauthConfig.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	log.Printf("github_login_started: redirecting to GitHub")
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	if s.oauthConfig == nil {
		http.Error(w, "GitHub OAuth not configured", http.StatusNotFound)
		return
	}
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if code == "" {
		log.Printf("github_callback_error: missing code")
		s.clearOAuthCookies(w)
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}
	expectedState, ok := s.getOAuthCookie(r, "oauth_state")
	if !ok || state != expectedState {
		log.Printf("github_callback_error: state mismatch")
		s.clearOAuthCookies(w)
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	verifier, ok := s.getOAuthCookie(r, "oauth_verifier")
	if !ok {
		log.Printf("github_callback_error: missing verifier")
		s.clearOAuthCookies(w)
		http.Error(w, "missing verifier", http.StatusBadRequest)
		return
	}
	next, _ := s.getOAuthCookie(r, "oauth_next")
	if next == "" {
		next = "/"
	}
	s.clearOAuthCookie(w, "oauth_state")
	s.clearOAuthCookie(w, "oauth_verifier")
	s.clearOAuthCookie(w, "oauth_next")
	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, s.httpClient)
	tok, err := s.oauthConfig.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		log.Printf("github_token_exchange_error: %v", err)
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		log.Printf("github_user_fetch_error: %v", err)
		http.Error(w, "failed to create user request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("github_user_fetch_error: %v", err)
		http.Error(w, "failed to fetch user", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("github_user_fetch_error: status=%d", resp.StatusCode)
		http.Error(w, "failed to fetch user", http.StatusInternalServerError)
		return
	}
	var user struct {
		Login string `json:"login"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		log.Printf("github_user_parse_error: %v", err)
		http.Error(w, "failed to parse user", http.StatusInternalServerError)
		return
	}
	if user.Login == "" {
		log.Printf("github_user_parse_error: empty login")
		http.Error(w, "empty login", http.StatusInternalServerError)
		return
	}
	email := strings.TrimSpace(user.Email)
	if email == "" {
		emailReq, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
		if err == nil {
			emailReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
			if emailResp, err := s.httpClient.Do(emailReq); err == nil {
				defer emailResp.Body.Close()
				if emailResp.StatusCode == http.StatusOK {
					var entries []struct {
						Email    string `json:"email"`
						Primary  bool   `json:"primary"`
						Verified bool   `json:"verified"`
					}
					if err := json.NewDecoder(emailResp.Body).Decode(&entries); err == nil {
						for _, entry := range entries {
							if entry.Primary && entry.Verified {
								email = strings.TrimSpace(entry.Email)
								break
							}
						}
						if email == "" {
							for _, entry := range entries {
								if entry.Verified {
									email = strings.TrimSpace(entry.Email)
									break
								}
							}
						}
					}
				}
			}
		}
	}
	if !s.emailAllowed(email) {
		log.Printf("github_login_blocked: user=%s email=%q not in allowlist", user.Login, email)
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	ghUser := "gh:" + user.Login
	s.setSessionCookie(w, ghUser, email, s.sessionTTL)
	log.Printf("github_login_success: user=%s", user.Login)
	http.Redirect(w, r, next, http.StatusFound)
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

func (s *Server) buildWhereClause(r *http.Request, from, to int64) (string, []interface{}) {
	where := "ts_unix BETWEEN ? AND ?"
	args := []interface{}{from, to}
	if host := strings.TrimSpace(r.URL.Query().Get("host")); host != "" {
		if host == "Unknown" {
			where += " AND (host IS NULL OR host = '')"
		} else {
			where += " AND host = ?"
			args = append(args, host)
		}
	}
	return where, args
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) error {
	from, to, err := s.parseRange(r)
	if err != nil {
		return err
	}
	rows, err := s.db.Query(`SELECT DISTINCT COALESCE(NULLIF(host, ''), 'Unknown') AS host FROM request_events WHERE ts_unix BETWEEN ? AND ? ORDER BY host`, from, to)
	if err != nil {
		return err
	}
	defer rows.Close()
	var hosts []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return err
		}
		hosts = append(hosts, h)
	}
	return writeJSON(w, hosts)
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
	where, args := s.buildWhereClause(r, from, to)
	// Requests count
	row := s.db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM request_events WHERE %s`, where), args...)
	_ = row.Scan(&sum.Requests)
	// Unique (approx depends on policy)
	row = s.db.QueryRow(fmt.Sprintf(`SELECT COUNT(DISTINCT COALESCE(remote_addr, '')) FROM request_events WHERE %s`, where), args...)
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
	where, whereArgs := s.buildWhereClause(r, from, to)
	query := fmt.Sprintf(`SELECT ((ts_unix + ?)/?)*? AS b, COUNT(*) FROM request_events WHERE %s GROUP BY b ORDER BY b`, where)
	args := append([]interface{}{tzOff, bucket, bucket}, whereArgs...)
	rows, err := s.db.Query(query, args...)
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
	where, baseArgs := s.buildWhereClause(r, from, to)
	where += " AND path IS NOT NULL AND path != ''"
	args := append(append([]interface{}{}, baseArgs...), limit)
	rows, err := s.db.Query(fmt.Sprintf(`SELECT path, COUNT(*) as c FROM request_events WHERE %s GROUP BY path ORDER BY c DESC LIMIT ?`, where), args...)
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
	where, baseArgs := s.buildWhereClause(r, from, to)
	if includeEmpty {
		args := append(append([]interface{}{}, baseArgs...), limit)
		rows, err = s.db.Query(fmt.Sprintf(`SELECT COALESCE(referer, '') AS ref, COUNT(*) as c FROM request_events WHERE %s GROUP BY ref ORDER BY c DESC LIMIT ?`, where), args...)
	} else {
		whereNonEmpty := where + " AND referer IS NOT NULL AND referer != ''"
		args := append(append([]interface{}{}, baseArgs...), limit)
		rows, err = s.db.Query(fmt.Sprintf(`SELECT referer AS ref, COUNT(*) as c FROM request_events WHERE %s GROUP BY ref ORDER BY c DESC LIMIT ?`, whereNonEmpty), args...)
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
	where, args := s.buildWhereClause(r, from, to)
	rows, err := s.db.Query(fmt.Sprintf(`SELECT COALESCE(status, 0) AS status, COUNT(*) FROM request_events WHERE %s GROUP BY COALESCE(status, 0) ORDER BY status`, where), args...)
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
	where, baseArgs := s.buildWhereClause(r, from, to)
	if includeEmpty {
		args := append(append([]interface{}{}, baseArgs...), limit)
		rows, err = s.db.Query(fmt.Sprintf(`SELECT COALESCE(user_agent, '') AS ua, COUNT(*) as c FROM request_events WHERE %s GROUP BY ua ORDER BY c DESC LIMIT ?`, where), args...)
	} else {
		whereNonEmpty := where + " AND user_agent IS NOT NULL AND user_agent != ''"
		args := append(append([]interface{}{}, baseArgs...), limit)
		rows, err = s.db.Query(fmt.Sprintf(`SELECT user_agent AS ua, COUNT(*) as c FROM request_events WHERE %s GROUP BY ua ORDER BY c DESC LIMIT ?`, whereNonEmpty), args...)
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
	where, baseArgs := s.buildWhereClause(r, from, to)
	where += " AND user_agent IS NOT NULL AND user_agent != ''"
	rows, err := s.db.Query(fmt.Sprintf(`SELECT user_agent FROM request_events WHERE %s`, where), baseArgs...)
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

// handleTopHosts returns the top hosts by request count.
func (s *Server) handleTopHosts(w http.ResponseWriter, r *http.Request) error {
	from, to, err := s.parseRange(r)
	if err != nil {
		return err
	}
	limit := clampInt(r.URL.Query().Get("limit"), 20, 1, 200)
	where, baseArgs := s.buildWhereClause(r, from, to)
	// group by host, treating NULL/empty as 'Unknown'
	query := fmt.Sprintf(`SELECT COALESCE(NULLIF(host, ''), 'Unknown') AS host, COUNT(*) as c FROM request_events WHERE %s GROUP BY host ORDER BY c DESC LIMIT ?`, where)
	args := append(append([]interface{}{}, baseArgs...), limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	type Row struct {
		Host  string `json:"host"`
		Count int64  `json:"count"`
	}
	var out []Row
	for rows.Next() {
		var host string
		var c int64
		if err := rows.Scan(&host, &c); err != nil {
			return err
		}
		out = append(out, Row{Host: host, Count: c})
	}
	return writeJSON(w, out)
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

// SetAppleOAuth configures Sign in with Apple for interactive browser login.
// Requires clientID (Services ID), teamID, keyID from Apple Developer portal,
// privateKeyPEM (ES256 .p8 key file contents), and callbackURL matching
// the registered callback. Optional scopes typically include "email" and "name".
// Returns error if private key parsing fails.
// Requires SetSecureCookies(true) due to SameSite=None requirement.
func (s *Server) SetAppleOAuth(clientID, teamID, keyID, privateKeyPEM, callbackURL string, scopes []string) error {
	if clientID == "" || teamID == "" || keyID == "" || privateKeyPEM == "" || callbackURL == "" {
		return nil
	}
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key is not ECDSA")
	}
	if len(scopes) == 0 {
		scopes = []string{"email", "name"}
	}
	s.appleConfig = &appleOAuthConfig{
		clientID:    clientID,
		teamID:      teamID,
		keyID:       keyID,
		privateKey:  ecKey,
		callbackURL: callbackURL,
		scopes:      scopes,
	}
	s.jwksCache = &jwksCache{
		keys: make(map[string]*rsa.PublicKey),
		ttl:  24 * time.Hour,
	}
	return nil
}

func (s *Server) generateAppleClientSecret() (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    s.appleConfig.teamID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		Audience:  jwt.ClaimStrings{"https://appleid.apple.com"},
		Subject:   s.appleConfig.clientID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = s.appleConfig.keyID
	return token.SignedString(s.appleConfig.privateKey)
}

func (jc *jwksCache) fetchAppleJWKS(httpClient *http.Client) error {
	// fast path: check expiration without write lock
	jc.mu.RLock()
	if time.Now().Before(jc.expires) {
		jc.mu.RUnlock()
		return nil
	}
	jc.mu.RUnlock()

	// slow path: acquire write lock and check again
	jc.mu.Lock()
	defer jc.mu.Unlock()

	// double-check after acquiring write lock (another goroutine may have updated)
	if time.Now().Before(jc.expires) {
		return nil
	}

	req, err := http.NewRequest("GET", "https://appleid.apple.com/auth/keys", nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch failed: status=%d", resp.StatusCode)
	}
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return err
	}
	newKeys := make(map[string]*rsa.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || k.Use != "sig" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		n := new(big.Int).SetBytes(nBytes)
		e := int(new(big.Int).SetBytes(eBytes).Int64())
		newKeys[k.Kid] = &rsa.PublicKey{N: n, E: e}
	}
	jc.keys = newKeys
	jc.expires = time.Now().Add(jc.ttl)
	return nil
}

func (jc *jwksCache) getKey(kid string) (*rsa.PublicKey, bool) {
	jc.mu.RLock()
	defer jc.mu.RUnlock()
	k, ok := jc.keys[kid]
	return k, ok
}

func (s *Server) verifyAppleIDToken(idToken, nonce string) (string, string, error) {
	if err := s.jwksCache.fetchAppleJWKS(s.httpClient); err != nil {
		return "", "", fmt.Errorf("jwks fetch: %w", err)
	}
	token, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid")
		}
		key, ok := s.jwksCache.getKey(kid)
		if !ok {
			return nil, fmt.Errorf("unknown kid: %s", kid)
		}
		return key, nil
	})
	if err != nil {
		return "", "", err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", "", fmt.Errorf("invalid token")
	}

	// explicitly validate expiration claim
	exp, ok := claims["exp"].(float64)
	if !ok {
		return "", "", fmt.Errorf("exp claim missing or invalid")
	}
	if time.Now().Unix() > int64(exp) {
		return "", "", fmt.Errorf("token expired")
	}

	if claims["iss"] != "https://appleid.apple.com" {
		return "", "", fmt.Errorf("invalid issuer")
	}
	audValid := false
	switch aud := claims["aud"].(type) {
	case string:
		audValid = aud == s.appleConfig.clientID
	case []interface{}:
		for _, a := range aud {
			if str, ok := a.(string); ok && str == s.appleConfig.clientID {
				audValid = true
				break
			}
		}
	}
	if !audValid {
		return "", "", fmt.Errorf("invalid audience")
	}
	// nonce is required for Apple OAuth replay protection
	if nonce == "" {
		return "", "", fmt.Errorf("missing nonce cookie")
	}
	claimNonce, ok := claims["nonce"].(string)
	if !ok {
		return "", "", fmt.Errorf("nonce claim missing or invalid type")
	}
	if claimNonce != nonce {
		return "", "", fmt.Errorf("nonce mismatch")
	}
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return "", "", fmt.Errorf("missing sub")
	}
	email, _ := claims["email"].(string)
	return sub, strings.TrimSpace(email), nil
}

func (s *Server) handleAppleLogin(w http.ResponseWriter, r *http.Request) {
	if s.appleConfig == nil {
		http.Error(w, "Apple OAuth not configured", http.StatusNotFound)
		return
	}

	// Apple OAuth requires SameSite=None cookies, which require Secure flag (HTTPS)
	if !s.secureCookies {
		log.Printf("apple_login_error: Apple OAuth requires HTTPS (LOGTOOL_SECURE_COOKIES=true)")
		http.Error(w, "Apple OAuth requires HTTPS", http.StatusInternalServerError)
		return
	}

	next := r.URL.Query().Get("next")
	if next == "" {
		next = "/"
	}
	state := generateState()
	verifier, challenge := generatePKCEPair()
	nonce := generateState()
	s.setOAuthCookieWithSameSite(w, "oauth_state", state, oauthCookieTTL, http.SameSiteNoneMode)
	s.setOAuthCookieWithSameSite(w, "oauth_verifier", verifier, oauthCookieTTL, http.SameSiteNoneMode)
	s.setOAuthCookieWithSameSite(w, "oauth_next", next, oauthCookieTTL, http.SameSiteNoneMode)
	s.setOAuthCookieWithSameSite(w, "oauth_nonce", nonce, oauthCookieTTL, http.SameSiteNoneMode)
	params := fmt.Sprintf("response_type=code&response_mode=form_post&client_id=%s&redirect_uri=%s&state=%s&scope=%s&code_challenge=%s&code_challenge_method=S256&nonce=%s",
		urlQueryEscape(s.appleConfig.clientID),
		urlQueryEscape(s.appleConfig.callbackURL),
		urlQueryEscape(state),
		urlQueryEscape(strings.Join(s.appleConfig.scopes, " ")),
		urlQueryEscape(challenge),
		urlQueryEscape(nonce))
	authURL := "https://appleid.apple.com/auth/authorize?" + params
	log.Printf("apple_login_started: redirecting to Apple")
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) handleAppleCallback(w http.ResponseWriter, r *http.Request) {
	if s.appleConfig == nil {
		http.Error(w, "Apple OAuth not configured", http.StatusNotFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		log.Printf("apple_callback_error: failed to parse form: %v", err)
		s.clearOAuthCookies(w)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	state := r.FormValue("state")
	code := r.FormValue("code")
	if code == "" {
		log.Printf("apple_callback_error: missing code")
		s.clearOAuthCookies(w)
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}
	expectedState, ok := s.getOAuthCookie(r, "oauth_state")
	if !ok || state != expectedState {
		log.Printf("apple_callback_error: state mismatch (received=%q expected=%q cookie_found=%v)", state, expectedState, ok)
		s.clearOAuthCookies(w)
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	verifier, ok := s.getOAuthCookie(r, "oauth_verifier")
	if !ok {
		log.Printf("apple_callback_error: missing verifier")
		s.clearOAuthCookies(w)
		http.Error(w, "missing verifier", http.StatusBadRequest)
		return
	}
	nonce, ok := s.getOAuthCookie(r, "oauth_nonce")
	if !ok {
		log.Printf("apple_callback_error: missing nonce cookie")
		s.clearOAuthCookies(w)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	next, _ := s.getOAuthCookie(r, "oauth_next")
	if next == "" {
		next = "/"
	}
	s.clearOAuthCookie(w, "oauth_state")
	s.clearOAuthCookie(w, "oauth_verifier")
	s.clearOAuthCookie(w, "oauth_next")
	s.clearOAuthCookie(w, "oauth_nonce")
	clientSecret, err := s.generateAppleClientSecret()
	if err != nil {
		log.Printf("apple_client_secret_error: %v", err)
		http.Error(w, "client secret generation failed", http.StatusInternalServerError)
		return
	}
	data := fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&client_secret=%s&code_verifier=%s",
		urlQueryEscape(code),
		urlQueryEscape(s.appleConfig.callbackURL),
		urlQueryEscape(s.appleConfig.clientID),
		urlQueryEscape(clientSecret),
		urlQueryEscape(verifier))
	req, err := http.NewRequestWithContext(r.Context(), "POST", "https://appleid.apple.com/auth/token", strings.NewReader(data))
	if err != nil {
		log.Printf("apple_token_exchange_error: %v", err)
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("apple_token_exchange_error: %v", err)
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("apple_token_exchange_error: status=%d", resp.StatusCode)
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}
	var tokenResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		log.Printf("apple_token_parse_error: %v", err)
		http.Error(w, "failed to parse token response", http.StatusInternalServerError)
		return
	}
	sub, email, err := s.verifyAppleIDToken(tokenResp.IDToken, nonce)
	if err != nil {
		log.Printf("apple_idtoken_verify_error: %v", err)
		http.Error(w, "id_token verification failed", http.StatusInternalServerError)
		return
	}
	if !s.emailAllowed(email) {
		log.Printf("apple_login_blocked: sub=%s email=%q not in allowlist", sub, email)
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	appleUser := "ap:" + sub
	s.setSessionCookie(w, appleUser, email, s.sessionTTL)
	log.Printf("apple_login_success: user=%s", sub)
	http.Redirect(w, r, next, http.StatusFound)
}
