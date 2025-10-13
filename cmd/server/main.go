package main

import (
	"encoding/base64"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"logtool/internal/db"
	"logtool/internal/webapi"
)

func main() {
	var (
		dbPath        = flag.String("db", "./monitor.db", "SQLite DB path")
		addr          = flag.String("addr", ":8080", "HTTP listen address")
		cors          = flag.Bool("cors", true, "Enable permissive CORS headers")
		defTZ         = flag.String("tz", "+00:00", "Default timezone for bucketing (e.g. -04:00)")
		staticDir     = flag.String("static", "", "Optional directory to serve at / (UI)")
		authUser      = flag.String("auth-user", "", "HTTP Basic username (optional)")
		authPass      = flag.String("auth-pass", "", "HTTP Basic password (optional)")
		bearerToken   = flag.String("auth-token", "", "Bearer token (optional; comma-separated for multiple)")
		bearerFile    = flag.String("auth-token-file", "", "Path to file with one bearer token per line (optional)")
		sessionSecret = flag.String("session-secret", "", "Secret for signing session cookies (base64 or raw string; optional)")
		sessionTTLStr = flag.String("session-ttl", "12h", "Session TTL (e.g., 12h, 24h)")
	)
	flag.Parse()

	// Allow env overrides for common flags when left at defaults
	if v := os.Getenv("LOGTOOL_DB"); v != "" && *dbPath == "./monitor.db" {
		*dbPath = v
	}
	if v := os.Getenv("LOGTOOL_ADDR"); v != "" && *addr == ":8080" {
		*addr = v
	}
	if v := os.Getenv("LOGTOOL_TZ"); v != "" && *defTZ == "+00:00" {
		*defTZ = v
	}
	if v := os.Getenv("LOGTOOL_STATIC"); v != "" && *staticDir == "" {
		*staticDir = v
	}

	sqldb, err := db.Open(*dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer sqldb.Close()

	// Allow env vars as fallback for creds
	if *authUser == "" {
		if v := os.Getenv("LOGTOOL_USER"); v != "" {
			*authUser = v
		}
	}
	if *authPass == "" {
		if v := os.Getenv("LOGTOOL_PASS"); v != "" {
			*authPass = v
		}
	}
	// Bearer tokens from flags/env/file
	tokens := parseTokens(*bearerToken)
	if v := os.Getenv("LOGTOOL_TOKEN"); v != "" {
		tokens = append(tokens, parseTokens(v)...)
	}
	if v := os.Getenv("LOGTOOL_TOKENS"); v != "" {
		tokens = append(tokens, parseTokens(v)...)
	}
	if *bearerFile != "" {
		if b, err := os.ReadFile(*bearerFile); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if s := strings.TrimSpace(line); s != "" && !strings.HasPrefix(s, "#") {
					tokens = append(tokens, s)
				}
			}
		}
	}

	api := webapi.New(sqldb, *defTZ, *cors, *authUser, *authPass, tokens)

	secureCookies := false
	if v := os.Getenv("LOGTOOL_SECURE_COOKIES"); v == "true" || v == "1" {
		secureCookies = true
	}
	if strings.HasPrefix(*addr, "https://") || secureCookies {
		api.SetSecureCookies(true)
		log.Printf("secure cookies enabled")
	}

	ghClientID := os.Getenv("GITHUB_CLIENT_ID")
	ghClientSecret := os.Getenv("GITHUB_CLIENT_SECRET")
	ghCallbackURL := os.Getenv("GITHUB_CALLBACK_URL")
	if ghClientID != "" && ghClientSecret != "" && ghCallbackURL != "" {
		api.SetGitHubOAuth(ghClientID, ghClientSecret, ghCallbackURL)
		log.Printf("GitHub OAuth enabled with callback URL: %s", ghCallbackURL)
	}

	if allowlist := parseTokens(os.Getenv("LOGTOOL_EMAIL_ALLOWLIST")); len(allowlist) > 0 {
		api.SetEmailAllowlist(allowlist)
		log.Printf("email allowlist enabled with %d entries", len(allowlist))
	}

	appleClientID := os.Getenv("APPLE_CLIENT_ID")
	appleTeamID := os.Getenv("APPLE_TEAM_ID")
	appleKeyID := os.Getenv("APPLE_KEY_ID")
	appleCallbackURL := os.Getenv("APPLE_CALLBACK_URL")
	applePrivateKey := os.Getenv("APPLE_PRIVATE_KEY")
	if applePrivateKey == "" {
		if keyFile := os.Getenv("APPLE_PRIVATE_KEY_FILE"); keyFile != "" {
			if b, err := os.ReadFile(keyFile); err == nil {
				applePrivateKey = string(b)
			}
		}
	}
	appleScopesStr := os.Getenv("APPLE_SCOPES")
	var appleScopes []string
	if appleScopesStr != "" {
		appleScopes = strings.Fields(appleScopesStr)
	}
	if appleClientID != "" && appleTeamID != "" && appleKeyID != "" && applePrivateKey != "" && appleCallbackURL != "" {
		if err := api.SetAppleOAuth(appleClientID, appleTeamID, appleKeyID, applePrivateKey, appleCallbackURL, appleScopes); err != nil {
			// don't log error details as they may contain key material
			log.Fatalf("Apple OAuth configuration failed: unable to parse private key or invalid parameters")
		}
		log.Printf("Apple OAuth enabled with callback URL: %s", appleCallbackURL)
	}

	if ghClientID != "" || appleClientID != "" {
		ttl, err := time.ParseDuration(*sessionTTLStr)
		if err != nil {
			ttl = 12 * time.Hour
		}
		if *sessionSecret == "" {
			if v := os.Getenv("LOGTOOL_SESSION_SECRET"); v != "" {
				*sessionSecret = v
			}
		}
		if v := os.Getenv("LOGTOOL_SESSION_TTL"); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				ttl = d
			}
		}
		sec := []byte(*sessionSecret)
		if s := strings.TrimSpace(*sessionSecret); s != "" {
			if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
				sec = b
			}
		}
		// validate minimum secret length for security
		if len(sec) < 32 {
			log.Fatalf("LOGTOOL_SESSION_SECRET must be at least 32 bytes (got %d bytes). Generate with: openssl rand -base64 32", len(sec))
		}
		api.SetSessionConfig(sec, ttl)
		log.Printf("session cookies enabled, ttl %s, secret length %d bytes", ttl, len(sec))
	}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	if *staticDir != "" {
		mux.Handle("/", api.Protect(http.FileServer(http.Dir(*staticDir))))
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("listening on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}

func parseTokens(csv string) []string {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}
