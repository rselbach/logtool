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
        dbPath = flag.String("db", "./monitor.db", "SQLite DB path")
        addr   = flag.String("addr", ":8080", "HTTP listen address")
        cors   = flag.Bool("cors", true, "Enable permissive CORS headers")
        defTZ  = flag.String("tz", "+00:00", "Default timezone for bucketing (e.g. -04:00)")
        staticDir = flag.String("static", "", "Optional directory to serve at / (UI)")
        authUser = flag.String("auth-user", "", "HTTP Basic username (optional)")
        authPass = flag.String("auth-pass", "", "HTTP Basic password (optional)")
        bearerToken = flag.String("auth-token", "", "Bearer token (optional; comma-separated for multiple)")
        bearerFile  = flag.String("auth-token-file", "", "Path to file with one bearer token per line (optional)")
        loginUser = flag.String("login-user", "", "Login username for form-based auth (optional)")
        loginHash = flag.String("login-hash", "", "Bcrypt password hash for form-based auth (optional)")
        sessionSecret = flag.String("session-secret", "", "Secret for signing session cookies (base64 or raw string; optional)")
        sessionTTLStr = flag.String("session-ttl", "12h", "Session TTL (e.g., 12h, 24h)")
    )
    flag.Parse()

    // Allow env overrides for common flags when left at defaults
    if v := os.Getenv("LOGTOOL_DB"); v != "" && *dbPath == "./monitor.db" { *dbPath = v }
    if v := os.Getenv("LOGTOOL_ADDR"); v != "" && *addr == ":8080" { *addr = v }
    if v := os.Getenv("LOGTOOL_TZ"); v != "" && *defTZ == "+00:00" { *defTZ = v }
    if v := os.Getenv("LOGTOOL_STATIC"); v != "" && *staticDir == "" { *staticDir = v }

    sqldb, err := db.Open(*dbPath)
    if err != nil { log.Fatalf("open db: %v", err) }
    defer sqldb.Close()

    // Allow env vars as fallback for creds
    if *authUser == "" { if v := os.Getenv("LOGTOOL_USER"); v != "" { *authUser = v } }
    if *authPass == "" { if v := os.Getenv("LOGTOOL_PASS"); v != "" { *authPass = v } }
    // Bearer tokens from flags/env/file
    tokens := parseTokens(*bearerToken)
    if v := os.Getenv("LOGTOOL_TOKEN"); v != "" { tokens = append(tokens, parseTokens(v)...) }
    if v := os.Getenv("LOGTOOL_TOKENS"); v != "" { tokens = append(tokens, parseTokens(v)...) }
    if *bearerFile != "" {
        if b, err := os.ReadFile(*bearerFile); err == nil {
            for _, line := range strings.Split(string(b), "\n") {
                if s := strings.TrimSpace(line); s != "" && !strings.HasPrefix(s, "#") { tokens = append(tokens, s) }
            }
        }
    }

    api := webapi.New(sqldb, *defTZ, *cors, *authUser, *authPass, tokens)
    // Form-based login config via flags/env
    if *loginUser == "" { if v := os.Getenv("LOGTOOL_LOGIN_USER"); v != "" { *loginUser = v } }
    if *loginHash == "" { if v := os.Getenv("LOGTOOL_LOGIN_HASH"); v != "" { *loginHash = v } }
    if *sessionSecret == "" { if v := os.Getenv("LOGTOOL_SESSION_SECRET"); v != "" { *sessionSecret = v } }
    if v := os.Getenv("LOGTOOL_SESSION_TTL"); v != "" { *sessionTTLStr = v }
    if *loginUser != "" && *loginHash != "" {
        ttl, err := time.ParseDuration(*sessionTTLStr)
        if err != nil { ttl = 12 * time.Hour }
        sec := []byte(*sessionSecret)
        if s := strings.TrimSpace(*sessionSecret); s != "" {
            if b, err := base64.RawURLEncoding.DecodeString(s); err == nil { sec = b }
        }
        api.SetLogin(*loginUser, *loginHash, sec, ttl)
        log.Printf("login enabled for user %s, session ttl %s", *loginUser, ttl)
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
    if csv == "" { return nil }
    parts := strings.Split(csv, ",")
    out := make([]string, 0, len(parts))
    for _, p := range parts {
        if s := strings.TrimSpace(p); s != "" { out = append(out, s) }
    }
    return out
}
