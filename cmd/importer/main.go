package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"logtool/internal/db"
	imp "logtool/internal/importer"
	"logtool/internal/util"
)

func main() {
	var (
		dbPath         = flag.String("db", "./monitor.db", "SQLite DB path")
		access         = flag.String("access", "./access.log", "access log path")
		errorLog       = flag.String("error", "./error.log", "error log path")
		logFormat      = flag.String("format", string(imp.FormatCaddy), "Log format: caddy|nginx")
		ipPolicy       = flag.String("ip-policy", "mask", "IP policy: store|mask|hash|drop")
		ipSalt         = flag.String("ip-salt", "", "Salt for hash policy (fallback to env IP_SALT)")
		backfillAccess = flag.String("backfill-access", "", "Comma-separated list or glob(s) for historical access logs (.gz supported)")
		backfillError  = flag.String("backfill-error", "", "Comma-separated list or glob(s) for historical error logs (.gz supported)")
		backfillOnly   = flag.Bool("backfill-only", false, "Only run backfill; skip incremental import")
	)
	flag.Parse()

	// Env overrides (used when flags unspecified, e.g., under systemd)
	if v := os.Getenv("LOGTOOL_DB"); v != "" && *dbPath == "./monitor.db" {
		*dbPath = v
	}
	if v := os.Getenv("LOGTOOL_ACCESS"); v != "" && *access == "./access.log" {
		*access = v
	}
	if v := os.Getenv("LOGTOOL_ERROR"); v != "" && *errorLog == "./error.log" {
		*errorLog = v
	}
	if v := os.Getenv("LOGTOOL_FORMAT"); v != "" && *logFormat == string(imp.FormatCaddy) {
		*logFormat = v
	}

	format, err := imp.ParseAccessFormat(*logFormat)
	if err != nil {
		log.Fatalf("parse format: %v", err)
	}

	log.Printf("LOGTOOL_ACCESS: %s", *access)

	// Open DB
	sqldb, err := db.Open(*dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer sqldb.Close()

	// Prepare hasher if needed
	var h *util.Hasher
	if *ipPolicy == string(imp.IPHash) {
		salt := *ipSalt
		if salt == "" {
			salt = os.Getenv("IP_SALT")
		}
		h = util.NewHasher(salt)
	}

	// Backfill first (optional)
	if *backfillAccess != "" {
		paths := splitCSV(*backfillAccess)
		if err := imp.ImportAccessFiles(sqldb, paths, format, imp.IPPolicy(*ipPolicy), h); err != nil {
			log.Fatalf("backfill access: %v", err)
		}
	}
	if *backfillError != "" {
		paths := splitCSV(*backfillError)
		if err := imp.ImportErrorFiles(sqldb, paths, format); err != nil {
			log.Fatalf("backfill error: %v", err)
		}
	}
	if !*backfillOnly {
		// Import access.log incrementally
		if err := importAccess(sqldb, *access, format, imp.IPPolicy(*ipPolicy), h); err != nil {
			log.Fatalf("import access: %v", err)
		}
		// Import error.log incrementally
		if err := importError(sqldb, *errorLog, format); err != nil {
			log.Fatalf("import error: %v", err)
		}
	}
	fmt.Println("Import completed.")
}

func importAccess(dbx *sql.DB, path string, format imp.AccessFormat, policy imp.IPPolicy, h *util.Hasher) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return imp.ImportAccess(dbx, "access", path, format, policy, h)
}

func importError(dbx *sql.DB, path string, format imp.AccessFormat) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return imp.ImportError(dbx, "error", path, format)
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if pp := strings.TrimSpace(p); pp != "" {
			out = append(out, pp)
		}
	}
	return out
}
