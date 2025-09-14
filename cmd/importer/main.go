package main

import (
    "database/sql"
    "flag"
    "fmt"
    "log"
    "os"

    "logtool/internal/db"
    imp "logtool/internal/importer"
    "logtool/internal/util"
)

func main() {
    var (
        dbPath   = flag.String("db", "./monitor.db", "SQLite DB path")
        access   = flag.String("access", "./access.log", "nginx access.log path")
        errorLog = flag.String("error", "./error.log", "nginx error.log path")
        ipPolicy = flag.String("ip-policy", "mask", "IP policy: store|mask|hash|drop")
        ipSalt   = flag.String("ip-salt", "", "Salt for hash policy (fallback to env IP_SALT)")
    )
    flag.Parse()

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

    // Import access.log
    if err := importAccess(sqldb, *access, imp.IPPolicy(*ipPolicy), h); err != nil {
        log.Fatalf("import access: %v", err)
    }
    // Import error.log
    if err := importError(sqldb, *errorLog); err != nil {
        log.Fatalf("import error: %v", err)
    }
    fmt.Println("Import completed.")
}

func importAccess(dbx *sql.DB, path string, policy imp.IPPolicy, h *util.Hasher) error {
    if _, err := os.Stat(path); err != nil {
        if os.IsNotExist(err) { return nil }
        return err
    }
    return imp.ImportAccess(dbx, "access", path, policy, h)
}

func importError(dbx *sql.DB, path string) error {
    if _, err := os.Stat(path); err != nil {
        if os.IsNotExist(err) { return nil }
        return err
    }
    return imp.ImportError(dbx, "error", path)
}

