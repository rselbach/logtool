package importer

import (
    "bufio"
    "compress/gzip"
    "database/sql"
    "fmt"
    "io"
    "log"
    "os"
    "path/filepath"
    "sort"
    "strings"
    "time"
)

// ImportAccessFiles backfills one or more log files (plain or .gz) without touching import_state.
// files may include globs. Duplicates are ignored via unique index on raw_line.
func ImportAccessFiles(db *sql.DB, files []string, policy IPPolicy, h hasher) error {
    expanded, err := expandFiles(files)
    if err != nil { return err }
    if len(expanded) == 0 { return nil }
    // Sort by name for deterministic order (mtime could be used too)
    sort.Slice(expanded, func(i, j int) bool { return expanded[i].path < expanded[j].path })
    tx, err := db.Begin()
    if err != nil { return err }
    stmt, err := tx.Prepare(`INSERT OR IGNORE INTO request_events (ts_unix, ts, remote_addr, xff, method, path, protocol, status, bytes_sent, referer, user_agent, raw_line)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    if err != nil { _ = tx.Rollback(); return err }
    defer stmt.Close()
    var total, totalInserted int64
    log.Printf("backfill access: files=%d", len(expanded))
    for _, f := range expanded {
        rc, err := openMaybeGzip(f.path)
        if err != nil { _ = tx.Rollback(); return fmt.Errorf("open %s: %w", f.path, err) }
        r := bufio.NewReader(rc)
        var lines, inserted int64
        var firstISO, lastISO string
        for {
            s, err := r.ReadString('\n')
            if len(s) > 0 {
                line := strings.TrimRight(s, "\n")
                m := accessRe.FindStringSubmatch(line)
                if m == nil {
                    // Try to extract time
                    t := time.Now().UTC()
                    if mm := timeBracketRe.FindStringSubmatch(line); mm != nil {
                        if tt, err := time.Parse(accessTimeLayout, mm[1]); err == nil { t = tt.UTC() }
                    }
                    iso := t.Format(time.RFC3339)
                    res, err := stmt.Exec(t.Unix(), iso, nil, nil, nil, nil, nil, nil, nil, nil, nil, line)
                    if err != nil { rc.Close(); _ = tx.Rollback(); return err }
                    if ra, _ := res.RowsAffected(); ra > 0 { inserted += ra; totalInserted += ra }
                    lines++; total++
                    if firstISO == "" { firstISO = iso }
                    lastISO = iso
                } else {
                    remote := normalizeIP(m[1], policy, h)
                    tsStr := m[2]
                    method := m[3]
                    path := m[4]
                    proto := m[5]
                    status := atoiSafe(m[6])
                    bytes := atoiSafeDash(m[7])
                    referer := nullVal(toNull(m[8]))
                    ua := nullVal(toNull(m[9]))
                    xff := nullVal(toNull(normalizeXFF(m[10], policy, h)))
                    tt, err := time.Parse(accessTimeLayout, tsStr)
                    if err != nil { tt = time.Now().UTC() }
                    tsUnix := tt.UTC().Unix()
                    tsISO := tt.UTC().Format(time.RFC3339)
                    var remoteVal interface{} = remote
                    if remote == "" { remoteVal = nil }
                    res, err := stmt.Exec(tsUnix, tsISO, remoteVal, xff, method, path, proto, status, bytes, referer, ua, line)
                    if err != nil { rc.Close(); _ = tx.Rollback(); return err }
                    if ra, _ := res.RowsAffected(); ra > 0 { inserted += ra; totalInserted += ra }
                    lines++; total++
                    if firstISO == "" { firstISO = tsISO }
                    lastISO = tsISO
                }
            }
            if err != nil {
                if err == io.EOF { break }
                rc.Close(); _ = tx.Rollback(); return err
            }
        }
        rc.Close()
        log.Printf("backfill access: file=%s lines=%d inserted=%d ignored=%d ts=[%s..%s]", f.path, lines, inserted, lines-inserted, firstISO, lastISO)
    }
    log.Printf("backfill access: files=%d total_lines=%d total_inserted=%d", len(expanded), total, totalInserted)
    return tx.Commit()
}

func ImportErrorFiles(db *sql.DB, files []string) error {
    expanded, err := expandFiles(files)
    if err != nil { return err }
    if len(expanded) == 0 { return nil }
    sort.Slice(expanded, func(i, j int) bool { return expanded[i].path < expanded[j].path })
    tx, err := db.Begin()
    if err != nil { return err }
    stmt, err := tx.Prepare(`INSERT OR IGNORE INTO error_events (ts_unix, ts, level, pid, tid, message, raw_line) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    if err != nil { _ = tx.Rollback(); return err }
    defer stmt.Close()
    var total, totalInserted int64
    log.Printf("backfill error: files=%d", len(expanded))
    for _, f := range expanded {
        rc, err := openMaybeGzip(f.path)
        if err != nil { _ = tx.Rollback(); return fmt.Errorf("open %s: %w", f.path, err) }
        r := bufio.NewReader(rc)
        var lines, inserted int64
        var firstISO, lastISO string
        for {
            s, err := r.ReadString('\n')
            if len(s) > 0 {
                line := strings.TrimRight(s, "\n")
                m := errRe.FindStringSubmatch(line)
                if m == nil {
                    t := time.Now().UTC()
                    iso := t.Format(time.RFC3339)
                    res, err := stmt.Exec(t.Unix(), iso, nil, nil, nil, nil, line)
                    if err != nil { rc.Close(); _ = tx.Rollback(); return err }
                    if ra, _ := res.RowsAffected(); ra > 0 { inserted += ra; totalInserted += ra }
                    lines++; total++
                    if firstISO == "" { firstISO = iso }
                    lastISO = iso
                } else {
                    tt, err := time.Parse(errTimeLayout, m[1])
                    if err != nil { tt = time.Now().UTC() }
                    lvl := m[2]
                    pid := atoiSafe(m[3])
                    tid := atoiSafe(m[4])
                    msg := m[5]
                    iso := tt.UTC().Format(time.RFC3339)
                    res, err := stmt.Exec(tt.UTC().Unix(), iso, lvl, pid, tid, msg, line)
                    if err != nil { rc.Close(); _ = tx.Rollback(); return err }
                    if ra, _ := res.RowsAffected(); ra > 0 { inserted += ra; totalInserted += ra }
                    lines++; total++
                    if firstISO == "" { firstISO = iso }
                    lastISO = iso
                }
            }
            if err != nil {
                if err == io.EOF { break }
                rc.Close(); _ = tx.Rollback(); return err
            }
        }
        rc.Close()
        log.Printf("backfill error: file=%s lines=%d inserted=%d ignored=%d ts=[%s..%s]", f.path, lines, inserted, lines-inserted, firstISO, lastISO)
    }
    log.Printf("backfill error: files=%d total_lines=%d total_inserted=%d", len(expanded), total, totalInserted)
    return tx.Commit()
}

type fileItem struct{ path string }

func expandFiles(paths []string) ([]fileItem, error) {
    var out []fileItem
    for _, p := range paths {
        p = strings.TrimSpace(p)
        if p == "" { continue }
        // Expand globs
        matches, err := filepath.Glob(p)
        if err != nil { return nil, err }
        if matches != nil && len(matches) > 0 {
            for _, m := range matches { out = append(out, fileItem{path: m}) }
            continue
        }
        // Fallback: add as-is
        if _, err := os.Stat(p); err != nil {
            if os.IsNotExist(err) {
                continue // silently skip missing
            }
            return nil, err
        }
        out = append(out, fileItem{path: p})
    }
    return out, nil
}

func openMaybeGzip(path string) (io.ReadCloser, error) {
    f, err := os.Open(path)
    if err != nil { return nil, err }
    if strings.HasSuffix(strings.ToLower(path), ".gz") {
        zr, err := gzip.NewReader(f)
        if err != nil { f.Close(); return nil, err }
        return &gzipReadCloser{ReadCloser: zr, f: f}, nil
    }
    return f, nil
}

type gzipReadCloser struct { io.ReadCloser; f *os.File }
func (g *gzipReadCloser) Close() error { _ = g.ReadCloser.Close(); return g.f.Close() }

func atoiSafe(s string) int {
    n := 0
    for _, ch := range s { if ch < '0' || ch > '9' { return 0 } }
    for i := 0; i < len(s); i++ { n = n*10 + int(s[i]-'0') }
    return n
}

func atoiSafeDash(s string) int {
    if s == "-" || s == "" { return 0 }
    return atoiSafe(s)
}
