package importer

import (
    "database/sql"
    "log"
    "net"
    "regexp"
    "strconv"
    "strings"
    "time"
)

// Access log is assumed to be Combined + XFF at the end:
// $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for"
var accessRe = regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\"]*?)\s+(\S+)"\s+(\d{3})\s+(\d+|-)\s+"([^"]*)"\s+"([^"]*)"\s+"([^"]*)"$`)

// AccessRe exposes the compiled regex (for debug tools/tests only).
func AccessRe() *regexp.Regexp { return accessRe }

const accessTimeLayout = "02/Jan/2006:15:04:05 -0700"
var timeBracketRe = regexp.MustCompile(`\[([^\]]+)\]`)

type IPPolicy string

const (
    IPStore IPPolicy = "store"
    IPMask  IPPolicy = "mask"
    IPHash  IPPolicy = "hash"
    IPDrop  IPPolicy = "drop"
)

type hasher interface{ HashString(s string) string }

// ImportAccess imports new lines from an access log.
func ImportAccess(db *sql.DB, logName, path string, policy IPPolicy, h hasher) error {
    // Capture previous state for logging
    prevSt, havePrev, _ := getState(db, logName)
    inode, _, _, _ := fileIdent(path)
    // Prepare insert statement.
    stmt, err := db.Prepare(`INSERT OR IGNORE INTO request_events (ts_unix, ts, remote_addr, xff, method, path, protocol, status, bytes_sent, referer, user_agent, raw_line)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    if err != nil {
        return err
    }
    defer stmt.Close()
    var total, inserted int64
    var firstISO, lastISO string
    err = withIncrementalRead(db, logName, path, func(line string) error {
        m := accessRe.FindStringSubmatch(line)
        if m == nil {
            // Store as raw if unparsed, but try to recover timestamp from [ ... ]
            t := time.Now().UTC()
            if mm := timeBracketRe.FindStringSubmatch(line); mm != nil {
                if tt, err := time.Parse(accessTimeLayout, mm[1]); err == nil {
                    t = tt.UTC()
                }
            }
            iso := t.Format(time.RFC3339)
            res, err := stmt.Exec(t.Unix(), iso, nil, nil, nil, nil, nil, nil, nil, nil, nil, line)
            if err == nil { if ra, _ := res.RowsAffected(); ra > 0 { inserted += ra } }
            total++
            if firstISO == "" { firstISO = iso }
            lastISO = iso
            return err
        }
        remote := normalizeIP(m[1], policy, h)
        tsStr := m[2]
        method := m[3]
        path := m[4]
        proto := m[5]
        status, _ := strconv.Atoi(m[6])
        bytes := 0
        if m[7] != "-" {
            bytes, _ = strconv.Atoi(m[7])
        }
        referer := toNull(m[8])
        ua := toNull(m[9])
        xff := toNull(normalizeXFF(m[10], policy, h))

        // Parse time like 13/Sep/2025:00:47:56 +0000
        tt, err := time.Parse(accessTimeLayout, tsStr)
        if err != nil {
            tt = time.Now().UTC()
        }
        tsUnix := tt.UTC().Unix()
        tsISO := tt.UTC().Format(time.RFC3339)

        // Insert (use NullString for optional fields)
        var remoteVal interface{} = remote
        if remote == "" {
            remoteVal = nil
        }
        res, err := stmt.Exec(tsUnix, tsISO, remoteVal, nullVal(xff), method, path, proto, status, bytes, nullVal(referer), nullVal(ua), line)
        if err == nil { if ra, _ := res.RowsAffected(); ra > 0 { inserted += ra } }
        total++
        if firstISO == "" { firstISO = tsISO }
        lastISO = tsISO
        return err
    })
    if err != nil { return err }
    newSt, _, _ := getState(db, logName)
    var prevPos int64
    if havePrev { prevPos = prevSt.position }
    log.Printf("import access: path=%s inode=%d pos=%d->%d (+%d) lines=%d inserted=%d ignored=%d ts=[%s..%s]",
        path, inode, prevPos, newSt.position, newSt.position-prevPos, total, inserted, total-inserted, firstISO, lastISO)
    return nil
}

// normalizeXFF applies IP policy to a comma-separated XFF list, keeping shape but normalizing IPs.
func normalizeXFF(s string, policy IPPolicy, h hasher) string {
    if s == "-" || strings.TrimSpace(s) == "" {
        return ""
    }
    parts := strings.Split(s, ",")
    for i := range parts {
        parts[i] = normalizeIP(strings.TrimSpace(parts[i]), policy, h)
    }
    return strings.Join(parts, ", ")
}

func normalizeIP(s string, policy IPPolicy, h hasher) string {
    if policy == IPDrop {
        return ""
    }
    ip := net.ParseIP(s)
    if ip == nil {
        // Not an IP (could be proxy name). Optionally hash the raw string.
        if policy == IPHash && h != nil {
            return "h:" + h.HashString(s)
        }
        if policy == IPMask {
            return "" // unrecognized => drop
        }
        return s
    }
    if policy == IPStore {
        return ip.String()
    }
    if policy == IPHash {
        if h == nil {
            return ""
        }
        return "h:" + h.HashString(ip.String())
    }
    // Mask
    if v4 := ip.To4(); v4 != nil {
        v4[3] = 0
        return v4.String()
    }
    // IPv6: zero lower 64 bits (keep /64)
    b := ip.To16()
    if b == nil { return "" }
    for i := 8; i < 16; i++ { b[i] = 0 }
    return net.IP(b).String()
}

type nullString struct {
    Valid bool
    Str   string
}

func toNull(s string) nullString {
    s = strings.TrimSpace(s)
    if s == "" || s == "-" {
        return nullString{Valid: false}
    }
    return nullString{Valid: true, Str: s}
}

func nullVal(ns nullString) interface{} {
    if !ns.Valid {
        return nil
    }
    return ns.Str
}
