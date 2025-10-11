package importer

import (
	"database/sql"
	"encoding/json"
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

const (
	accessTimeLayout   = "02/Jan/2006:15:04:05 -0700"
	caddyTimeLayout    = "2006/01/02 15:04:05.000"
	caddyTimeLayoutAlt = "2006/01/02 15:04:05"
)

var timeBracketRe = regexp.MustCompile(`\[([^\]]+)\]`)
var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

type IPPolicy string

const (
	IPStore IPPolicy = "store"
	IPMask  IPPolicy = "mask"
	IPHash  IPPolicy = "hash"
	IPDrop  IPPolicy = "drop"
)

type hasher interface{ HashString(s string) string }

type accessRecord struct {
	ts        time.Time
	remote    string
	xff       nullString
	method    string
	path      string
	proto     string
	status    int
	bytes     int
	referer   nullString
	userAgent nullString
}

func parseAccessLine(line string, format AccessFormat, policy IPPolicy, h hasher) (accessRecord, bool) {
	switch format {
	case FormatCaddy:
		return parseCaddyAccess(line, policy, h)
	case FormatNginx:
		return parseNginxAccess(line, policy, h)
	default:
		return accessRecord{}, false
	}
}

// ImportAccess imports new lines from an access log.
func ImportAccess(db *sql.DB, logName, path string, format AccessFormat, policy IPPolicy, h hasher) error {
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
		rec, ok := parseAccessLine(line, format, policy, h)
		if !ok {
			t := fallbackAccessTime(line, format)
			iso := t.Format(time.RFC3339)
			res, err := stmt.Exec(t.Unix(), iso, nil, nil, nil, nil, nil, nil, nil, nil, nil, line)
			if err == nil {
				if ra, _ := res.RowsAffected(); ra > 0 {
					inserted += ra
				}
			}
			total++
			if firstISO == "" {
				firstISO = iso
			}
			lastISO = iso
			return err
		}
		ts := rec.ts.UTC()
		iso := ts.Format(time.RFC3339)

		var remoteVal interface{}
		if rec.remote == "" {
			remoteVal = nil
		} else {
			remoteVal = rec.remote
		}
		res, err := stmt.Exec(ts.Unix(), iso, remoteVal, nullVal(rec.xff), rec.method, rec.path, rec.proto, rec.status, rec.bytes, nullVal(rec.referer), nullVal(rec.userAgent), line)
		if err == nil {
			if ra, _ := res.RowsAffected(); ra > 0 {
				inserted += ra
			}
		}
		total++
		if firstISO == "" {
			firstISO = iso
		}
		lastISO = iso
		return err
	})
	if err != nil {
		return err
	}
	newSt, _, _ := getState(db, logName)
	var prevPos int64
	if havePrev {
		prevPos = prevSt.position
	}
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
	if b == nil {
		return ""
	}
	for i := 8; i < 16; i++ {
		b[i] = 0
	}
	return net.IP(b).String()
}

func parseNginxAccess(line string, policy IPPolicy, h hasher) (accessRecord, bool) {
	m := accessRe.FindStringSubmatch(line)
	if m == nil {
		return accessRecord{}, false
	}
	tt, err := time.Parse(accessTimeLayout, m[2])
	if err != nil {
		tt = time.Now().UTC()
	}
	status, _ := strconv.Atoi(m[6])
	bytes := 0
	if m[7] != "-" {
		bytes, _ = strconv.Atoi(m[7])
	}
	return accessRecord{
		ts:        tt.UTC(),
		remote:    normalizeIP(m[1], policy, h),
		xff:       toNull(normalizeXFF(m[10], policy, h)),
		method:    m[3],
		path:      m[4],
		proto:     m[5],
		status:    status,
		bytes:     bytes,
		referer:   toNull(m[8]),
		userAgent: toNull(m[9]),
	}, true
}

type caddyAccessPayload struct {
	Request struct {
		RemoteIP string              `json:"remote_ip"`
		ClientIP string              `json:"client_ip"`
		Proto    string              `json:"proto"`
		Method   string              `json:"method"`
		URI      string              `json:"uri"`
		Headers  map[string][]string `json:"headers"`
	} `json:"request"`
	Size   int `json:"size"`
	Status int `json:"status"`
}

func parseCaddyAccess(line string, policy IPPolicy, h hasher) (accessRecord, bool) {
	parts := splitCaddyLine(line)
	if len(parts) < 5 {
		return accessRecord{}, false
	}
	ts, ok := parseCaddyTimestamp(parts[0])
	if !ok {
		return accessRecord{}, false
	}
	logger := parts[2]
	if !strings.Contains(logger, "http.log.access") {
		return accessRecord{}, false
	}
	payloadStr := strings.TrimSpace(parts[4])
	var payload caddyAccessPayload
	if err := json.Unmarshal([]byte(payloadStr), &payload); err != nil {
		return accessRecord{}, false
	}
	req := payload.Request
	if req.Method == "" || req.URI == "" {
		return accessRecord{}, false
	}
	remote := req.RemoteIP
	if remote == "" {
		remote = req.ClientIP
	}
	xffHeader := headerValue(req.Headers, "X-Forwarded-For")
	return accessRecord{
		ts:        ts,
		remote:    normalizeIP(remote, policy, h),
		xff:       toNull(normalizeXFF(xffHeader, policy, h)),
		method:    req.Method,
		path:      req.URI,
		proto:     req.Proto,
		status:    payload.Status,
		bytes:     payload.Size,
		referer:   toNull(headerValue(req.Headers, "Referer")),
		userAgent: toNull(headerValue(req.Headers, "User-Agent")),
	}, true
}

func fallbackAccessTime(line string, format AccessFormat) time.Time {
	switch format {
	case FormatCaddy:
		parts := splitCaddyLine(line)
		if len(parts) > 0 {
			if ts, ok := parseCaddyTimestamp(parts[0]); ok {
				return ts
			}
		}
	case FormatNginx:
		if mm := timeBracketRe.FindStringSubmatch(line); mm != nil {
			if tt, err := time.Parse(accessTimeLayout, mm[1]); err == nil {
				return tt.UTC()
			}
		}
	}
	if mm := timeBracketRe.FindStringSubmatch(line); mm != nil {
		if tt, err := time.Parse(accessTimeLayout, mm[1]); err == nil {
			return tt.UTC()
		}
	}
	return time.Now().UTC()
}

func headerValue(headers map[string][]string, key string) string {
	if len(headers) == 0 {
		return ""
	}
	for k, vals := range headers {
		if strings.EqualFold(k, key) && len(vals) > 0 {
			return strings.Join(vals, ", ")
		}
	}
	return ""
}

func splitCaddyLine(line string) []string {
	cleaned := stripANSI(line)
	return strings.SplitN(cleaned, "\t", 5)
}

func parseCaddyTimestamp(tsField string) (time.Time, bool) {
	tsField = strings.TrimSpace(tsField)
	if tsField == "" {
		return time.Time{}, false
	}
	layouts := []string{caddyTimeLayout, caddyTimeLayoutAlt}
	for _, layout := range layouts {
		tt, err := time.ParseInLocation(layout, tsField, time.Local)
		if err == nil {
			return tt.UTC(), true
		}
	}
	return time.Time{}, false
}

func stripANSI(s string) string {
	if !strings.Contains(s, "\x1b") {
		return s
	}
	return ansiRe.ReplaceAllString(s, "")
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
