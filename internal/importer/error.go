package importer

import (
	"database/sql"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// nginx error log line: 2025/09/13 03:00:06 [warn] 2116903#2116903: message
var errRe = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[([a-z]+)\] (\d+)#(\d+): (.*)$`)

const errTimeLayout = "2006/01/02 15:04:05"

type errorRecord struct {
	ts      time.Time
	level   string
	pid     *int
	tid     *int
	message string
}

func ImportError(db *sql.DB, logName, path string, format AccessFormat) error {
	prevSt, havePrev, _ := getState(db, logName)
	inode, _, _, _ := fileIdent(path)
	stmt, err := db.Prepare(`INSERT OR IGNORE INTO error_events (ts_unix, ts, level, pid, tid, message, raw_line)
                             VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	var total, inserted int64
	var firstISO, lastISO string
	err = withIncrementalRead(db, logName, path, func(line string) error {
		rec, ok := parseErrorLine(line, format)
		if !ok {
			t := fallbackErrorTime(line, format)
			iso := t.Format(time.RFC3339)
			res, err := stmt.Exec(t.Unix(), iso, nil, nil, nil, nil, line)
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
		var pidVal interface{}
		if rec.pid != nil {
			pidVal = *rec.pid
		}
		var tidVal interface{}
		if rec.tid != nil {
			tidVal = *rec.tid
		}
		res, err := stmt.Exec(ts.Unix(), iso, rec.level, pidVal, tidVal, rec.message, line)
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
	log.Printf("import error: path=%s inode=%d pos=%d->%d (+%d) lines=%d inserted=%d ignored=%d ts=[%s..%s]",
		path, inode, prevPos, newSt.position, newSt.position-prevPos, total, inserted, total-inserted, firstISO, lastISO)
	return nil
}

func parseErrorLine(line string, format AccessFormat) (errorRecord, bool) {
	switch format {
	case FormatCaddy:
		return parseCaddyError(line)
	case FormatNginx:
		return parseNginxError(line)
	default:
		return errorRecord{}, false
	}
}

func parseNginxError(line string) (errorRecord, bool) {
	m := errRe.FindStringSubmatch(line)
	if m == nil {
		return errorRecord{}, false
	}
	tt, err := time.Parse(errTimeLayout, m[1])
	if err != nil {
		tt = time.Now().UTC()
	}
	pid := intPtrFromString(m[3])
	tid := intPtrFromString(m[4])
	return errorRecord{
		ts:      tt.UTC(),
		level:   m[2],
		pid:     pid,
		tid:     tid,
		message: m[5],
	}, true
}

func parseCaddyError(line string) (errorRecord, bool) {
	parts := splitCaddyLine(line)
	if len(parts) < 3 {
		return errorRecord{}, false
	}
	ts, ok := parseCaddyTimestamp(parts[0])
	if !ok {
		return errorRecord{}, false
	}
	level := strings.TrimSpace(parts[1])
	logger := ""
	if len(parts) >= 3 {
		logger = strings.TrimSpace(parts[2])
	}
	msg := ""
	if len(parts) >= 4 {
		msg = strings.TrimSpace(parts[3])
	}
	if len(parts) >= 5 {
		extra := strings.TrimSpace(parts[4])
		if extra != "" {
			if msg != "" {
				msg = msg + " " + extra
			} else {
				msg = extra
			}
		}
	}
	if logger != "" {
		if msg != "" {
			msg = logger + ": " + msg
		} else {
			msg = logger
		}
	}
	if msg == "" {
		msg = stripANSI(line)
	}
	return errorRecord{
		ts:      ts,
		level:   level,
		message: msg,
	}, true
}

func fallbackErrorTime(line string, format AccessFormat) time.Time {
	switch format {
	case FormatCaddy:
		parts := splitCaddyLine(line)
		if len(parts) > 0 {
			if ts, ok := parseCaddyTimestamp(parts[0]); ok {
				return ts
			}
		}
	case FormatNginx:
		if m := errRe.FindStringSubmatch(line); m != nil {
			if tt, err := time.Parse(errTimeLayout, m[1]); err == nil {
				return tt.UTC()
			}
		}
	}
	if m := errRe.FindStringSubmatch(line); m != nil {
		if tt, err := time.Parse(errTimeLayout, m[1]); err == nil {
			return tt.UTC()
		}
	}
	return time.Now().UTC()
}

func intPtrFromString(s string) *int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	return &v
}
