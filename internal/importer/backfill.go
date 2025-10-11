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
func ImportAccessFiles(db *sql.DB, files []string, format AccessFormat, policy IPPolicy, h hasher) error {
	expanded, err := expandFiles(files)
	if err != nil {
		return err
	}
	if len(expanded) == 0 {
		return nil
	}
	// Sort by name for deterministic order (mtime could be used too)
	sort.Slice(expanded, func(i, j int) bool { return expanded[i].path < expanded[j].path })
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO request_events (ts_unix, ts, remote_addr, xff, method, path, protocol, status, bytes_sent, referer, user_agent, raw_line)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	var total, totalInserted int64
	log.Printf("backfill access: files=%d", len(expanded))
	for _, f := range expanded {
		rc, err := openMaybeGzip(f.path)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("open %s: %w", f.path, err)
		}
		r := bufio.NewReader(rc)
		var lines, inserted int64
		var firstISO, lastISO string
		for {
			s, err := r.ReadString('\n')
			if len(s) > 0 {
				line := strings.TrimRight(s, "\n")
				rec, ok := parseAccessLine(line, format, policy, h)
				if !ok {
					t := fallbackAccessTime(line, format)
					iso := t.Format(time.RFC3339)
					res, err := stmt.Exec(t.Unix(), iso, nil, nil, nil, nil, nil, nil, nil, nil, nil, line)
					if err != nil {
						rc.Close()
						_ = tx.Rollback()
						return err
					}
					if ra, _ := res.RowsAffected(); ra > 0 {
						inserted += ra
						totalInserted += ra
					}
					lines++
					total++
					if firstISO == "" {
						firstISO = iso
					}
					lastISO = iso
					continue
				}
				ts := rec.ts.UTC()
				iso := ts.Format(time.RFC3339)
				var remoteVal interface{}
				if rec.remote != "" {
					remoteVal = rec.remote
				}
				res, err := stmt.Exec(ts.Unix(), iso, remoteVal, nullVal(rec.xff), rec.method, rec.path, rec.proto, rec.status, rec.bytes, nullVal(rec.referer), nullVal(rec.userAgent), line)
				if err != nil {
					rc.Close()
					_ = tx.Rollback()
					return err
				}
				if ra, _ := res.RowsAffected(); ra > 0 {
					inserted += ra
					totalInserted += ra
				}
				lines++
				total++
				if firstISO == "" {
					firstISO = iso
				}
				lastISO = iso
			}
			if err != nil {
				if err == io.EOF {
					break
				}
				rc.Close()
				_ = tx.Rollback()
				return err
			}
		}
		rc.Close()
		log.Printf("backfill access: file=%s lines=%d inserted=%d ignored=%d ts=[%s..%s]", f.path, lines, inserted, lines-inserted, firstISO, lastISO)
	}
	log.Printf("backfill access: files=%d total_lines=%d total_inserted=%d", len(expanded), total, totalInserted)
	return tx.Commit()
}

func ImportErrorFiles(db *sql.DB, files []string, format AccessFormat) error {
	expanded, err := expandFiles(files)
	if err != nil {
		return err
	}
	if len(expanded) == 0 {
		return nil
	}
	sort.Slice(expanded, func(i, j int) bool { return expanded[i].path < expanded[j].path })
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO error_events (ts_unix, ts, level, pid, tid, message, raw_line) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	var total, totalInserted int64
	log.Printf("backfill error: files=%d", len(expanded))
	for _, f := range expanded {
		rc, err := openMaybeGzip(f.path)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("open %s: %w", f.path, err)
		}
		r := bufio.NewReader(rc)
		var lines, inserted int64
		var firstISO, lastISO string
		for {
			s, err := r.ReadString('\n')
			if len(s) > 0 {
				line := strings.TrimRight(s, "\n")
				rec, ok := parseErrorLine(line, format)
				if !ok {
					t := fallbackErrorTime(line, format)
					iso := t.Format(time.RFC3339)
					res, err := stmt.Exec(t.Unix(), iso, nil, nil, nil, nil, line)
					if err != nil {
						rc.Close()
						_ = tx.Rollback()
						return err
					}
					if ra, _ := res.RowsAffected(); ra > 0 {
						inserted += ra
						totalInserted += ra
					}
					lines++
					total++
					if firstISO == "" {
						firstISO = iso
					}
					lastISO = iso
					continue
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
				if err != nil {
					rc.Close()
					_ = tx.Rollback()
					return err
				}
				if ra, _ := res.RowsAffected(); ra > 0 {
					inserted += ra
					totalInserted += ra
				}
				lines++
				total++
				if firstISO == "" {
					firstISO = iso
				}
				lastISO = iso
			}
			if err != nil {
				if err == io.EOF {
					break
				}
				rc.Close()
				_ = tx.Rollback()
				return err
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
		if p == "" {
			continue
		}
		// Expand globs
		matches, err := filepath.Glob(p)
		if err != nil {
			return nil, err
		}
		if matches != nil && len(matches) > 0 {
			for _, m := range matches {
				out = append(out, fileItem{path: m})
			}
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
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &gzipReadCloser{ReadCloser: zr, f: f}, nil
	}
	return f, nil
}

type gzipReadCloser struct {
	io.ReadCloser
	f *os.File
}

func (g *gzipReadCloser) Close() error { _ = g.ReadCloser.Close(); return g.f.Close() }
