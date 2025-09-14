package importer

import (
    "database/sql"
    "log"
    "regexp"
    "strconv"
    "time"
)

// nginx error log line: 2025/09/13 03:00:06 [warn] 2116903#2116903: message
var errRe = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[([a-z]+)\] (\d+)#(\d+): (.*)$`)

const errTimeLayout = "2006/01/02 15:04:05"

func ImportError(db *sql.DB, logName, path string) error {
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
        m := errRe.FindStringSubmatch(line)
        if m == nil {
            t := time.Now().UTC()
            iso := t.Format(time.RFC3339)
            res, err := stmt.Exec(t.Unix(), iso, nil, nil, nil, nil, line)
            if err == nil { if ra, _ := res.RowsAffected(); ra > 0 { inserted += ra } }
            total++
            if firstISO == "" { firstISO = iso }
            lastISO = iso
            return err
        }
        tt, err := time.Parse(errTimeLayout, m[1])
        if err != nil {
            tt = time.Now().UTC()
        }
        lvl := m[2]
        pid, _ := strconv.Atoi(m[3])
        tid, _ := strconv.Atoi(m[4])
        msg := m[5]
        iso := tt.UTC().Format(time.RFC3339)
        res, err := stmt.Exec(tt.UTC().Unix(), iso, lvl, pid, tid, msg, line)
        if err == nil { if ra, _ := res.RowsAffected(); ra > 0 { inserted += ra } }
        total++
        if firstISO == "" { firstISO = iso }
        lastISO = iso
        return err
    })
    if err != nil { return err }
    newSt, _, _ := getState(db, logName)
    var prevPos int64
    if havePrev { prevPos = prevSt.position }
    log.Printf("import error: path=%s inode=%d pos=%d->%d (+%d) lines=%d inserted=%d ignored=%d ts=[%s..%s]",
        path, inode, prevPos, newSt.position, newSt.position-prevPos, total, inserted, total-inserted, firstISO, lastISO)
    return nil
}
