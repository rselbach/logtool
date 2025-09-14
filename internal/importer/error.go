package importer

import (
    "database/sql"
    "regexp"
    "strconv"
    "time"
)

// nginx error log line: 2025/09/13 03:00:06 [warn] 2116903#2116903: message
var errRe = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[([a-z]+)\] (\d+)#(\d+): (.*)$`)

const errTimeLayout = "2006/01/02 15:04:05"

func ImportError(db *sql.DB, logName, path string) error {
    stmt, err := db.Prepare(`INSERT INTO error_events (ts_unix, ts, level, pid, tid, message, raw_line)
                             VALUES (?, ?, ?, ?, ?, ?, ?)`)
    if err != nil {
        return err
    }
    defer stmt.Close()

    return withIncrementalRead(db, logName, path, func(line string) error {
        m := errRe.FindStringSubmatch(line)
        if m == nil {
            t := time.Now().UTC()
            _, err := stmt.Exec(t.Unix(), t.Format(time.RFC3339), nil, nil, nil, nil, line)
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
        _, err = stmt.Exec(tt.UTC().Unix(), tt.UTC().Format(time.RFC3339), lvl, pid, tid, msg, line)
        return err
    })
}

