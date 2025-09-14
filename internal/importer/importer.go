package importer

import (
    "bufio"
    "database/sql"
    "errors"
    "fmt"
    "io"
    "os"
    "syscall"
    "time"
)

type fileState struct {
    inode     uint64
    position  int64
    lastMtime int64
    lastSize  int64
}

// getState fetches the last known state for a given logical log name.
func getState(db *sql.DB, logName string) (fileState, bool, error) {
    var st fileState
    row := db.QueryRow(`SELECT inode, position, last_mtime, last_size FROM import_state WHERE log_name = ?`, logName)
    switch err := row.Scan(&st.inode, &st.position, &st.lastMtime, &st.lastSize); err {
    case nil:
        return st, true, nil
    case sql.ErrNoRows:
        return fileState{}, false, nil
    default:
        return fileState{}, false, err
    }
}

func upsertState(db *sql.DB, logName string, st fileState) error {
    _, err := db.Exec(`INSERT INTO import_state (log_name, inode, position, last_mtime, last_size, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?)
                       ON CONFLICT(log_name) DO UPDATE SET inode=excluded.inode, position=excluded.position, last_mtime=excluded.last_mtime, last_size=excluded.last_size, updated_at=excluded.updated_at`,
        logName, st.inode, st.position, st.lastMtime, st.lastSize, time.Now().Unix())
    return err
}

// fileIdent returns inode and size/mtime info for a path.
func fileIdent(path string) (inode uint64, size int64, mtime int64, err error) {
    fi, err := os.Stat(path)
    if err != nil {
        return 0, 0, 0, err
    }
    st, ok := fi.Sys().(*syscall.Stat_t)
    if !ok {
        return 0, 0, 0, errors.New("unsupported stat type for inode")
    }
    return uint64(st.Ino), fi.Size(), fi.ModTime().Unix(), nil
}

// withIncrementalRead reads new bytes since last position and calls process for each line.
// It persists the final file position, handling truncation and rotation by inode.
func withIncrementalRead(db *sql.DB, logName, path string, process func(line string) error) error {
    inode, size, mtime, err := fileIdent(path)
    if err != nil {
        return fmt.Errorf("stat %s: %w", path, err)
    }
    st, have, err := getState(db, logName)
    if err != nil {
        return err
    }

    startPos := int64(0)
    if have && st.inode == inode {
        if st.position <= size {
            startPos = st.position
        } else {
            // Truncated: start over on current file.
            startPos = 0
        }
    } else {
        // New file (rotation) or first run: start at 0 for now.
        startPos = 0
    }

    f, err := os.Open(path)
    if err != nil {
        return err
    }
    defer f.Close()
    if _, err := f.Seek(startPos, io.SeekStart); err != nil {
        return err
    }
    r := bufio.NewReader(f)
    cur := startPos
    for {
        s, err := r.ReadString('\n')
        if len(s) > 0 {
            // Trim trailing newline for processing but count all bytes.
            line := s
            if line[len(line)-1] == '\n' {
                line = line[:len(line)-1]
            }
            if err2 := process(line); err2 != nil {
                return err2
            }
            cur += int64(len(s))
        }
        if err != nil {
            if errors.Is(err, io.EOF) {
                break
            }
            return err
        }
    }
    return upsertState(db, logName, fileState{inode: inode, position: cur, lastMtime: mtime, lastSize: size})
}

