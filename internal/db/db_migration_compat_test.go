package db

import (
	"database/sql"
	"os"
	"testing"
	_ "github.com/mattn/go-sqlite3"
)

func TestHostColumnMigrationBackwardCompat(t *testing.T) {
	dbPath := "/tmp/test_logtool_old_schema.db"
	os.Remove(dbPath)
	defer os.Remove(dbPath)
	
	// Create old schema without host column
	sqldb, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	
	// Create old table structure
	_, err = sqldb.Exec(`CREATE TABLE request_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts_unix INTEGER NOT NULL,
		ts TEXT NOT NULL,
		remote_addr TEXT,
		xff TEXT,
		method TEXT,
		path TEXT,
		protocol TEXT,
		status INTEGER,
		bytes_sent INTEGER,
		referer TEXT,
		user_agent TEXT,
		raw_line TEXT
	)`)
	if err != nil {
		t.Fatalf("create old table: %v", err)
	}
	
	// Insert test data
	_, err = sqldb.Exec(`INSERT INTO request_events 
		(ts_unix, ts, remote_addr, method, path, status, raw_line) 
		VALUES (1697000000, '2023-10-11T00:00:00Z', '192.168.1.1', 'GET', '/test', 200, 'test log line')`)
	if err != nil {
		t.Fatalf("insert test data: %v", err)
	}
	
	sqldb.Close()
	
	// Now open with new migration
	sqldb, err = Open(dbPath)
	if err != nil {
		t.Fatalf("open db with migration: %v", err)
	}
	defer sqldb.Close()
	
	// Verify host column was added
	rows, err := sqldb.Query("PRAGMA table_info(request_events)")
	if err != nil {
		t.Fatalf("query table info: %v", err)
	}
	defer rows.Close()
	
	hasHostColumn := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dfltValue interface{}
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if name == "host" {
			hasHostColumn = true
			t.Logf("Migration added 'host' column: type=%s", ctype)
		}
	}
	
	if !hasHostColumn {
		t.Fatal("Migration failed to add 'host' column!")
	}
	
	// Verify old data is still there
	var count int
	err = sqldb.QueryRow("SELECT COUNT(*) FROM request_events WHERE path = '/test'").Scan(&count)
	if err != nil {
		t.Fatalf("query old data: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 row, got %d", count)
	}
	t.Log("Old data preserved after migration")
	
	// Verify we can insert new data with host
	_, err = sqldb.Exec(`INSERT INTO request_events 
		(ts_unix, ts, remote_addr, method, path, status, host, raw_line) 
		VALUES (1697000001, '2023-10-11T00:00:01Z', '192.168.1.2', 'GET', '/test2', 200, 'example.com', 'test log line 2')`)
	if err != nil {
		t.Fatalf("insert new data with host: %v", err)
	}
	t.Log("Successfully inserted new data with host column")
}
