package db

import (
	"os"
	"testing"
)

func TestHostColumnMigration(t *testing.T) {
	dbPath := "/tmp/test_logtool_migration.db"
	os.Remove(dbPath)
	defer os.Remove(dbPath)
	
	sqldb, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer sqldb.Close()
	
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
			t.Logf("Found 'host' column: type=%s", ctype)
		}
	}
	
	if !hasHostColumn {
		t.Fatal("'host' column not found!")
	}
	
	rows2, err := sqldb.Query("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_request_host'")
	if err != nil {
		t.Fatalf("query indexes: %v", err)
	}
	defer rows2.Close()
	
	hasIndex := false
	for rows2.Next() {
		var name string
		if err := rows2.Scan(&name); err != nil {
			t.Fatalf("scan index: %v", err)
		}
		if name == "idx_request_host" {
			hasIndex = true
			t.Log("Found 'idx_request_host' index")
		}
	}
	
	if !hasIndex {
		t.Fatal("'idx_request_host' index not found!")
	}
}
