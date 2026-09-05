package recovery

import (
	"strings"
	"testing"
)

func TestCommandPostgresDSNRemovesPasswordFromArguments(t *testing.T) {
	safe, password, err := commandPostgresDSN("postgres://ztfl:super-secret@db.example:5432/ztfl?sslmode=require")
	if err != nil {
		t.Fatalf("parse PostgreSQL recovery DSN: %v", err)
	}
	if password != "super-secret" {
		t.Fatalf("password = %q", password)
	}
	if strings.Contains(safe, "super-secret") {
		t.Fatalf("password leaked into PostgreSQL command DSN: %s", safe)
	}
	if safe != "postgres://ztfl@db.example:5432/ztfl?sslmode=require" {
		t.Fatalf("safe PostgreSQL DSN = %q", safe)
	}
}

func TestCommandPostgresDSNRejectsUnsupportedForms(t *testing.T) {
	for _, value := range []string{"", "host=db user=ztfl", "mysql://db/ztfl", "postgres:///ztfl"} {
		if _, _, err := commandPostgresDSN(value); err == nil {
			t.Fatalf("unsupported PostgreSQL DSN %q was accepted", value)
		}
	}
}

func TestRequireCompatiblePostgresToolRejectsOlderMajor(t *testing.T) {
	if err := requireCompatiblePostgresTool(17, 180006, "pg_dump"); err == nil {
		t.Fatal("PostgreSQL 17 pg_dump was accepted for a PostgreSQL 18 source")
	}
	if err := requireCompatiblePostgresTool(18, 180006, "pg_dump"); err != nil {
		t.Fatalf("matching PostgreSQL tool was rejected: %v", err)
	}
	if err := requireCompatiblePostgresTool(19, 180006, "pg_dump"); err != nil {
		t.Fatalf("newer PostgreSQL tool was rejected: %v", err)
	}
}
