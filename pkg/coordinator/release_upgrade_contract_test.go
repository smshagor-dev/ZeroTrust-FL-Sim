package coordinator

import "testing"

func TestReleaseStateSchemaUpgradeWindowIsExplicit(t *testing.T) {
	if legacyCoordinatorStateSchemaVersion != 1 {
		t.Fatalf("legacy coordinator state schema = %d, want 1", legacyCoordinatorStateSchemaVersion)
	}
	if previousCoordinatorStateSchemaVersion != 2 {
		t.Fatalf("previous coordinator state schema = %d, want 2", previousCoordinatorStateSchemaVersion)
	}
	if coordinatorStateSchemaVersion != 3 {
		t.Fatalf("current coordinator state schema = %d, want 3", coordinatorStateSchemaVersion)
	}
}

func TestReleasePostgresMigrationSequenceIsContiguousAndPinned(t *testing.T) {
	migrations, err := loadPostgresMigrations()
	if err != nil {
		t.Fatalf("load embedded PostgreSQL migrations: %v", err)
	}
	want := []string{
		"001_coordinator_state.sql",
		"002_model_artifact_reference.sql",
		"003_audit_events.sql",
	}
	if len(migrations) != len(want) {
		t.Fatalf("migration count = %d, want %d", len(migrations), len(want))
	}
	for index, migration := range migrations {
		wantVersion := index + 1
		if migration.version != wantVersion {
			t.Fatalf("migration %d version = %d, want %d", index, migration.version, wantVersion)
		}
		if migration.name != want[index] {
			t.Fatalf("migration %d name = %q, want %q", index, migration.name, want[index])
		}
		if migration.sql == "" {
			t.Fatalf("migration %q has empty SQL", migration.name)
		}
	}
}
