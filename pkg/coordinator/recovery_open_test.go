package coordinator

import "testing"

func TestValidateRecoveryMigrationLedgerRequiresExactBinarySchema(t *testing.T) {
	embedded, err := loadPostgresMigrations()
	if err != nil {
		t.Fatalf("load embedded migrations: %v", err)
	}
	valid := make([]RecoveryMigration, len(embedded))
	for index, migration := range embedded {
		valid[index] = RecoveryMigration{Version: migration.version, Name: migration.name}
	}
	if err := ValidateRecoveryMigrationLedger(valid); err != nil {
		t.Fatalf("exact recovery migration ledger rejected: %v", err)
	}
	if len(valid) < 2 {
		t.Fatal("test requires multiple embedded migrations")
	}
	if err := ValidateRecoveryMigrationLedger(valid[:len(valid)-1]); err == nil {
		t.Fatal("older recovery migration ledger was accepted")
	}
	future := append([]RecoveryMigration(nil), valid...)
	future = append(future, RecoveryMigration{Version: valid[len(valid)-1].Version + 1, Name: "999_future.sql"})
	if err := ValidateRecoveryMigrationLedger(future); err == nil {
		t.Fatal("future recovery migration ledger was accepted")
	}
	wrongName := append([]RecoveryMigration(nil), valid...)
	wrongName[len(wrongName)-1].Name = "003_tampered.sql"
	if err := ValidateRecoveryMigrationLedger(wrongName); err == nil {
		t.Fatal("mismatched recovery migration name was accepted")
	}
}
