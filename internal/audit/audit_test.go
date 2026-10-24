package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/hashim-work-svg/Audit-Agnet/internal/demo"
)

func TestAuditLogAndVerify(t *testing.T) {
	sqliteDB, err := demo.InitDemoDB()
	if err != nil {
		t.Fatalf("InitDemoDB failed: %v", err)
	}
	defer sqliteDB.Close()

	ctx := context.Background()
	logger := NewLogger(sqliteDB.RawDB(), "test-hmac-key")

	// 1. Log three events
	rec1, err := logger.Log(ctx, "analytics-agent", "run_query", "SELECT id FROM customers", "SELECT id FROM customers LIMIT 50", "ALLOWED", 5)
	if err != nil {
		t.Fatalf("failed logging event 1: %v", err)
	}
	if rec1.PrevHash != GenesisHash {
		t.Errorf("expected genesis prev_hash for first record, got %s", rec1.PrevHash)
	}

	rec2, err := logger.Log(ctx, "analytics-agent", "run_query", "DROP TABLE customers", "", "DENIED", 0)
	if err != nil {
		t.Fatalf("failed logging event 2: %v", err)
	}
	if rec2.PrevHash != rec1.RecordHash {
		t.Errorf("expected record 2 prev_hash to equal record 1 hash, got %s != %s", rec2.PrevHash, rec1.RecordHash)
	}

	rec3, err := logger.Log(ctx, "support-agent", "run_query", "SELECT email FROM customers", "SELECT email FROM customers LIMIT 25", "MASKED", 5)
	if err != nil {
		t.Fatalf("failed logging event 3: %v", err)
	}
	if rec3.PrevHash != rec2.RecordHash {
		t.Errorf("expected record 3 prev_hash to equal record 2 hash")
	}

	// 2. Verify clean audit log passes
	count, err := logger.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("expected audit chain to verify cleanly, got error: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 verified records, got %d", count)
	}

	// 3. Tamper with record 2 (e.g. modify rewritten_sql or row_count directly in DB)
	_, err = sqliteDB.RawDB().ExecContext(ctx, "UPDATE audit_records SET decision = 'ALLOWED' WHERE id = ?", rec2.ID)
	if err != nil {
		t.Fatalf("failed simulating tampering: %v", err)
	}

	// 4. Verify tampering is immediately detected
	_, err = logger.VerifyAuditChain(ctx)
	if err == nil || !errors.Is(err, ErrInvalidRecord) {
		t.Errorf("expected ErrInvalidRecord after modifying record payload, got: %v", err)
	}
}
