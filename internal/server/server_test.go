package server

import (
	"context"
	"strings"
	"testing"

	"github.com/hashim-work-svg/Audit-Agnet/embedded"
	"github.com/hashim-work-svg/Audit-Agnet/internal/audit"
	"github.com/hashim-work-svg/Audit-Agnet/internal/auth"
	"github.com/hashim-work-svg/Audit-Agnet/internal/demo"
	"github.com/hashim-work-svg/Audit-Agnet/internal/masking"
	"github.com/hashim-work-svg/Audit-Agnet/internal/policy"
	"github.com/hashim-work-svg/Audit-Agnet/internal/ratelimit"
	"github.com/hashim-work-svg/Audit-Agnet/internal/sqlvalidate"
)

func TestGatewayPipeline(t *testing.T) {
	sqliteDB, err := demo.InitDemoDB()
	if err != nil {
		t.Fatalf("InitDemoDB failed: %v", err)
	}
	defer sqliteDB.Close()

	pe, err := policy.LoadFromYAML(embedded.ExamplePolicyYAML)
	if err != nil {
		t.Fatalf("LoadFromYAML failed: %v", err)
	}

	rawDB := sqliteDB.RawDB()
	authenticator := auth.NewAuthenticator(rawDB)
	validator := sqlvalidate.NewValidator(pe)
	masker := masking.NewMasker(pe, "test-secret")
	logger := audit.NewLogger(rawDB, "test-audit-secret")
	limiter := ratelimit.NewLimiter(pe)

	gw := NewGateway(sqliteDB, authenticator, pe, validator, masker, logger, limiter)
	ctx := context.Background()

	// 1. Tool Pinning Verification
	err = gw.VerifyToolPin("list_tables", "List database tables permitted for the calling agent", "{}")
	if err != nil {
		t.Errorf("expected clean tool pin verification, got: %v", err)
	}
	err = gw.VerifyToolPin("list_tables", "Altered description", "{}")
	if err == nil {
		t.Errorf("expected tool pin mismatch error on modified description, got nil")
	}

	// 2. Test ListTables for analytics-agent
	tables, err := gw.ListTables(ctx, "demo-token-analytics")
	if err != nil {
		t.Fatalf("ListTables failed: %v", err)
	}
	// Internal tables agent_keys and audit_records should NEVER be returned
	for _, tbl := range tables {
		if tbl == "agent_keys" || tbl == "audit_records" {
			t.Errorf("internal table %q leaked in list_tables", tbl)
		}
	}
	if len(tables) < 3 {
		t.Errorf("expected at least 3 tables, got: %v", tables)
	}

	// 3. Test DescribeTable for analytics-agent
	// ssn_last4 should NOT be in described columns
	cols, err := gw.DescribeTable(ctx, "demo-token-analytics", "customers")
	if err != nil {
		t.Fatalf("DescribeTable failed: %v", err)
	}
	for _, c := range cols {
		if c.Name == "ssn_last4" {
			t.Errorf("restricted column ssn_last4 leaked in describe_table")
		}
	}

	// 4. Test RunQuery with PII masking
	res, err := gw.RunQuery(ctx, "demo-token-analytics", "SELECT id, full_name, email, phone, credit_card_last4 FROM customers WHERE id = 1")
	if err != nil {
		t.Fatalf("RunQuery failed: %v", err)
	}
	if res.RowCount != 1 {
		t.Fatalf("expected 1 row, got %d", res.RowCount)
	}
	firstRow := res.Rows[0]

	// Verify email is partially masked
	email := firstRow["email"].(string)
	if !strings.Contains(email, "***") || !strings.HasSuffix(email, "@example.corp") {
		t.Errorf("expected masked email, got %q", email)
	}

	// Verify phone is redacted
	phone := firstRow["phone"].(string)
	if phone != "[REDACTED_PHONE]" {
		t.Errorf("expected [REDACTED_PHONE], got %q", phone)
	}

	// 5. Test Denied query (DROP TABLE)
	_, err = gw.RunQuery(ctx, "demo-token-analytics", "DROP TABLE customers")
	if err == nil {
		t.Fatalf("expected DROP TABLE to be denied, but it succeeded")
	}

	// 6. Test Audit Log Verification passes on clean chain
	verifiedCount, err := logger.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("expected audit chain to verify cleanly, got: %v", err)
	}
	if verifiedCount == 0 {
		t.Errorf("expected verified records in audit chain, got 0")
	}
}
