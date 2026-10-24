package demo

import (
	"context"
	"testing"
)

func TestInitDemoDB(t *testing.T) {
	ctx := context.Background()

	database, err := InitDemoDB()
	if err != nil {
		t.Fatalf("InitDemoDB failed: %v", err)
	}
	defer database.Close()

	// Verify all expected tables exist
	expectedTables := []string{
		"agent_keys",
		"audit_records",
		"customers",
		"order_items",
		"orders",
		"products",
	}

	tables, err := database.ListTables(ctx)
	if err != nil {
		t.Fatalf("ListTables failed: %v", err)
	}

	tableSet := make(map[string]bool)
	for _, tbl := range tables {
		tableSet[tbl] = true
	}

	for _, expected := range expectedTables {
		if !tableSet[expected] {
			t.Errorf("missing expected table %q in demo database, found: %v", expected, tables)
		}
	}

	// Verify customer seed rows and PII
	customerRes, err := database.ExecuteQuery(ctx, "SELECT id, full_name, email, phone FROM customers ORDER BY id ASC")
	if err != nil {
		t.Fatalf("failed to query customers: %v", err)
	}

	if customerRes.RowCount != 5 {
		t.Errorf("expected 5 seeded customers, got %d", customerRes.RowCount)
	}

	firstCustomerName := customerRes.Rows[0][1]
	if firstCustomerName != "Alice Vance" {
		t.Errorf("expected first customer to be 'Alice Vance', got %v", firstCustomerName)
	}

	// Verify products
	productRes, err := database.ExecuteQuery(ctx, "SELECT COUNT(*) FROM products")
	if err != nil {
		t.Fatalf("failed to query product count: %v", err)
	}
	if productRes.RowCount != 1 {
		t.Fatalf("expected 1 row for product count, got %d", productRes.RowCount)
	}

	// Verify agent credentials
	agentRes, err := database.ExecuteQuery(ctx, "SELECT agent_id, revoked FROM agent_keys WHERE agent_id = 'analytics-agent'")
	if err != nil {
		t.Fatalf("failed to query agent_keys: %v", err)
	}
	if agentRes.RowCount != 1 {
		t.Fatalf("expected 1 record for analytics-agent, got %d", agentRes.RowCount)
	}
}

func TestSplitSQLStatements(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "Empty input",
			input:    "",
			expected: 0,
		},
		{
			name:     "Single statement with comments",
			input:    "-- Comment line\nSELECT 1;\n-- Another comment",
			expected: 1,
		},
		{
			name:     "Multiple statements",
			input:    "CREATE TABLE t1 (id INT);\nINSERT INTO t1 VALUES (1);\nSELECT * FROM t1;",
			expected: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := splitSQLStatements(tc.input)
			if len(got) != tc.expected {
				t.Errorf("expected %d statements, got %d: %#v", tc.expected, len(got), got)
			}
		})
	}
}
