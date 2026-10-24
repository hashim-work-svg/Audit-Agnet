package sqlvalidate

import (
	"strings"
	"testing"

	"github.com/hashim-work-svg/Audit-Agnet/embedded"
	"github.com/hashim-work-svg/Audit-Agnet/internal/policy"
)

func TestSQLValidatorComprehensive(t *testing.T) {
	pe, err := policy.LoadFromYAML(embedded.ExamplePolicyYAML)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	validator := NewValidator(pe)

	tests := []struct {
		name        string
		agentID     string
		query       string
		shouldPass  bool
		expectedErr string
	}{
		// 1-10: Allowed legitimate queries
		{
			name:       "Allowed simple select on customers",
			agentID:    "analytics-agent",
			query:      "SELECT id, full_name, email FROM customers",
			shouldPass: true,
		},
		{
			name:       "Allowed select with WHERE filter",
			agentID:    "analytics-agent",
			query:      "SELECT id, full_name, email FROM customers WHERE id = 1",
			shouldPass: true,
		},
		{
			name:       "Allowed select on products",
			agentID:    "analytics-agent",
			query:      "SELECT id, sku, name, price_cents FROM products",
			shouldPass: true,
		},
		{
			name:       "Allowed select on orders with ORDER BY",
			agentID:    "analytics-agent",
			query:      "SELECT id, customer_id, total_cents FROM orders ORDER BY total_cents DESC",
			shouldPass: true,
		},
		{
			name:       "Allowed select on order_items",
			agentID:    "analytics-agent",
			query:      "SELECT id, order_id, quantity FROM order_items",
			shouldPass: true,
		},
		{
			name:       "Allowed query with explicit low LIMIT",
			agentID:    "analytics-agent",
			query:      "SELECT id, full_name FROM customers LIMIT 10",
			shouldPass: true,
		},
		{
			name:       "Allowed query for support-agent on permitted table",
			agentID:    "support-agent",
			query:      "SELECT id, full_name, email FROM customers WHERE id = 2",
			shouldPass: true,
		},
		{
			name:       "Allowed query for restricted-agent on products",
			agentID:    "restricted-agent",
			query:      "SELECT id, sku, name, price_cents FROM products",
			shouldPass: true,
		},
		{
			name:       "Allowed aggregate COUNT function",
			agentID:    "analytics-agent",
			query:      "SELECT count(id) FROM customers",
			shouldPass: true,
		},
		{
			name:       "Allowed join between allowed tables",
			agentID:    "analytics-agent",
			query:      "SELECT orders.id, orders.total_cents FROM orders JOIN customers ON orders.customer_id = customers.id",
			shouldPass: true,
		},

		// 11-20: Denied DDL, DML & non-SELECT statements
		{
			name:        "Denied INSERT statement",
			agentID:     "analytics-agent",
			query:       "INSERT INTO customers (full_name) VALUES ('Hacker')",
			shouldPass:  false,
			expectedErr: "only read-only SELECT",
		},
		{
			name:        "Denied UPDATE statement",
			agentID:     "analytics-agent",
			query:       "UPDATE customers SET email = 'hacked@example.com'",
			shouldPass:  false,
			expectedErr: "only read-only SELECT",
		},
		{
			name:        "Denied DELETE statement",
			agentID:     "analytics-agent",
			query:       "DELETE FROM customers WHERE id = 1",
			shouldPass:  false,
			expectedErr: "only read-only SELECT",
		},
		{
			name:        "Denied DROP TABLE",
			agentID:     "analytics-agent",
			query:       "DROP TABLE customers",
			shouldPass:  false,
			expectedErr: "only read-only SELECT",
		},
		{
			name:        "Denied ALTER TABLE",
			agentID:     "analytics-agent",
			query:       "ALTER TABLE customers ADD COLUMN malicious TEXT",
			shouldPass:  false,
			expectedErr: "only read-only SELECT",
		},
		{
			name:        "Denied TRUNCATE TABLE",
			agentID:     "analytics-agent",
			query:       "TRUNCATE TABLE customers",
			shouldPass:  false,
			expectedErr: "only read-only SELECT",
		},
		{
			name:        "Denied CREATE TABLE",
			agentID:     "analytics-agent",
			query:       "CREATE TABLE evil (id INT)",
			shouldPass:  false,
			expectedErr: "only read-only SELECT",
		},
		{
			name:        "Denied Multiple Statements with semicolon",
			agentID:     "analytics-agent",
			query:       "SELECT id FROM customers; DROP TABLE orders;",
			shouldPass:  false,
			expectedErr: "multiple SQL statements",
		},
		{
			name:        "Denied Stacking Statements",
			agentID:     "analytics-agent",
			query:       "SELECT id FROM products; SELECT * FROM customers",
			shouldPass:  false,
			expectedErr: "multiple SQL statements",
		},
		{
			name:        "Denied Empty Query",
			agentID:     "analytics-agent",
			query:       "   ",
			shouldPass:  false,
			expectedErr: "query is empty",
		},

		// 21-30: Denied dangerous functions & file I/O
		{
			name:        "Denied INTO OUTFILE exfiltration",
			agentID:     "analytics-agent",
			query:       "SELECT id FROM customers INTO OUTFILE '/tmp/dump.txt'",
			shouldPass:  false,
			expectedErr: "prohibited dangerous function",
		},
		{
			name:        "Denied INTO DUMPFILE",
			agentID:     "analytics-agent",
			query:       "SELECT id FROM customers INTO DUMPFILE '/var/www/shell.php'",
			shouldPass:  false,
			expectedErr: "prohibited dangerous function",
		},
		{
			name:        "Denied LOAD_FILE function",
			agentID:     "analytics-agent",
			query:       "SELECT LOAD_FILE('/etc/passwd') FROM customers",
			shouldPass:  false,
			expectedErr: "prohibited dangerous function",
		},
		{
			name:        "Denied SLEEP time-based injection",
			agentID:     "analytics-agent",
			query:       "SELECT id FROM customers WHERE id = 1 AND SLEEP(5)",
			shouldPass:  false,
			expectedErr: "prohibited dangerous function",
		},
		{
			name:        "Denied BENCHMARK DoS attack",
			agentID:     "analytics-agent",
			query:       "SELECT BENCHMARK(10000000, MD5('test')) FROM customers",
			shouldPass:  false,
			expectedErr: "prohibited dangerous function",
		},
		{
			name:        "Denied GET_LOCK DoS",
			agentID:     "analytics-agent",
			query:       "SELECT GET_LOCK('mcp_lock', 10) FROM customers",
			shouldPass:  false,
			expectedErr: "prohibited dangerous function",
		},
		{
			name:        "Denied FOR UPDATE locking clause",
			agentID:     "analytics-agent",
			query:       "SELECT id FROM customers FOR UPDATE",
			shouldPass:  false,
			expectedErr: "prohibited dangerous function",
		},
		{
			name:        "Denied LOCK IN SHARE MODE",
			agentID:     "analytics-agent",
			query:       "SELECT id FROM customers LOCK IN SHARE MODE",
			shouldPass:  false,
			expectedErr: "prohibited dangerous function",
		},
		{
			name:        "Denied User variable injection (@var)",
			agentID:     "analytics-agent",
			query:       "SELECT id, @evil:=email FROM customers",
			shouldPass:  false,
			expectedErr: "prohibited dangerous function",
		},
		{
			name:        "Denied SQLite ATTACH DATABASE",
			agentID:     "analytics-agent",
			query:       "ATTACH DATABASE '/etc/shadow' AS shadow",
			shouldPass:  false,
			expectedErr: "prohibited dangerous function",
		},

		// 31-42: Denied system tables, unauthorized tables & columns, and SELECT *
		{
			name:        "Denied access to information_schema",
			agentID:     "analytics-agent",
			query:       "SELECT table_name FROM information_schema.tables",
			shouldPass:  false,
			expectedErr: "system catalog",
		},
		{
			name:        "Denied access to mysql system schema",
			agentID:     "analytics-agent",
			query:       "SELECT user, host FROM mysql.user",
			shouldPass:  false,
			expectedErr: "system catalog",
		},
		{
			name:        "Denied access to sqlite_master",
			agentID:     "analytics-agent",
			query:       "SELECT sql FROM sqlite_master",
			shouldPass:  false,
			expectedErr: "system catalog",
		},
		{
			name:        "Denied access to internal agent_keys table",
			agentID:     "analytics-agent",
			query:       "SELECT token_hash FROM agent_keys",
			shouldPass:  false,
			expectedErr: "system catalog",
		},
		{
			name:        "Denied access to internal audit_records table",
			agentID:     "analytics-agent",
			query:       "SELECT record_hash FROM audit_records",
			shouldPass:  false,
			expectedErr: "system catalog",
		},
		{
			name:        "Denied unauthorized table for restricted-agent (customers)",
			agentID:     "restricted-agent",
			query:       "SELECT id FROM customers",
			shouldPass:  false,
			expectedErr: "not authorized to query table",
		},
		{
			name:        "Denied unauthorized table for support-agent (products)",
			agentID:     "support-agent",
			query:       "SELECT id FROM products",
			shouldPass:  false,
			expectedErr: "not authorized to query table",
		},
		{
			name:        "Denied unauthorized column (ssn_last4 for analytics-agent)",
			agentID:     "analytics-agent",
			query:       "SELECT ssn_last4 FROM customers",
			shouldPass:  false,
			expectedErr: "not authorized to select column",
		},
		{
			name:        "Denied unauthorized column for restricted-agent (stock_quantity)",
			agentID:     "restricted-agent",
			query:       "SELECT stock_quantity FROM products",
			shouldPass:  false,
			expectedErr: "not authorized to select column",
		},
		{
			name:        "Denied SELECT * on table with restricted column (customers)",
			agentID:     "analytics-agent",
			query:       "SELECT * FROM customers",
			shouldPass:  false,
			expectedErr: "SELECT * is not permitted on tables with restricted columns",
		},
		{
			name:        "Denied Malformed SQL",
			agentID:     "analytics-agent",
			query:       "SELECT FROM WHERE",
			shouldPass:  false,
			expectedErr: "failed to parse SQL query AST",
		},
		{
			name:        "Denied PRAGMA command",
			agentID:     "analytics-agent",
			query:       "PRAGMA table_info(customers)",
			shouldPass:  false,
			expectedErr: "prohibited dangerous function",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := validator.ValidateAndRewrite(tt.agentID, tt.query)
			if tt.shouldPass {
				if err != nil {
					t.Fatalf("expected query to pass, got error: %v", err)
				}
				if res == nil {
					t.Fatalf("expected non-nil ValidationResult")
				}
				if !strings.Contains(strings.ToUpper(res.RewrittenSQL), "LIMIT") {
					t.Errorf("expected LIMIT to be enforced in rewritten SQL: %s", res.RewrittenSQL)
				}
			} else {
				if err == nil {
					t.Fatalf("expected query to be denied, but it passed: %s", tt.query)
				}
				if tt.expectedErr != "" && !strings.Contains(err.Error(), tt.expectedErr) {
					t.Errorf("expected error containing %q, got: %v", tt.expectedErr, err)
				}
			}
		})
	}
}

func TestLimitRewriting(t *testing.T) {
	pe, err := policy.LoadFromYAML(embedded.ExamplePolicyYAML)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}
	validator := NewValidator(pe)

	// analytics-agent max_rows_per_query is 50
	// 1. Query without LIMIT should have LIMIT 50 injected
	res1, err := validator.ValidateAndRewrite("analytics-agent", "SELECT id, full_name FROM customers")
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if !strings.Contains(res1.RewrittenSQL, "limit 50") && !strings.Contains(res1.RewrittenSQL, "LIMIT 50") {
		t.Errorf("expected 'limit 50' in rewritten SQL, got: %s", res1.RewrittenSQL)
	}

	// 2. Query with excessive LIMIT 1000 should be capped to 50
	res2, err := validator.ValidateAndRewrite("analytics-agent", "SELECT id, full_name FROM customers LIMIT 1000")
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if !strings.Contains(res2.RewrittenSQL, "limit 50") && !strings.Contains(res2.RewrittenSQL, "LIMIT 50") {
		t.Errorf("expected excessive limit to be capped to 50, got: %s", res2.RewrittenSQL)
	}

	// 3. Query with valid small LIMIT 5 should be preserved
	res3, err := validator.ValidateAndRewrite("analytics-agent", "SELECT id, full_name FROM customers LIMIT 5")
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if !strings.Contains(res3.RewrittenSQL, "limit 5") && !strings.Contains(res3.RewrittenSQL, "LIMIT 5") {
		t.Errorf("expected limit 5 to be preserved, got: %s", res3.RewrittenSQL)
	}
}
