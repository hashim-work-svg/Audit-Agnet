package db

import (
	"context"
	"os"
	"testing"
)

func TestMySQLIntegration(t *testing.T) {
	if os.Getenv("RUN_MYSQL_INTEGRATION") != "true" {
		t.Skip("skipping MySQL integration test; RUN_MYSQL_INTEGRATION not set to 'true'")
	}

	dsn := os.Getenv("MYSQL_TEST_DSN")
	if dsn == "" {
		t.Fatal("RUN_MYSQL_INTEGRATION is 'true' but MYSQL_TEST_DSN is not provided")
	}

	mysqlDB, err := NewMySQL(dsn, "mcp_guard_test")
	if err != nil {
		t.Fatalf("failed to connect to MySQL: %v", err)
	}
	defer mysqlDB.Close()

	ctx := context.Background()

	// 1. Test ListTables
	tables, err := mysqlDB.ListTables(ctx)
	if err != nil {
		t.Fatalf("MySQL ListTables failed: %v", err)
	}
	if len(tables) == 0 {
		t.Fatalf("expected tables in MySQL test database, got 0")
	}

	// 2. Test DescribeTable
	cols, err := mysqlDB.DescribeTable(ctx, "customers")
	if err != nil {
		t.Fatalf("MySQL DescribeTable failed: %v", err)
	}
	if len(cols) == 0 {
		t.Errorf("expected customer columns in MySQL, got 0")
	}

	// 3. Test ExecuteQuery
	res, err := mysqlDB.ExecuteQuery(ctx, "SELECT id, full_name, email FROM customers LIMIT 5")
	if err != nil {
		t.Fatalf("MySQL ExecuteQuery failed: %v", err)
	}
	if res.RowCount == 0 {
		t.Errorf("expected seeded customer rows in MySQL, got 0")
	}
}
