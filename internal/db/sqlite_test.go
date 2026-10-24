package db

import (
	"context"
	"errors"
	"testing"
)

func TestSQLiteQuerier(t *testing.T) {
	ctx := context.Background()
	database, err := NewInMemorySQLite()
	if err != nil {
		t.Fatalf("expected NewInMemorySQLite to succeed, got: %v", err)
	}
	defer database.Close()

	if database.Driver() != DriverSQLite {
		t.Fatalf("expected driver %s, got %s", DriverSQLite, database.Driver())
	}

	// Create test table
	createSQL := `
		CREATE TABLE test_users (
			id INTEGER PRIMARY KEY,
			username VARCHAR(50) NOT NULL,
			email VARCHAR(100),
			active INTEGER DEFAULT 1
		);
	`
	if _, err := database.RawDB().ExecContext(ctx, createSQL); err != nil {
		t.Fatalf("failed to create test table: %v", err)
	}

	// Test ListTables
	t.Run("ListTables", func(t *testing.T) {
		tables, err := database.ListTables(ctx)
		if err != nil {
			t.Fatalf("ListTables failed: %v", err)
		}
		found := false
		for _, tbl := range tables {
			if tbl == "test_users" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected test_users in tables list, got: %v", tables)
		}
	})

	// Test DescribeTable
	t.Run("DescribeTable", func(t *testing.T) {
		cols, err := database.DescribeTable(ctx, "test_users")
		if err != nil {
			t.Fatalf("DescribeTable failed: %v", err)
		}
		if len(cols) != 4 {
			t.Fatalf("expected 4 columns, got %d", len(cols))
		}
		colMap := make(map[string]ColumnInfo)
		for _, col := range cols {
			colMap[col.Name] = col
		}

		if !colMap["id"].IsPrimaryKey {
			t.Errorf("expected id to be primary key")
		}
		if colMap["username"].IsNullable {
			t.Errorf("expected username to not be nullable")
		}
		if !colMap["email"].IsNullable {
			t.Errorf("expected email to be nullable")
		}
	})

	// Test DescribeTable with non-existent table
	t.Run("DescribeTableNotFound", func(t *testing.T) {
		_, err := database.DescribeTable(ctx, "non_existent_table")
		if err == nil {
			t.Fatal("expected error for non-existent table, got nil")
		}
		if !errors.Is(err, ErrTableNotFound) {
			t.Errorf("expected ErrTableNotFound, got: %v", err)
		}
	})

	// Test ExecuteQuery
	t.Run("ExecuteQuery", func(t *testing.T) {
		insertSQL := `
			INSERT INTO test_users (id, username, email, active) 
			VALUES (1, 'agent01', 'agent@example.com', 1);
		`
		if _, err := database.RawDB().ExecContext(ctx, insertSQL); err != nil {
			t.Fatalf("failed to insert test record: %v", err)
		}

		query := "SELECT id, username, email FROM test_users WHERE id = 1"
		result, err := database.ExecuteQuery(ctx, query)
		if err != nil {
			t.Fatalf("ExecuteQuery failed: %v", err)
		}
		if result.RowCount != 1 {
			t.Fatalf("expected 1 row, got %d", result.RowCount)
		}
		if len(result.Columns) != 3 {
			t.Fatalf("expected 3 columns, got %d", len(result.Columns))
		}
		if result.Rows[0][1] != "agent01" {
			t.Errorf("expected username 'agent01', got %v", result.Rows[0][1])
		}
	})
}
