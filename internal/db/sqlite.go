package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// SQLiteDB implements the Querier interface backed by pure-Go SQLite.
type SQLiteDB struct {
	db *sql.DB
}

// NewSQLite opens a SQLite database connection with the provided DSN.
func NewSQLite(dsn string) (*SQLiteDB, error) {
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite connection: %w", err)
	}

	if err := conn.Ping(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to ping sqlite database: %w", err)
	}

	return &SQLiteDB{db: conn}, nil
}

// NewInMemorySQLite initializes an ephemeral in-memory SQLite database.
func NewInMemorySQLite() (*SQLiteDB, error) {
	// Use shared cache in memory mode so multiple connections see the same tables
	dsn := "file:demo.db?mode=memory&cache=shared"
	return NewSQLite(dsn)
}

// Driver returns DriverSQLite.
func (s *SQLiteDB) Driver() DriverType {
	return DriverSQLite
}

// Close closes the underlying SQL database handle.
func (s *SQLiteDB) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// RawDB returns the raw *sql.DB instance for running initialization scripts.
func (s *SQLiteDB) RawDB() *sql.DB {
	return s.db
}

// ListTables queries the sqlite_schema for all user-defined tables.
func (s *SQLiteDB) ListTables(ctx context.Context) ([]string, error) {
	const query = `
		SELECT name FROM sqlite_schema 
		WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
		ORDER BY name ASC
	`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list sqlite tables: %w", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("failed to scan table name: %w", err)
		}
		tables = append(tables, name)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite rows iteration error: %w", err)
	}

	return tables, nil
}

// DescribeTable inspects table column schema using PRAGMA table_info.
func (s *SQLiteDB) DescribeTable(ctx context.Context, tableName string) ([]ColumnInfo, error) {
	sanitized := strings.ReplaceAll(tableName, `"`, `""`)
	pragmaQuery := fmt.Sprintf(`PRAGMA table_info("%s")`, sanitized)

	rows, err := s.db.QueryContext(ctx, pragmaQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to query table pragma: %w", err)
	}
	defer rows.Close()

	var columns []ColumnInfo
	for rows.Next() {
		var (
			cid          int
			name         string
			colType      string
			notNull      int
			defaultValue sql.NullString
			pk           int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &defaultValue, &pk); err != nil {
			return nil, fmt.Errorf("failed to scan column pragma: %w", err)
		}
		columns = append(columns, ColumnInfo{
			Name:         name,
			DataType:     colType,
			IsNullable:   notNull == 0,
			IsPrimaryKey: pk > 0,
		})
	}

	if len(columns) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrTableNotFound, tableName)
	}

	return columns, nil
}

// ExecuteQuery executes a read-only SELECT query and captures the tabular result set.
func (s *SQLiteDB) ExecuteQuery(ctx context.Context, query string) (*QueryResult, error) {
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query execution failed: %w", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve query column names: %w", err)
	}

	var results [][]interface{}
	for rows.Next() {
		values := make([]interface{}, len(cols))
		scanPointers := make([]interface{}, len(cols))
		for i := range values {
			scanPointers[i] = &values[i]
		}

		if err := rows.Scan(scanPointers...); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Convert []byte results to string for consistent handling
		rowValues := make([]interface{}, len(cols))
		for i, v := range values {
			if b, ok := v.([]byte); ok {
				rowValues[i] = string(b)
			} else {
				rowValues[i] = v
			}
		}
		results = append(results, rowValues)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration failed: %w", err)
	}

	return &QueryResult{
		Columns:  cols,
		Rows:     results,
		RowCount: len(results),
	}, nil
}
