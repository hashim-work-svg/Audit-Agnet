package db

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
)

// MySQLDB implements the Querier interface backed by MySQL 8.
type MySQLDB struct {
	db     *sql.DB
	dbName string
}

// NewMySQL opens a MySQL database connection using the provided DSN and target database.
func NewMySQL(dsn string, dbName string) (*MySQLDB, error) {
	conn, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open mysql connection: %w", err)
	}

	if err := conn.Ping(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to ping mysql database: %w", err)
	}

	return &MySQLDB{
		db:     conn,
		dbName: dbName,
	}, nil
}

// Driver returns DriverMySQL.
func (m *MySQLDB) Driver() DriverType {
	return DriverMySQL
}

// Close terminates the MySQL connection pool.
func (m *MySQLDB) Close() error {
	if m.db == nil {
		return nil
	}
	return m.db.Close()
}

// RawDB returns the raw *sql.DB instance.
func (m *MySQLDB) RawDB() *sql.DB {
	return m.db
}

// ListTables retrieves table names from information_schema.tables for the configured database.
func (m *MySQLDB) ListTables(ctx context.Context) ([]string, error) {
	const query = `
		SELECT table_name 
		FROM information_schema.tables 
		WHERE table_schema = ? AND table_type = 'BASE TABLE'
		ORDER BY table_name ASC
	`
	rows, err := m.db.QueryContext(ctx, query, m.dbName)
	if err != nil {
		return nil, fmt.Errorf("failed to list mysql tables: %w", err)
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
		return nil, fmt.Errorf("mysql table row iteration error: %w", err)
	}

	return tables, nil
}

// DescribeTable retrieves column schemas from information_schema.columns.
func (m *MySQLDB) DescribeTable(ctx context.Context, tableName string) ([]ColumnInfo, error) {
	const query = `
		SELECT column_name, data_type, is_nullable, column_key
		FROM information_schema.columns
		WHERE table_schema = ? AND table_name = ?
		ORDER BY ordinal_position ASC
	`
	rows, err := m.db.QueryContext(ctx, query, m.dbName, tableName)
	if err != nil {
		return nil, fmt.Errorf("failed to describe mysql table: %w", err)
	}
	defer rows.Close()

	var columns []ColumnInfo
	for rows.Next() {
		var (
			name       string
			colType    string
			isNullable string
			colKey     string
		)
		if err := rows.Scan(&name, &colType, &isNullable, &colKey); err != nil {
			return nil, fmt.Errorf("failed to scan mysql column: %w", err)
		}
		columns = append(columns, ColumnInfo{
			Name:         name,
			DataType:     colType,
			IsNullable:   isNullable == "YES",
			IsPrimaryKey: colKey == "PRI",
		})
	}

	if len(columns) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrTableNotFound, tableName)
	}

	return columns, nil
}

// ExecuteQuery executes a read-only query on MySQL and returns the tabular result set.
func (m *MySQLDB) ExecuteQuery(ctx context.Context, query string) (*QueryResult, error) {
	rows, err := m.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("mysql query execution failed: %w", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to get column names: %w", err)
	}

	var results [][]interface{}
	for rows.Next() {
		values := make([]interface{}, len(cols))
		scanPointers := make([]interface{}, len(cols))
		for i := range values {
			scanPointers[i] = &values[i]
		}

		if err := rows.Scan(scanPointers...); err != nil {
			return nil, fmt.Errorf("failed to scan mysql row: %w", err)
		}

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
		return nil, fmt.Errorf("mysql rows iteration failed: %w", err)
	}

	return &QueryResult{
		Columns:  cols,
		Rows:     results,
		RowCount: len(results),
	}, nil
}
