// Package db provides database abstraction interfaces and driver implementations
// for read-only query execution across SQLite and MySQL engines.
package db

import (
	"context"
	"fmt"
)

// ColumnInfo describes a database table column and its metadata.
type ColumnInfo struct {
	Name         string `json:"name"`
	DataType     string `json:"data_type"`
	IsNullable   bool   `json:"is_nullable"`
	IsPrimaryKey bool   `json:"is_primary_key"`
}

// QueryResult represents the executed tabular results from a SELECT statement.
type QueryResult struct {
	Columns  []string        `json:"columns"`
	Rows     [][]interface{} `json:"rows"`
	RowCount int             `json:"row_count"`
}

// DriverType indicates the underlying database dialect.
type DriverType string

const (
	// DriverSQLite indicates an embedded SQLite database.
	DriverSQLite DriverType = "sqlite"
	// DriverMySQL indicates a MySQL 8.0 database.
	DriverMySQL DriverType = "mysql"
)

// Querier is the primary interface for executing read-only database inspections and queries.
type Querier interface {
	// ListTables returns all user table names in the database.
	ListTables(ctx context.Context) ([]string, error)

	// DescribeTable returns column definitions for a given table.
	DescribeTable(ctx context.Context, tableName string) ([]ColumnInfo, error)

	// ExecuteQuery executes a validated read-only SQL query and returns rows.
	ExecuteQuery(ctx context.Context, query string) (*QueryResult, error)

	// Driver returns the underlying driver type.
	Driver() DriverType

	// Close terminates the underlying database connections.
	Close() error
}

// ErrTableNotFound is returned when inspecting a non-existent table.
var ErrTableNotFound = fmt.Errorf("table not found")
