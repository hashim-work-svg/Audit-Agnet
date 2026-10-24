// Package demo provides embedded database bootstrapping for zero-install demonstrations.
package demo

import (
	"context"
	"fmt"
	"strings"

	"github.com/muhammad-hashim/mcp-guard/embedded"
	"github.com/muhammad-hashim/mcp-guard/internal/db"
)

// InitDemoDB initializes an in-memory SQLite database populated with embedded schema and synthetic seed data.
func InitDemoDB() (*db.SQLiteDB, error) {
	sqliteDB, err := db.NewInMemorySQLite()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize in-memory sqlite demo database: %w", err)
	}

	ctx := context.Background()

	// Execute DDL schema
	if err := executeScript(ctx, sqliteDB, embedded.SchemaSQL); err != nil {
		_ = sqliteDB.Close()
		return nil, fmt.Errorf("failed to apply embedded schema: %w", err)
	}

	// Execute synthetic seed data
	if err := executeScript(ctx, sqliteDB, embedded.SeedSQL); err != nil {
		_ = sqliteDB.Close()
		return nil, fmt.Errorf("failed to apply embedded seed data: %w", err)
	}

	return sqliteDB, nil
}

// executeScript parses and executes a multi-statement SQL script.
func executeScript(ctx context.Context, database *db.SQLiteDB, script string) error {
	raw := database.RawDB()
	statements := splitSQLStatements(script)

	for _, stmt := range statements {
		trimmed := strings.TrimSpace(stmt)
		if trimmed == "" {
			continue
		}
		if _, err := raw.ExecContext(ctx, trimmed); err != nil {
			return fmt.Errorf("failed executing statement [%s]: %w", truncateForLog(trimmed, 60), err)
		}
	}
	return nil
}

// splitSQLStatements splits a SQL string into individual executable statements while ignoring comments.
func splitSQLStatements(sqlText string) []string {
	var statements []string
	var current strings.Builder

	lines := strings.Split(sqlText, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip full comment lines
		if strings.HasPrefix(trimmed, "--") {
			continue
		}
		current.WriteString(line)
		current.WriteString("\n")

		if strings.HasSuffix(trimmed, ";") {
			statements = append(statements, current.String())
			current.Reset()
		}
	}

	if current.Len() > 0 {
		remainder := strings.TrimSpace(current.String())
		if remainder != "" {
			statements = append(statements, remainder)
		}
	}

	return statements
}

// truncateForLog shortens long SQL strings for error messages.
func truncateForLog(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
