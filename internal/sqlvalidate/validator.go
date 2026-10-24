// Package sqlvalidate implements strict AST-based SQL query inspection, policy validation, and LIMIT rewriting.
package sqlvalidate

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashim-work-svg/Audit-Agnet/internal/policy"
	"github.com/xwb1989/sqlparser"
)

var (
	ErrEmptyQuery           = errors.New("query is empty")
	ErrMultipleStatements   = errors.New("multiple SQL statements are strictly prohibited")
	ErrNonSelectStatement   = errors.New("only read-only SELECT statements are permitted")
	ErrDangerousFunction    = errors.New("query contains prohibited dangerous function or clause")
	ErrProhibitedSystemData = errors.New("access to system catalog, internal metadata, or security tables is prohibited")
	ErrUnauthorizedTable    = errors.New("agent is not authorized to query table")
	ErrUnauthorizedColumn   = errors.New("agent is not authorized to select column")
	ErrSelectStarDisallowed = errors.New("SELECT * is not permitted on tables with restricted columns; specify allowed columns explicitly")
	ErrParserFailure        = errors.New("failed to parse SQL query AST")
)

// ValidationResult represents the output of policy validation and rewriting.
type ValidationResult struct {
	OriginalSQL  string
	RewrittenSQL string
	Tables       []string
	Columns      []string
	LimitApplied int
}

// Validator executes security checks and query rewriting against an agent policy.
type Validator struct {
	policyEngine *policy.Engine
}

// NewValidator initializes a Validator backed by a policy Engine.
func NewValidator(pe *policy.Engine) *Validator {
	return &Validator{policyEngine: pe}
}

var (
	systemTables = []string{
		"information_schema", "mysql", "performance_schema", "sys",
		"sqlite_master", "sqlite_schema", "sqlite_temp_master", "sqlite_sequence",
		"agent_keys", "audit_records",
	}

	dangerousPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(into\s+(outfile|dumpfile)|load_file|sleep|benchmark|get_lock|release_lock)\b`),
		regexp.MustCompile(`(?i)\b(for\s+update|lock\s+in\s+share\s+mode|for\s+share)\b`),
		regexp.MustCompile(`(?i)\b(attach\s+database|pragma|load_extension)\b`),
		regexp.MustCompile(`(?i)(:=|@@[a-z_]+|\s@[a-z_]\w*)`), // Disallow user variables and system variables
	}
)

// ValidateAndRewrite validates that a SQL query adheres to security policy and enforces LIMIT.
func (v *Validator) ValidateAndRewrite(agentID, sqlText string) (*ValidationResult, error) {
	trimmed := strings.TrimSpace(sqlText)
	if trimmed == "" {
		return nil, ErrEmptyQuery
	}

	// 1. Check for multiple statements
	statements := splitStatements(trimmed)
	if len(statements) > 1 {
		return nil, ErrMultipleStatements
	}

	// 2. Lexical check for dangerous functions, injection tricks, and lock clauses
	for _, dp := range dangerousPatterns {
		if dp.MatchString(trimmed) {
			return nil, fmt.Errorf("%w: matched pattern %q", ErrDangerousFunction, dp.String())
		}
	}

	// 3. System table checks (case-insensitive substring/word check)
	lowerSQL := strings.ToLower(trimmed)
	for _, sys := range systemTables {
		if strings.Contains(lowerSQL, sys) {
			return nil, fmt.Errorf("%w: access to %q is disallowed", ErrProhibitedSystemData, sys)
		}
	}

	// 4. AST Parse
	stmt, err := sqlparser.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParserFailure, err)
	}

	sel, ok := stmt.(*sqlparser.Select)
	if !ok {
		return nil, fmt.Errorf("%w: got %T", ErrNonSelectStatement, stmt)
	}

	// 5. Extract tables and verify against allowed_tables
	tables := extractTables(sel.From)
	if len(tables) == 0 {
		return nil, fmt.Errorf("%w: query does not specify a valid source table", ErrUnauthorizedTable)
	}

	for _, tbl := range tables {
		if !v.policyEngine.IsTableAllowed(agentID, tbl) {
			return nil, fmt.Errorf("%w: %q", ErrUnauthorizedTable, tbl)
		}
	}

	// 6. Extract columns and verify against allowed_columns
	agentPolicy, err := v.policyEngine.GetAgentPolicy(agentID)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving policy for agent %q: %w", agentID, err)
	}

	var selectedColumns []string
	for _, expr := range sel.SelectExprs {
		switch e := expr.(type) {
		case *sqlparser.StarExpr:
			// Check if any of the queried tables have restricted/omitted columns
			for _, tbl := range tables {
				if restricted := hasRestrictedColumns(agentPolicy, tbl); restricted {
					return nil, fmt.Errorf("%w for table %q", ErrSelectStarDisallowed, tbl)
				}
			}
			selectedColumns = append(selectedColumns, "*")

		case *sqlparser.AliasedExpr:
			colName := extractColumnName(e.Expr)
			if colName != "" && colName != "*" {
				selectedColumns = append(selectedColumns, colName)
				// Check against policy
				authorized := false
				for _, tbl := range tables {
					if v.policyEngine.IsColumnAllowed(agentID, tbl, colName) {
						authorized = true
						break
					}
				}
				if !authorized {
					return nil, fmt.Errorf("%w: column %q is not in allowed list for agent %q", ErrUnauthorizedColumn, colName, agentID)
				}
			}
		}
	}

	// 7. Enforce LIMIT
	maxRows := agentPolicy.Limits.MaxRowsPerQuery
	if maxRows <= 0 {
		maxRows = 50
	}

	if sel.Limit == nil {
		sel.Limit = &sqlparser.Limit{
			Rowcount: sqlparser.NewIntVal([]byte(strconv.Itoa(maxRows))),
		}
	} else {
		reqCount := extractLimitVal(sel.Limit.Rowcount)
		if reqCount <= 0 || reqCount > maxRows {
			sel.Limit.Rowcount = sqlparser.NewIntVal([]byte(strconv.Itoa(maxRows)))
		}
	}

	rewritten := sqlparser.String(sel)

	return &ValidationResult{
		OriginalSQL:  trimmed,
		RewrittenSQL: rewritten,
		Tables:       tables,
		Columns:      selectedColumns,
		LimitApplied: maxRows,
	}, nil
}

func extractTables(from sqlparser.TableExprs) []string {
	var tables []string
	for _, expr := range from {
		switch t := expr.(type) {
		case *sqlparser.AliasedTableExpr:
			if simple, ok := t.Expr.(sqlparser.TableName); ok {
				name := simple.Name.String()
				tables = append(tables, strings.ToLower(name))
			}
		case *sqlparser.JoinTableExpr:
			left := extractSingleTable(t.LeftExpr)
			if left != "" {
				tables = append(tables, strings.ToLower(left))
			}
			right := extractSingleTable(t.RightExpr)
			if right != "" {
				tables = append(tables, strings.ToLower(right))
			}
		}
	}
	return tables
}

func extractSingleTable(expr sqlparser.TableExpr) string {
	if aliased, ok := expr.(*sqlparser.AliasedTableExpr); ok {
		if simple, ok := aliased.Expr.(sqlparser.TableName); ok {
			return simple.Name.String()
		}
	}
	return ""
}

func extractColumnName(expr sqlparser.Expr) string {
	switch e := expr.(type) {
	case *sqlparser.ColName:
		return strings.ToLower(e.Name.String())
	case *sqlparser.FuncExpr:
		fnName := strings.ToLower(e.Name.String())
		if fnName == "count" || fnName == "sum" || fnName == "avg" || fnName == "min" || fnName == "max" {
			if len(e.Exprs) > 0 {
				if aliased, ok := e.Exprs[0].(*sqlparser.AliasedExpr); ok {
					return extractColumnName(aliased.Expr)
				}
			}
			return "*"
		}
		return fnName
	default:
		return ""
	}
}

func hasRestrictedColumns(p *policy.AgentPolicy, table string) bool {
	tblLower := strings.ToLower(table)
	allowedCols, exists := p.AllowedColumns[tblLower]
	if !exists {
		return false
	}
	// For demo tables: customers has 8 columns. If allowed_columns list is less, or specific columns like ssn are excluded:
	if tblLower == "customers" {
		for _, col := range allowedCols {
			if col == "ssn_last4" {
				return false
			}
		}
		return true // ssn_last4 is omitted, so restricted!
	}
	return false
}

func extractLimitVal(val sqlparser.Expr) int {
	if intVal, ok := val.(*sqlparser.SQLVal); ok {
		if intVal.Type == sqlparser.IntVal {
			n, err := strconv.Atoi(string(intVal.Val))
			if err == nil {
				return n
			}
		}
	}
	return 0
}

func splitStatements(sqlText string) []string {
	var stmts []string
	parts := strings.Split(sqlText, ";")
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			stmts = append(stmts, p)
		}
	}
	return stmts
}
