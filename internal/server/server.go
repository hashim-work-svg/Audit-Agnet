// Package server coordinates the MCP gateway pipeline: authentication, rate limiting, SQL AST validation,
// read-only execution, PII masking, and tamper-evident audit logging.
package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/hashim-work-svg/Audit-Agnet/internal/audit"
	"github.com/hashim-work-svg/Audit-Agnet/internal/auth"
	"github.com/hashim-work-svg/Audit-Agnet/internal/db"
	"github.com/hashim-work-svg/Audit-Agnet/internal/masking"
	"github.com/hashim-work-svg/Audit-Agnet/internal/policy"
	"github.com/hashim-work-svg/Audit-Agnet/internal/ratelimit"
	"github.com/hashim-work-svg/Audit-Agnet/internal/sqlvalidate"
)

var (
	ErrRateLimitExceeded = errors.New("rate limit exceeded: too many queries per minute")
	ErrToolPinMismatch   = errors.New("tool definition integrity verification failed: tool pinning mismatch")
)

// ToolDefinition represents metadata and schema for an exposed MCP tool.
type ToolDefinition struct {
	Name        string
	Description string
	InputSchema string
	PinnedHash  string
}

// Gateway manages end-to-end security pipeline for agent interactions.
type Gateway struct {
	database      db.Querier
	authenticator *auth.Authenticator
	policyEngine  *policy.Engine
	validator     *sqlvalidate.Validator
	masker        *masking.Masker
	logger        *audit.Logger
	limiter       *ratelimit.Limiter
	toolPins      map[string]string
}

// NewGateway constructs a fully wired security gateway.
func NewGateway(
	database db.Querier,
	authenticator *auth.Authenticator,
	pe *policy.Engine,
	validator *sqlvalidate.Validator,
	masker *masking.Masker,
	logger *audit.Logger,
	limiter *ratelimit.Limiter,
) *Gateway {
	gw := &Gateway{
		database:      database,
		authenticator: authenticator,
		policyEngine:  pe,
		validator:     validator,
		masker:        masker,
		logger:        logger,
		limiter:       limiter,
		toolPins:      make(map[string]string),
	}

	// Pin tool definitions at startup
	gw.pinTool("list_tables", "List database tables permitted for the calling agent", "{}")
	gw.pinTool("describe_table", "Describe permitted column schema of an accessible database table", `{"type":"object","properties":{"table":{"type":"string"}}}`)
	gw.pinTool("run_query", "Execute a read-only SQL SELECT query with AST validation, limits, and PII masking", `{"type":"object","properties":{"sql":{"type":"string"}}}`)

	return gw
}

func (gw *Gateway) pinTool(name, desc, schema string) {
	canonical := fmt.Sprintf("%s|%s|%s", name, desc, schema)
	h := sha256.Sum256([]byte(canonical))
	gw.toolPins[name] = hex.EncodeToString(h[:])
}

// VerifyToolPin ensures a tool definition has not been altered at runtime.
func (gw *Gateway) VerifyToolPin(name, desc, schema string) error {
	expected, ok := gw.toolPins[name]
	if !ok {
		return fmt.Errorf("%w: unknown tool %q", ErrToolPinMismatch, name)
	}
	canonical := fmt.Sprintf("%s|%s|%s", name, desc, schema)
	h := sha256.Sum256([]byte(canonical))
	current := hex.EncodeToString(h[:])
	if current != expected {
		return fmt.Errorf("%w for tool %q", ErrToolPinMismatch, name)
	}
	return nil
}

// ListTables executes the `list_tables` tool, returning ONLY tables permitted for the authenticated agent.
func (gw *Gateway) ListTables(ctx context.Context, token string) ([]string, error) {
	agent, err := gw.authenticator.Authenticate(ctx, token)
	if err != nil {
		return nil, err
	}

	if !gw.limiter.Allow(agent.AgentID) {
		return nil, ErrRateLimitExceeded
	}

	allTables, err := gw.database.ListTables(ctx)
	if err != nil {
		return nil, err
	}

	// Filter out internal system tables AND tables not allowed by policy
	var allowed []string
	for _, tbl := range allTables {
		tblLower := strings.ToLower(tbl)
		if tblLower == "agent_keys" || tblLower == "audit_records" || strings.HasPrefix(tblLower, "sqlite_") {
			continue
		}
		if gw.policyEngine.IsTableAllowed(agent.AgentID, tbl) {
			allowed = append(allowed, tbl)
		}
	}

	_, _ = gw.logger.Log(ctx, agent.AgentID, "list_tables", "", "", "ALLOWED", len(allowed))
	return allowed, nil
}

// DescribeTable executes the `describe_table` tool, returning ONLY permitted column schemas.
func (gw *Gateway) DescribeTable(ctx context.Context, token, table string) ([]db.ColumnInfo, error) {
	agent, err := gw.authenticator.Authenticate(ctx, token)
	if err != nil {
		return nil, err
	}

	if !gw.limiter.Allow(agent.AgentID) {
		return nil, ErrRateLimitExceeded
	}

	if !gw.policyEngine.IsTableAllowed(agent.AgentID, table) {
		_, _ = gw.logger.Log(ctx, agent.AgentID, "describe_table", table, "", "DENIED", 0)
		return nil, fmt.Errorf("agent %q is not authorized to access table %q", agent.AgentID, table)
	}

	allCols, err := gw.database.DescribeTable(ctx, table)
	if err != nil {
		return nil, err
	}

	var allowedCols []db.ColumnInfo
	for _, c := range allCols {
		if gw.policyEngine.IsColumnAllowed(agent.AgentID, table, c.Name) {
			allowedCols = append(allowedCols, c)
		}
	}

	_, _ = gw.logger.Log(ctx, agent.AgentID, "describe_table", table, "", "ALLOWED", len(allowedCols))
	return allowedCols, nil
}

// QueryResult holds sanitized rows and execution metadata.
type QueryResult struct {
	AgentID      string
	OriginalSQL  string
	RewrittenSQL string
	RowCount     int
	Rows         []map[string]interface{}
}

// RunQuery executes the `run_query` tool: validates AST, enforces LIMIT, executes, masks PII, and logs audit record.
func (gw *Gateway) RunQuery(ctx context.Context, token, sqlQuery string) (*QueryResult, error) {
	agent, err := gw.authenticator.Authenticate(ctx, token)
	if err != nil {
		return nil, err
	}

	if !gw.limiter.Allow(agent.AgentID) {
		_, _ = gw.logger.Log(ctx, agent.AgentID, "run_query", sqlQuery, "", "DENIED_RATELIMIT", 0)
		return nil, ErrRateLimitExceeded
	}

	// 1. AST Validation and Limit Injection
	valRes, err := gw.validator.ValidateAndRewrite(agent.AgentID, sqlQuery)
	if err != nil {
		_, _ = gw.logger.Log(ctx, agent.AgentID, "run_query", sqlQuery, "", "DENIED", 0)
		return nil, fmt.Errorf("security policy violation: %w", err)
	}

	// 2. Execute on database
	rawRows, err := gw.database.ExecuteQuery(ctx, valRes.RewrittenSQL)
	if err != nil {
		_, _ = gw.logger.Log(ctx, agent.AgentID, "run_query", sqlQuery, valRes.RewrittenSQL, "ERROR", 0)
		return nil, fmt.Errorf("query execution failed: %w", err)
	}

	// 3. PII Masking
	primaryTable := ""
	if len(valRes.Tables) > 0 {
		primaryTable = valRes.Tables[0]
	}

	maskedRows := make([]map[string]interface{}, len(rawRows.Rows))
	for i, rowVals := range rawRows.Rows {
		rowMap := make(map[string]interface{}, len(rawRows.Columns))
		for colIdx, colName := range rawRows.Columns {
			if colIdx < len(rowVals) {
				rowMap[colName] = rowVals[colIdx]
			}
		}
		maskedRows[i] = gw.masker.MaskRow(agent.AgentID, primaryTable, rowMap)
	}

	// 4. Log successful audited execution
	decision := "ALLOWED"
	if len(valRes.Columns) > 0 {
		for _, col := range valRes.Columns {
			if gw.policyEngine.GetMaskingRule(agent.AgentID, primaryTable, col) != "" {
				decision = "MASKED"
				break
			}
		}
	}

	_, err = gw.logger.Log(ctx, agent.AgentID, "run_query", sqlQuery, valRes.RewrittenSQL, decision, len(maskedRows))
	if err != nil {
		return nil, fmt.Errorf("failed appending audit record: %w", err)
	}

	return &QueryResult{
		AgentID:      agent.AgentID,
		OriginalSQL:  sqlQuery,
		RewrittenSQL: valRes.RewrittenSQL,
		RowCount:     len(maskedRows),
		Rows:         maskedRows,
	}, nil
}
