// Package audit implements append-only, tamper-evident hash-chained audit logging.
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"
)

var (
	ErrTamperedChain = errors.New("audit log verification failed: hash chain tampering detected")
	ErrInvalidRecord = errors.New("audit log verification failed: record hash mismatch")
)

const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Record represents an audited agent interaction record.
type Record struct {
	ID           int
	Timestamp    string
	AgentID      string
	ToolName     string
	OriginalSQL  string
	RewrittenSQL string
	Decision     string
	RowCount     int
	PrevHash     string
	RecordHash   string
}

// Logger writes and verifies cryptographic audit records in the database.
type Logger struct {
	db     *sql.DB
	secret []byte
}

// NewLogger creates an audit Logger backed by a database handle and optional HMAC secret.
func NewLogger(db *sql.DB, secret string) *Logger {
	if secret == "" {
		secret = "mcp-guard-audit-integrity-secret-2026"
	}
	return &Logger{
		db:     db,
		secret: []byte(secret),
	}
}

// Log writes an audit event to the append-only database table with cryptographic chaining.
func (l *Logger) Log(ctx context.Context, agentID, tool, originalSQL, rewrittenSQL, decision string, rowCount int) (*Record, error) {
	// 1. Get the latest record hash to chain from
	prevHash, err := l.getLatestRecordHash(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed fetching latest audit hash: %w", err)
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)

	rec := Record{
		Timestamp:    timestamp,
		AgentID:      agentID,
		ToolName:     tool,
		OriginalSQL:  originalSQL,
		RewrittenSQL: rewrittenSQL,
		Decision:     decision,
		RowCount:     rowCount,
		PrevHash:     prevHash,
	}

	// 2. Compute canonical cryptographic hash
	rec.RecordHash = l.ComputeRecordHash(rec)

	// 3. Insert record into database
	query := `INSERT INTO audit_records 
		(timestamp, agent_id, tool_name, original_sql, rewritten_sql, decision, row_count, prev_hash, record_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	res, err := l.db.ExecContext(ctx, query,
		rec.Timestamp, rec.AgentID, rec.ToolName, rec.OriginalSQL, rec.RewrittenSQL,
		rec.Decision, rec.RowCount, rec.PrevHash, rec.RecordHash,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert audit record: %w", err)
	}

	id, err := res.LastInsertId()
	if err == nil {
		rec.ID = int(id)
	}

	return &rec, nil
}

// ComputeRecordHash generates the keyed HMAC-SHA256 hash across ALL record fields.
func (l *Logger) ComputeRecordHash(r Record) string {
	// Canonical pipe-delimited payload protecting all fields from tampering
	canonical := fmt.Sprintf("audit_v1|%s|%s|%s|%s|%s|%s|%s|%s",
		r.Timestamp,
		r.AgentID,
		r.ToolName,
		r.OriginalSQL,
		r.RewrittenSQL,
		r.Decision,
		strconv.Itoa(r.RowCount),
		r.PrevHash,
	)

	mac := hmac.New(sha256.New, l.secret)
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyAuditChain traverses all historical audit records in order and validates hash chain integrity.
func (l *Logger) VerifyAuditChain(ctx context.Context) (int, error) {
	query := `SELECT id, timestamp, agent_id, tool_name, original_sql, rewritten_sql, decision, row_count, prev_hash, record_hash 
		FROM audit_records ORDER BY id ASC`

	rows, err := l.db.QueryContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed querying audit records: %w", err)
	}
	defer rows.Close()

	expectedPrevHash := GenesisHash
	verifiedCount := 0

	for rows.Next() {
		var r Record
		err := rows.Scan(
			&r.ID, &r.Timestamp, &r.AgentID, &r.ToolName, &r.OriginalSQL, &r.RewrittenSQL,
			&r.Decision, &r.RowCount, &r.PrevHash, &r.RecordHash,
		)
		if err != nil {
			return verifiedCount, fmt.Errorf("failed scanning audit record: %w", err)
		}

		// 1. Verify that PrevHash connects to preceding record's RecordHash
		if r.PrevHash != expectedPrevHash {
			return verifiedCount, fmt.Errorf("%w: record ID %d prev_hash [%s] does not match expected [%s]",
				ErrTamperedChain, r.ID, r.PrevHash, expectedPrevHash)
		}

		// 2. Re-compute RecordHash and verify authenticity of all record fields
		expectedHash := l.ComputeRecordHash(r)
		if r.RecordHash != expectedHash {
			return verifiedCount, fmt.Errorf("%w: record ID %d payload modified; stored [%s] != recomputed [%s]",
				ErrInvalidRecord, r.ID, r.RecordHash, expectedHash)
		}

		expectedPrevHash = r.RecordHash
		verifiedCount++
	}

	return verifiedCount, rows.Err()
}

func (l *Logger) getLatestRecordHash(ctx context.Context) (string, error) {
	var latestHash string
	query := `SELECT record_hash FROM audit_records ORDER BY id DESC LIMIT 1`
	err := l.db.QueryRowContext(ctx, query).Scan(&latestHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GenesisHash, nil
		}
		return "", err
	}
	return latestHash, nil
}
