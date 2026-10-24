// Package auth provides bearer token authentication and agent credential verification.
package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrMissingToken = errors.New("authentication failed: missing bearer token")
	ErrInvalidToken = errors.New("authentication failed: invalid or unknown bearer token")
	ErrRevokedToken = errors.New("authentication failed: agent token has been revoked")
)

// AgentInfo holds authenticated agent identity and access state.
type AgentInfo struct {
	AgentID     string
	Description string
	IsRevoked   bool
}

// Authenticator handles agent credential verification against token hashes.
type Authenticator struct {
	db *sql.DB
}

// NewAuthenticator creates an Authenticator backed by a database handle.
func NewAuthenticator(db *sql.DB) *Authenticator {
	return &Authenticator{db: db}
}

// HashToken calculates the standard SHA-256 hex digest of a bearer token.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// Authenticate validates a bearer token against stored agent_keys.
func (a *Authenticator) Authenticate(ctx context.Context, token string) (*AgentInfo, error) {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return nil, ErrMissingToken
	}

	// Remove optional "Bearer " prefix if present
	if strings.HasPrefix(strings.ToLower(trimmed), "bearer ") {
		trimmed = strings.TrimSpace(trimmed[7:])
	}

	tokenHash := HashToken(trimmed)

	var agentID, desc string
	var revoked int
	query := `SELECT agent_id, description, revoked FROM agent_keys WHERE token_hash = ?`
	err := a.db.QueryRowContext(ctx, query, tokenHash).Scan(&agentID, &desc, &revoked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("auth query failed: %w", err)
	}

	if revoked != 0 {
		return nil, fmt.Errorf("%w for agent %q", ErrRevokedToken, agentID)
	}

	return &AgentInfo{
		AgentID:     agentID,
		Description: desc,
		IsRevoked:   false,
	}, nil
}
