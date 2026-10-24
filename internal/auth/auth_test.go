package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/hashim-work-svg/Audit-Agnet/internal/demo"
)

func TestAuthenticate(t *testing.T) {
	sqliteDB, err := demo.InitDemoDB()
	if err != nil {
		t.Fatalf("InitDemoDB failed: %v", err)
	}
	defer sqliteDB.Close()

	authenticator := NewAuthenticator(sqliteDB.RawDB())
	ctx := context.Background()

	// 1. Valid token for analytics-agent
	info, err := authenticator.Authenticate(ctx, "demo-token-analytics")
	if err != nil {
		t.Fatalf("expected valid auth for analytics-agent, got: %v", err)
	}
	if info.AgentID != "analytics-agent" {
		t.Errorf("expected agent_id 'analytics-agent', got %q", info.AgentID)
	}

	// 2. Valid token with "Bearer " prefix
	infoBearer, err := authenticator.Authenticate(ctx, "Bearer demo-token-support")
	if err != nil {
		t.Fatalf("expected valid auth with Bearer prefix, got: %v", err)
	}
	if infoBearer.AgentID != "support-agent" {
		t.Errorf("expected agent_id 'support-agent', got %q", infoBearer.AgentID)
	}

	// 3. Revoked token
	_, err = authenticator.Authenticate(ctx, "demo-token-revoked")
	if err == nil || !errors.Is(err, ErrRevokedToken) {
		t.Errorf("expected ErrRevokedToken, got: %v", err)
	}

	// 4. Unknown token
	_, err = authenticator.Authenticate(ctx, "invalid-random-token")
	if err == nil || !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got: %v", err)
	}

	// 5. Empty token
	_, err = authenticator.Authenticate(ctx, "")
	if err == nil || !errors.Is(err, ErrMissingToken) {
		t.Errorf("expected ErrMissingToken, got: %v", err)
	}
}
