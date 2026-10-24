package policy

import (
	"testing"

	"github.com/hashim-work-svg/Audit-Agnet/embedded"
)

func TestPolicyEngine(t *testing.T) {
	engine, err := LoadFromYAML(embedded.ExamplePolicyYAML)
	if err != nil {
		t.Fatalf("failed to load embedded policy YAML: %v", err)
	}

	// 1. Check analytics-agent allowed tables
	if !engine.IsTableAllowed("analytics-agent", "customers") {
		t.Errorf("expected customers table to be allowed for analytics-agent")
	}
	if !engine.IsTableAllowed("analytics-agent", "orders") {
		t.Errorf("expected orders table to be allowed for analytics-agent")
	}

	// 2. Check restricted table for restricted-agent
	if engine.IsTableAllowed("restricted-agent", "customers") {
		t.Errorf("customers table must NOT be allowed for restricted-agent")
	}
	if !engine.IsTableAllowed("restricted-agent", "products") {
		t.Errorf("products table should be allowed for restricted-agent")
	}

	// 3. Check column permissions
	// analytics-agent has ssn_last4 omitted from allowed_columns
	if engine.IsColumnAllowed("analytics-agent", "customers", "ssn_last4") {
		t.Errorf("ssn_last4 should NOT be allowed for analytics-agent")
	}
	if !engine.IsColumnAllowed("analytics-agent", "customers", "email") {
		t.Errorf("email should be allowed for analytics-agent")
	}

	// 4. Check masking rules
	rule := engine.GetMaskingRule("analytics-agent", "customers", "email")
	if rule != "partial" {
		t.Errorf("expected email masking rule 'partial', got %q", rule)
	}
	rule = engine.GetMaskingRule("analytics-agent", "customers", "phone")
	if rule != "redact" {
		t.Errorf("expected phone masking rule 'redact', got %q", rule)
	}

	// 5. Unknown agent
	_, err = engine.GetAgentPolicy("unknown-agent")
	if err == nil {
		t.Errorf("expected error for unknown agent, got nil")
	}
}
