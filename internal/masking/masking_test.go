package masking

import (
	"strings"
	"testing"

	"github.com/hashim-work-svg/Audit-Agnet/embedded"
	"github.com/hashim-work-svg/Audit-Agnet/internal/policy"
)

func TestMasking(t *testing.T) {
	pe, err := policy.LoadFromYAML(embedded.ExamplePolicyYAML)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	masker := NewMasker(pe, "test-secret-salt")

	// 1. Test analytics-agent on customers
	// email: partial, phone: redact, credit_card_last4: hash
	row := map[string]interface{}{
		"id":                1,
		"full_name":         "Alice Vance",
		"email":             "alice.vance@example.corp",
		"phone":             "+1-555-0101",
		"credit_card_last4": "4321",
	}

	masked := masker.MaskRow("analytics-agent", "customers", row)

	// Email partial
	maskedEmail, ok := masked["email"].(string)
	if !ok || !strings.Contains(maskedEmail, "***") || !strings.HasSuffix(maskedEmail, "@example.corp") {
		t.Errorf("expected partial email masking, got: %v", masked["email"])
	}

	// Phone redact
	if masked["phone"] != "[REDACTED_PHONE]" {
		t.Errorf("expected [REDACTED_PHONE], got: %v", masked["phone"])
	}

	// Credit card hash
	cardHash, ok := masked["credit_card_last4"].(string)
	if !ok || len(cardHash) != 64 {
		t.Errorf("expected 64-char hex hash for credit_card_last4, got: %v", masked["credit_card_last4"])
	}

	// Unmasked field
	if masked["id"] != 1 {
		t.Errorf("expected id 1 untouched, got: %v", masked["id"])
	}

	// 2. Test free-text PII auto-detection in orders shipping_address
	textRow := map[string]interface{}{
		"id": 101,
		"notes": "Customer requested callback at 555-234-5678 or email ceo@secretcorp.com with SSN 123-45-6789.",
	}
	maskedText := masker.MaskRow("analytics-agent", "orders", textRow)
	notes := maskedText["notes"].(string)
	if strings.Contains(notes, "555-234-5678") {
		t.Errorf("expected phone number to be auto-redacted in free text, got: %s", notes)
	}
	if strings.Contains(notes, "ceo@secretcorp.com") {
		t.Errorf("expected email to be auto-redacted in free text, got: %s", notes)
	}
	if strings.Contains(notes, "123-45-6789") {
		t.Errorf("expected SSN to be auto-redacted in free text, got: %s", notes)
	}

	// 3. Test nil values and partial phone masking
	nilRow := map[string]interface{}{
		"id":    nil,
		"phone": "555-0101",
		"city":  "Short",
	}
	maskedNil := masker.MaskRow("support-agent", "customers", nilRow)
	if maskedNil["id"] != nil {
		t.Errorf("expected nil value preserved, got: %v", maskedNil["id"])
	}
	if !strings.HasSuffix(maskedNil["phone"].(string), "****") {
		t.Errorf("expected partial phone masking, got: %v", maskedNil["phone"])
	}
}
