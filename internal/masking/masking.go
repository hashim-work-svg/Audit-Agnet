// Package masking provides PII sanitization, column-level masking rules, and regex pattern redaction.
package masking

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashim-work-svg/Audit-Agnet/internal/policy"
)

var (
	emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	phoneRegex = regexp.MustCompile(`(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}`)
	ssnRegex   = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
)

// Masker applies data privacy and sanitization rules to SQL query result sets.
type Masker struct {
	policyEngine *policy.Engine
	hmacKey      []byte
}

// NewMasker creates a Masker with an optional HMAC secret for secure salting of short hashes.
func NewMasker(pe *policy.Engine, secret string) *Masker {
	if secret == "" {
		secret = "mcp-guard-internal-salt-key-2026"
	}
	return &Masker{
		policyEngine: pe,
		hmacKey:      []byte(secret),
	}
}

// MaskRow sanitizes a map of column values for a specific table according to agent policy.
func (m *Masker) MaskRow(agentID, table string, row map[string]interface{}) map[string]interface{} {
	masked := make(map[string]interface{}, len(row))

	agentPolicy, _ := m.policyEngine.GetAgentPolicy(agentID)
	autoDetect := true
	if agentPolicy != nil {
		autoDetect = agentPolicy.PIIAutoDetect
	}

	for col, val := range row {
		if val == nil {
			masked[col] = nil
			continue
		}

		strVal := fmt.Sprintf("%v", val)
		rule := m.policyEngine.GetMaskingRule(agentID, table, col)

		if rule != "" {
			masked[col] = m.applyRule(rule, col, strVal)
			continue
		}

		// If no explicit column rule, check PII auto-detect on text columns
		if autoDetect && isTextColumn(strVal) {
			masked[col] = m.sanitizeFreeText(strVal)
		} else {
			masked[col] = val
		}
	}

	return masked
}

func (m *Masker) applyRule(rule, col, val string) string {
	switch strings.ToLower(rule) {
	case "redact":
		return fmt.Sprintf("[REDACTED_%s]", strings.ToUpper(col))

	case "hash":
		// Keyed HMAC-SHA256 to prevent pre-computation attacks on low-entropy fields (like last4 credit card)
		mac := hmac.New(sha256.New, m.hmacKey)
		mac.Write([]byte(val))
		return hex.EncodeToString(mac.Sum(nil))

	case "partial":
		return maskPartial(col, val)

	default:
		return val
	}
}

func maskPartial(col, val string) string {
	colLower := strings.ToLower(col)
	if strings.Contains(colLower, "email") || strings.Contains(val, "@") {
		parts := strings.Split(val, "@")
		if len(parts) == 2 && len(parts[0]) > 0 {
			user := parts[0]
			if len(user) <= 2 {
				return "*@" + parts[1]
			}
			return string(user[0]) + "***" + string(user[len(user)-1]) + "@" + parts[1]
		}
	}

	if strings.Contains(colLower, "phone") {
		if len(val) >= 4 {
			return val[:len(val)-4] + "****"
		}
		return "****"
	}

	if len(val) <= 4 {
		return "****"
	}
	return val[:3] + " " + strings.Repeat("*", len(val)-4)
}

func (m *Masker) sanitizeFreeText(text string) string {
	sanitized := emailRegex.ReplaceAllString(text, "[REDACTED_EMAIL]")
	sanitized = phoneRegex.ReplaceAllString(sanitized, "[REDACTED_PHONE]")
	sanitized = ssnRegex.ReplaceAllString(sanitized, "[REDACTED_SSN]")
	return sanitized
}

func isTextColumn(val string) bool {
	return len(val) > 5 && (strings.Contains(val, " ") || strings.Contains(val, "@") || strings.Contains(val, "-"))
}
