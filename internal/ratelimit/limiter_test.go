package ratelimit

import (
	"testing"

	"github.com/hashim-work-svg/Audit-Agnet/embedded"
	"github.com/hashim-work-svg/Audit-Agnet/internal/policy"
)

func TestRateLimiter(t *testing.T) {
	pe, err := policy.LoadFromYAML(embedded.ExamplePolicyYAML)
	if err != nil {
		t.Fatalf("failed loading policy: %v", err)
	}

	limiter := NewLimiter(pe)

	// restricted-agent has max_queries_per_minute = 10
	for i := 0; i < 10; i++ {
		if !limiter.Allow("restricted-agent") {
			t.Fatalf("query %d should be allowed within limit", i+1)
		}
	}

	// 11th query should be blocked
	if limiter.Allow("restricted-agent") {
		t.Errorf("expected 11th query to be blocked by rate limiter")
	}

	// analytics-agent has limit 60, should still be allowed
	if !limiter.Allow("analytics-agent") {
		t.Errorf("analytics-agent should not be affected by restricted-agent quota")
	}
}
