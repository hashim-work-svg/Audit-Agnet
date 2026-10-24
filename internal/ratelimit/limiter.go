// Package ratelimit provides in-memory per-agent rate limiting using sliding window timestamps.
package ratelimit

import (
	"sync"
	"time"

	"github.com/hashim-work-svg/Audit-Agnet/internal/policy"
)

// Limiter manages query rate thresholds per agent identity.
type Limiter struct {
	mu           sync.Mutex
	policyEngine *policy.Engine
	history      map[string][]time.Time
}

// NewLimiter creates an in-memory per-agent rate Limiter.
func NewLimiter(pe *policy.Engine) *Limiter {
	return &Limiter{
		policyEngine: pe,
		history:      make(map[string][]time.Time),
	}
}

// Allow checks if an agent has remaining query quota within the 1-minute window.
func (l *Limiter) Allow(agentID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	agentPolicy, err := l.policyEngine.GetAgentPolicy(agentID)
	maxQueries := 60
	if err == nil && agentPolicy.Limits.MaxQueriesPerMinute > 0 {
		maxQueries = agentPolicy.Limits.MaxQueriesPerMinute
	}

	now := time.Now()
	cutoff := now.Add(-1 * time.Minute)

	// Clean up timestamps older than 1 minute
	valid := make([]time.Time, 0, len(l.history[agentID]))
	for _, t := range l.history[agentID] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= maxQueries {
		l.history[agentID] = valid
		return false
	}

	valid = append(valid, now)
	l.history[agentID] = valid
	return true
}
