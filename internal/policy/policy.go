// Package policy provides agent access control rules and data security limits.
package policy

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// PolicyFile represents the top-level YAML configuration structure.
type PolicyFile struct {
	Version string                 `yaml:"version"`
	Agents  map[string]AgentPolicy `yaml:"agents"`
}

// AgentPolicy defines the granular access boundaries for a specific agent identity.
type AgentPolicy struct {
	Description    string                         `yaml:"description"`
	AllowedTables  []string                       `yaml:"allowed_tables"`
	AllowedColumns map[string][]string            `yaml:"allowed_columns"`
	MaskedColumns  map[string]map[string]string   `yaml:"masked_columns"`
	Limits         PolicyLimits                   `yaml:"limits"`
	PIIAutoDetect  bool                           `yaml:"pii_auto_detect"`
}

// PolicyLimits enforces resource and bandwidth controls per query.
type PolicyLimits struct {
	MaxRowsPerQuery     int `yaml:"max_rows_per_query"`
	MaxQueriesPerMinute int `yaml:"max_queries_per_minute"`
	MaxResultBytes      int `yaml:"max_result_bytes"`
}

// Engine evaluates agent policies against database requests.
type Engine struct {
	agents map[string]AgentPolicy
}

// LoadFromYAML parses raw policy YAML bytes into a policy Engine.
func LoadFromYAML(data []byte) (*Engine, error) {
	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("failed to parse policy YAML: %w", err)
	}

	engine := &Engine{
		agents: make(map[string]AgentPolicy),
	}

	for id, p := range pf.Agents {
		// Normalize allowed tables to lowercase
		tables := make([]string, len(p.AllowedTables))
		for i, t := range p.AllowedTables {
			tables[i] = strings.ToLower(strings.TrimSpace(t))
		}
		p.AllowedTables = tables

		// Normalize allowed columns
		normCols := make(map[string][]string)
		for tbl, cols := range p.AllowedColumns {
			tblLower := strings.ToLower(strings.TrimSpace(tbl))
			colList := make([]string, len(cols))
			for i, c := range cols {
				colList[i] = strings.ToLower(strings.TrimSpace(c))
			}
			normCols[tblLower] = colList
		}
		p.AllowedColumns = normCols

		// Normalize masked columns
		normMasked := make(map[string]map[string]string)
		for tbl, colRules := range p.MaskedColumns {
			tblLower := strings.ToLower(strings.TrimSpace(tbl))
			ruleMap := make(map[string]string)
			for col, rule := range colRules {
				ruleMap[strings.ToLower(strings.TrimSpace(col))] = strings.ToLower(strings.TrimSpace(rule))
			}
			normMasked[tblLower] = ruleMap
		}
		p.MaskedColumns = normMasked

		// Defaults
		if p.Limits.MaxRowsPerQuery <= 0 {
			p.Limits.MaxRowsPerQuery = 50
		}
		if p.Limits.MaxQueriesPerMinute <= 0 {
			p.Limits.MaxQueriesPerMinute = 60
		}
		if p.Limits.MaxResultBytes <= 0 {
			p.Limits.MaxResultBytes = 1048576 // 1MB
		}

		engine.agents[id] = p
	}

	return engine, nil
}

// GetAgentPolicy retrieves the access policy for a specific agent.
func (e *Engine) GetAgentPolicy(agentID string) (*AgentPolicy, error) {
	p, ok := e.agents[agentID]
	if !ok {
		return nil, fmt.Errorf("no policy configured for agent %q", agentID)
	}
	return &p, nil
}

// IsTableAllowed checks if an agent is authorized to access a given table.
func (e *Engine) IsTableAllowed(agentID, table string) bool {
	p, ok := e.agents[agentID]
	if !ok {
		return false
	}
	target := strings.ToLower(strings.TrimSpace(table))
	for _, t := range p.AllowedTables {
		if t == target {
			return true
		}
	}
	return false
}

// IsColumnAllowed checks if an agent is authorized to read a specific column from a table.
func (e *Engine) IsColumnAllowed(agentID, table, column string) bool {
	p, ok := e.agents[agentID]
	if !ok {
		return false
	}
	tbl := strings.ToLower(strings.TrimSpace(table))
	col := strings.ToLower(strings.TrimSpace(column))

	// If no column restrictions defined for table, default to checking if table is allowed
	cols, exists := p.AllowedColumns[tbl]
	if !exists {
		return e.IsTableAllowed(agentID, table)
	}

	for _, c := range cols {
		if c == col || c == "*" {
			return true
		}
	}
	return false
}

// GetMaskingRule returns the PII masking rule (hash, partial, redact) for a column.
func (e *Engine) GetMaskingRule(agentID, table, column string) string {
	p, ok := e.agents[agentID]
	if !ok {
		return ""
	}
	tbl := strings.ToLower(strings.TrimSpace(table))
	col := strings.ToLower(strings.TrimSpace(column))

	if tblRules, ok := p.MaskedColumns[tbl]; ok {
		if rule, ok := tblRules[col]; ok {
			return rule
		}
	}
	return ""
}
