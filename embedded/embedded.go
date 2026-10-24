// Package embedded provides embedded SQL schemas, seed data, and default policies.
package embedded

import _ "embed"

// SchemaSQL contains the DDL schema for SQLite and MySQL databases.
//
//go:embed schema.sql
var SchemaSQL string

// SeedSQL contains deterministic synthetic data for demo and integration tests.
//
//go:embed seed.sql
var SeedSQL string

// ExamplePolicyYAML contains the default agent policy definitions.
//
//go:embed example-policy.yaml
var ExamplePolicyYAML []byte
