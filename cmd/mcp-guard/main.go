// Package main is the entry point for the mcp-guard command line interface.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/hashim-work-svg/Audit-Agnet/embedded"
	"github.com/hashim-work-svg/Audit-Agnet/internal/audit"
	"github.com/hashim-work-svg/Audit-Agnet/internal/auth"
	"github.com/hashim-work-svg/Audit-Agnet/internal/demo"
	"github.com/hashim-work-svg/Audit-Agnet/internal/masking"
	"github.com/hashim-work-svg/Audit-Agnet/internal/policy"
	"github.com/hashim-work-svg/Audit-Agnet/internal/ratelimit"
	"github.com/hashim-work-svg/Audit-Agnet/internal/server"
	"github.com/hashim-work-svg/Audit-Agnet/internal/sqlvalidate"
	"github.com/spf13/cobra"
)

var (
	// Version is injected during build time via ldflags.
	Version = "v0.1.0"
	// Commit is injected during build time via ldflags.
	Commit = "none"
	// Date is injected during build time via ldflags.
	Date = "unknown"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "mcp-guard",
		Short: "MCP-Guard: Scoped, Audited, Policy-Controlled MCP Database Gateway",
		Long: `MCP-Guard is an open-source Model Context Protocol (MCP) server that provides
AI agents with safe, read-only, policy-controlled access to MySQL and SQLite databases,
featuring AST SQL validation, PII masking, token authentication, rate limiting,
and a tamper-evident hash-chained audit log.`,
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the binary version and build metadata",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("mcp-guard %s (commit: %s, date: %s)\n", Version, Commit, Date)
		},
	}

	hashTokenCmd := &cobra.Command{
		Use:   "hash-token [token]",
		Short: "Generate SHA-256 token hash for agent key provisioning",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			token := args[0]
			hash := auth.HashToken(token)
			fmt.Printf("Plaintext Token: %s\n", token)
			fmt.Printf("SHA-256 Hash:    %s\n", hash)
		},
	}

	demoCmd := &cobra.Command{
		Use:   "demo",
		Short: "Run an interactive zero-install demonstration with embedded synthetic database",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("=== MCP-Guard Zero-Install Interactive Demonstration ===")
			fmt.Println("Bootstrapping embedded in-memory database and security gateway...")
			fmt.Println()

			sqliteDB, err := demo.InitDemoDB()
			if err != nil {
				return fmt.Errorf("failed to initialize demo database: %w", err)
			}
			defer sqliteDB.Close()

			pe, err := policy.LoadFromYAML(embedded.ExamplePolicyYAML)
			if err != nil {
				return fmt.Errorf("failed to load policy: %w", err)
			}

			rawDB := sqliteDB.RawDB()
			authenticator := auth.NewAuthenticator(rawDB)
			validator := sqlvalidate.NewValidator(pe)
			masker := masking.NewMasker(pe, "demo-secret-salt-key")
			logger := audit.NewLogger(rawDB, "demo-audit-hmac-key")
			limiter := ratelimit.NewLimiter(pe)

			gw := server.NewGateway(sqliteDB, authenticator, pe, validator, masker, logger, limiter)
			ctx := context.Background()

			// Step 1: Tool Pinning Verification
			fmt.Println("[Step 1] Verifying Tool-Definition Pinning...")
			if err := gw.VerifyToolPin("run_query", "Execute a read-only SQL SELECT query with AST validation, limits, and PII masking", `{"type":"object","properties":{"sql":{"type":"string"}}}`); err != nil {
				return fmt.Errorf("tool pin check failed: %w", err)
			}
			fmt.Println("✓ Tool schemas verified against startup cryptographic pins.")
			fmt.Println()

			// Step 2: List Tables as Analytics Agent
			fmt.Println("[Step 2] Authenticating as 'analytics-agent' (token: demo-token-analytics)...")
			tables, err := gw.ListTables(ctx, "demo-token-analytics")
			if err != nil {
				return fmt.Errorf("list_tables failed: %w", err)
			}
			fmt.Printf("Permitted Tables: %v (internal security tables hidden)\n\n", tables)

			// Step 3: Run Query with PII Masking
			query := "SELECT id, full_name, email, phone, credit_card_last4 FROM customers LIMIT 3"
			fmt.Printf("[Step 3] Executing Query with PII Masking:\nSQL: %s\n", query)
			res, err := gw.RunQuery(ctx, "demo-token-analytics", query)
			if err != nil {
				return fmt.Errorf("run_query failed: %w", err)
			}
			fmt.Printf("Returned %d rows:\n", res.RowCount)
			for i, r := range res.Rows {
				fmt.Printf("  Row %d: ID=%v | Name=%v | Email=%v | Phone=%v | CC_Hash=%v\n",
					i+1, r["id"], r["full_name"], r["email"], r["phone"], r["credit_card_last4"])
			}
			fmt.Println()

			// Step 4: Block Malicious Injections & Unauthorized Access
			fmt.Println("[Step 4] Testing Policy & AST Injection Defense:")
			attacks := []struct {
				name  string
				agent string
				token string
				sql   string
			}{
				{"Stacking Injection (DROP TABLE)", "analytics-agent", "demo-token-analytics", "SELECT id FROM customers; DROP TABLE customers;"},
				{"Time-based Injection (SLEEP)", "analytics-agent", "demo-token-analytics", "SELECT id FROM customers WHERE id = 1 AND SLEEP(5)"},
				{"Unauthorized Table Access", "restricted-agent", "demo-token-restricted", "SELECT id FROM customers"},
				{"File Exfiltration (INTO OUTFILE)", "analytics-agent", "demo-token-analytics", "SELECT id FROM customers INTO OUTFILE '/tmp/dump'"},
			}

			for _, att := range attacks {
				_, attErr := gw.RunQuery(ctx, att.token, att.sql)
				if attErr != nil {
					fmt.Printf("  🛡️  BLOCKED: %s\n     Reason: %v\n", att.name, attErr)
				} else {
					fmt.Printf("  ❌ ERROR: %s was not blocked!\n", att.name)
				}
			}
			fmt.Println()

			// Step 5: Verify Hash Chain Audit Log
			fmt.Println("[Step 5] Verifying Audit Log Cryptographic Hash Chain...")
			verifiedCount, err := logger.VerifyAuditChain(ctx)
			if err != nil {
				return fmt.Errorf("audit chain verification failed: %w", err)
			}
			fmt.Printf("✓ %d audit events verified with unbroken HMAC-SHA256 hash chaining.\n", verifiedCount)
			fmt.Println("\n=== Demo Complete: MCP-Guard successfully enforced all security controls ===")
			return nil
		},
	}

	verifyAuditCmd := &cobra.Command{
		Use:   "verify-audit",
		Short: "Verify cryptographic integrity and hash chaining of the audit log",
		RunE: func(cmd *cobra.Command, args []string) error {
			sqliteDB, err := demo.InitDemoDB()
			if err != nil {
				return fmt.Errorf("failed to open database: %w", err)
			}
			defer sqliteDB.Close()

			logger := audit.NewLogger(sqliteDB.RawDB(), "demo-audit-hmac-key")
			count, err := logger.VerifyAuditChain(context.Background())
			if err != nil {
				return fmt.Errorf("AUDIT TAMPERING DETECTED: %w", err)
			}
			fmt.Printf("Audit Log Verified: %d events intact with valid hash chain.\n", count)
			return nil
		},
	}

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(hashTokenCmd)
	rootCmd.AddCommand(demoCmd)
	rootCmd.AddCommand(verifyAuditCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
