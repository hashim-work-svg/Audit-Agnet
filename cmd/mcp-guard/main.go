// Package main is the entry point for the mcp-guard command line interface.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Version is injected during build time via ldflags.
	Version = "v0.1.0-dev"
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

	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
