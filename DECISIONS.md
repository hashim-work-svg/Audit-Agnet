# Architecture Decision Records (ADRs) - MCP-Guard

## ADR-0001: Pure-Go Static Single-Binary Architecture (CGO_ENABLED=0)
* **Date:** 2026-10-24
* **Status:** Accepted
* **Context:**
  MCP servers must deploy seamlessly across heterogeneous client environments (developer laptops, containerized pipelines, secure bastion servers) without external runtime dependencies, dynamic C libraries, or complex installation steps.
* **Decision:**
  Enforce `CGO_ENABLED=0` across all builds and tests. Back embedded demo execution with pure-Go SQLite (`modernc.org/sqlite`) and production database connections with pure-Go MySQL (`github.com/go-sql-driver/mysql`).
* **Consequences:**
  Cross-compilation for Linux (amd64, arm64), macOS (amd64, arm64), and Windows (amd64) produces 100% statically linked binaries with zero C library dependencies.

---

## ADR-0002: AST-Based SQL Parser Selection (Vitess sqlparser vs TiDB)
* **Date:** 2026-10-24
* **Status:** Accepted
* **Context:**
  Regex-based SQL sanitization is inherently vulnerable to SQL injection bypasses, obfuscated whitespace, comments, nested subqueries, and non-trivial dialect syntax. We require a true Abstract Syntax Tree (AST) parser to inspect table and column references and enforce read-only semantics.
* **Decision:**
  Select Vitess SQL parser (`github.com/xwb1989/sqlparser`), the production-hardened parser used by Vitess proxy.
* **Comparison:**
  - *Vitess sqlparser:* Pure Go, extremely lightweight, zero CGo, specifically designed for query parsing, rewriting, AST node inspection, and proxying.
  - *PingCAP/TiDB parser:* Complete MySQL 8.0 DDL coverage, but pulls in extensive TiDB engine dependencies and requires Go toolchain >= 1.26.
* **Consequences:**
  Allows clean AST traversal to reject multi-statements, non-SELECT queries, forbidden subqueries, functions like `SLEEP` and `BENCHMARK`, and safely inject `LIMIT` clauses.

---

## ADR-0003: Agent Authentication and Token Storage Scheme
* **Date:** 2026-10-24
* **Status:** Accepted
* **Context:**
  Each AI agent authenticates via a Bearer token. Storing raw tokens in database tables or memory creates severe credential exposure risk.
* **Decision:**
  Store only cryptographic hashes (SHA-256 / HMAC with server secret) of agent tokens in the `agent_keys` table. The gateway accepts the Bearer token in the MCP authorization header or environment, hashes it, and queries the policy/key store for active credentials.
* **Consequences:**
  Even if the gateway database or memory is inspected, raw agent tokens cannot be reconstructed.

---

## ADR-0004: Zero-Install Embedded Demo Mode via `go:embed`
* **Date:** 2026-10-24
* **Status:** Accepted
* **Context:**
  Evaluators and hiring managers must be able to test the gateway with a single command without provisioning a MySQL server or installing Docker.
* **Decision:**
  Embed schema DDL and deterministic synthetic seed data directly into the binary via `go:embed`. Running `mcp-guard demo` boots an in-memory SQLite database instance pre-loaded with synthetic e-commerce data and pre-configured agent policies.
* **Consequences:**
  The binary is fully self-contained, offline-capable, and requires zero external database servers to demonstrate.

---

## ADR-0005: Model Context Protocol (MCP) Protocol Engine
* **Date:** 2026-10-24
* **Status:** Accepted
* **Context:**
  MCP defines JSON-RPC 2.0 communication over stdio and HTTP/SSE transports for tool discovery and execution.
* **Decision:**
  Adopt official MCP primitives (`github.com/modelcontextprotocol/go-sdk`), supporting stdio and HTTP/SSE with strict type-safe schema definitions for `list_tables`, `describe_table`, and `run_query`.
* **Consequences:**
  Ensures 100% interoperability with official MCP clients (Claude Desktop, IDE extensions, custom agent harnesses).
