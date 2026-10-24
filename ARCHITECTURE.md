# Architecture & Security Pipeline: MCP-Guard

`mcp-guard` is a secure reverse-proxy gateway implementing the Model Context Protocol (MCP) to provide AI agents with policy-controlled, read-only database access.

## System Architecture Diagram

```mermaid
flowchart TD
    subgraph Client["AI Agent / MCP Client"]
        Agent["Autonomous Agent / LLM"]
    end

    subgraph Gateway["MCP-Guard Gateway (Single Static Go Binary)"]
        Transport["Transport Layer\n(stdio / Streamable HTTP SSE)"]
        Auth["Authentication & Key Store\n(SHA-256 Hashed Token Verification)"]
        RateLimit["Token Bucket Rate Limiter\n(Queries/min & Bandwidth Limits)"]
        PinCheck["Tool Definition Pinning\n(SHA-256 Hash Guard Against Poisoning)"]
        
        subgraph Pipeline["Zero-Trust Execution Pipeline"]
            AST["AST SQL Parser (Vitess)\nSingle SELECT Enforced\nSubquery & Function Auditing"]
            Policy["Policy Engine\nTable/Column Scoping\nLIMIT Injection & Row Caps"]
            Exec["Read-Only DB Execution\n(MySQL 8 / Embedded SQLite)"]
            Masking["PII Masking Engine\n(Partial / Redact / Hash / Regex Canary)"]
            Audit["Append-Only Hash-Chain Audit Log\n(SHA-256 Previous Record Linkage)"]
        end
    end

    subgraph Database["Underlying Storage Layer"]
        MySQL[("Production MySQL 8\n(Read-Only Least Privilege User)")]
        SQLite[("Embedded In-Memory SQLite\n(Zero-Install Demo Mode)")]
    end

    Agent -->|"MCP JSON-RPC 2.0 (Bearer Token)"| Transport
    Transport --> Auth
    Auth -->|"Valid Agent ID"| RateLimit
    RateLimit -->|"Under Quota"| PinCheck
    PinCheck --> AST
    AST -->|"Single Safe SELECT"| Policy
    Policy -->|"Rewritten AST with Enforced LIMIT"| Exec
    Exec -->|"Execute SELECT"| MySQL
    Exec -.->|"Execute SELECT (Demo)"| SQLite
    MySQL -->|"Raw Result Rows"| Masking
    SQLite -.->|"Raw Result Rows"| Masking
    Masking -->|"Sanitized PII Data"| Audit
    Audit -->|"Record Logged & Chained"| Transport
    Transport -->|"MCP Tool Response (Masked)"| Agent
```

## Security Pipeline Stages

1. **Authentication:**
   The gateway inspects the incoming agent authorization credentials against pre-computed SHA-256 hashes in `agent_keys`. Unauthenticated requests or revoked agents are immediately terminated with JSON-RPC error `-32001`.

2. **Rate Limiting:**
   A per-agent token-bucket rate limiter enforces maximum queries per minute and result bandwidth limits to defend against data exfiltration and denial-of-service.

3. **Tool Definition Pinning:**
   At boot, `mcp-guard` computes a SHA-256 fingerprint of all registered tool schemas (`list_tables`, `describe_table`, `run_query`). Any runtime alteration or prototype pollution attempt triggers an immediate security alert.

4. **AST SQL Parser & Validator:**
   Using Vitess Abstract Syntax Tree (AST) parsing, the gateway ensures:
   - Exactly one statement is supplied (multi-query injection blocked).
   - The statement type is exclusively `SELECT` (all `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `GRANT` rejected).
   - Dangerous server functions (`SLEEP`, `BENCHMARK`, `LOAD_FILE`, `INTO OUTFILE`) are rejected.
   - All referenced tables and columns are validated against the agent's policy.

5. **Policy Enforcement & Query Rewriting:**
   - Any query attempting to access forbidden tables or restricted columns is rejected.
   - For permitted queries without a `LIMIT` clause, the policy engine safely injects an AST `LIMIT` node conforming to `max_rows_per_query`.

6. **PII Masking:**
   Tabular results pass through the masking pipeline:
   - **Column Rules:** Columns designated for masking are transformed via `partial` (e.g. `a***e@example.corp`), `redact` (e.g. `[REDACTED_PHONE]`), or `hash` (SHA-256).
   - **Canary Pattern Detection:** Free-text columns are scanned for email addresses, phone numbers, and payment tokens.

7. **Tamper-Evident Hash-Chain Audit Logging:**
   Every query decision (allowed, denied, or masked) is appended to the audit log. Each record stores:
   $$\text{Hash}_n = \text{SHA256}(\text{Timestamp} \parallel \text{AgentID} \parallel \text{Tool} \parallel \text{Query} \parallel \text{Decision} \parallel \text{Hash}_{n-1})$$
   Any post-hoc alteration or deletion of audit logs breaks the cryptographic chain and is detected by `mcp-guard verify-audit`.
