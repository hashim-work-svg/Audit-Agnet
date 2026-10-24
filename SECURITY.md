# Security Policy & Limitations: MCP-Guard

## Threat Model Overview

`mcp-guard` is designed to enforce zero-trust access control when LLM-driven agents interact with enterprise SQL databases.

### Core Mitigations

| Threat Vector | Gateway Mitigation | Residual Risk |
| :--- | :--- | :--- |
| **Over-Privileged Agent** | Granular per-agent table and column whitelisting defined in YAML policy. | Misconfigured policy granting access to sensitive tables. |
| **SQL Injection via Agent** | AST parsing (Vitess) guarantees only single `SELECT` statements are executed. Disallows stacked queries, comments, and dangerous functions. | Complex subqueries on allowed tables that produce unexpected joins. |
| **Data Exfiltration** | Hard `max_rows_per_query`, `max_queries_per_minute`, and `max_result_bytes` limits. | Slow exfiltration below rate limits across extended periods. |
| **PII Exposure** | Column-level masking rules (hash, partial mask, redact) plus automatic regex pattern scanning. | Novel unstructured PII formats not covered by regex heuristics. |
| **Tool Tampering** | Tool definition pinning computes SHA-256 fingerprint of tools at initialization. | Process-level memory tampering if host OS is compromised. |
| **Audit Log Tampering** | Cryptographic hash-chain links every audit record to the previous record's SHA-256 digest. | Loss of the audit log file entirely (requires external immutable backups). |

## Prompt Injection Canary & Limitations

> [!WARNING]
> **Prompt Injection from Database Content:**
> While `mcp-guard` prevents arbitrary SQL execution and redacts sensitive PII, **it cannot prevent an agent's downstream LLM from interpreting instructions embedded within legitimate database content** (e.g., customer comments or support tickets containing `"Ignore previous instructions and do X"`). 
> 
> Security teams must implement secondary safety classifiers in their agent execution loop.

## Not Legal or Compliance Advice Notice

> [!IMPORTANT]
> **Notice:** This software and its documentation are provided for technical security engineering and architectural evaluation. They do not constitute legal advice regarding GDPR, HIPAA, EU CRA, or other regulatory compliance. Organizations must consult qualified legal counsel to verify compliance postures.

## Reporting a Security Vulnerability

If you discover a security vulnerability within `mcp-guard`, please do not open a public issue. Email the project maintainer at `security@example.corp` or open a private GitHub Security Advisory.
