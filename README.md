# MCP-Guard 🛡️

[![CI](https://github.com/hashim-work-svg/Audit-Agnet/actions/workflows/ci.yml/badge.svg)](https://github.com/hashim-work-svg/Audit-Agnet/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/hashim-work-svg/Audit-Agnet)](https://goreportcard.com/report/github.com/hashim-work-svg/Audit-Agnet)
[![Static Binary](https://img.shields.io/badge/Binary-Static%20CGO_ENABLED%3D0-brightgreen.svg)](#installation)

> **Zero-Trust, Policy-Controlled, Audited MCP Database Gateway for AI Agents.**

---

## 1. Problem & Industry Evidence

The **Model Context Protocol (MCP)** enables autonomous AI agents and Large Language Models (LLMs) to connect directly to enterprise data stores. However, security controls have lagged behind adoption:

* **Missing Access Controls:** 2026 security benchmarks reveal that **only ~18% of deployed MCP servers enforce granular tool scoping or access controls**, with the majority granting unrestricted queries.
* **Over-Privileged Risk:** Analysts project a substantial surge in enterprise security incidents tied to unauthorized database exfiltration and prompt injection via uncurated agent tool connections through 2027.
* **Tampering & Audit Gaps:** Standard MCP implementations lack immutable audit trails, making forensic attribution of agent actions difficult or impossible.

**`mcp-guard`** solves this by acting as a security proxy gateway between AI agents and SQL databases (MySQL 8 & embedded SQLite). Every tool invocation is authenticated, rate-limited, validated via Abstract Syntax Tree (AST) parsing, masked for PII, and chained into a tamper-evident cryptographic audit log.

---

## 2. Key Capabilities

* 🔒 **Granular Least Privilege:** YAML policies restrict each agent to specific tables, explicit column lists, and query row limits.
* 🛡️ **AST-Based SQL Validation:** Powered by Vitess AST parsing. Rejects multi-statements, non-`SELECT` operations, subqueries on forbidden tables, and dangerous database routines (`SLEEP`, `BENCHMARK`, `LOAD_FILE`, `INTO OUTFILE`).
* 🎭 **Automated PII Masking:** Dynamic field-level masking (hash, redact, partial mask) plus pattern detection for emails, phone numbers, and payment tokens.
* ⛓️ **Tamper-Evident Hash-Chain Audit Log:** Every query decision is cryptographically chained using SHA-256 digests. Any post-hoc modification or row deletion is immediately flagged by `verify-audit`.
* ⚡ **Single Static Binary (`CGO_ENABLED=0`):** Pure-Go dependencies with zero external dynamic C library requirements. Shipped for Linux, macOS, and Windows.
* 🚀 **Zero-Install Demo:** Run `mcp-guard demo` to immediately test with embedded synthetic data—no MySQL or Docker required.

---

## 3. Architecture Overview

```
[AI Agent / LLM Client]
          │  MCP JSON-RPC (Bearer Token)
          ▼
   ┌───────────────┐
   │ Authentication│ ───► Token SHA-256 Verification & Revocation Check
   └───────┬───────┘
           ▼
   ┌───────────────┐
   │  Rate Limiter │ ───► Token Bucket (Queries/min & Bandwidth Limits)
   └───────┬───────┘
           ▼
   ┌───────────────┐
   │ AST Validator │ ───► Vitess AST Parser (Single SELECT only, No Stacking)
   └───────┬───────┘
           ▼
   ┌───────────────┐
   │ Policy Engine │ ───► Table/Column Whitelisting & Auto LIMIT Injection
   └───────┬───────┘
           ▼
   ┌───────────────┐
   │ Execution DB  │ ───► Read-Only Execution (MySQL 8 / Embedded SQLite)
   └───────┬───────┘
           ▼
   ┌───────────────┐
   │  PII Masking  │ ───► Partial Masking, Redaction & Regex Scanning
   └───────┬───────┘
           ▼
   ┌───────────────┐
   │ Hash-Chained  │ ───► Append-Only SHA-256 Tamper-Evident Audit Record
   │   Audit Log   │
   └───────┬───────┘
           ▼
[Sanitized MCP Result]
```

---

## 4. Quickstart: Zero-Install Demo

Experience `mcp-guard` immediately with embedded synthetic e-commerce data:

```bash
# Clone the repository
git clone https://github.com/hashim-work-svg/Audit-Agnet.git
cd Audit-Agnet

# Run the zero-install demo (uses pure-Go embedded SQLite and synthetic data)
go run ./cmd/mcp-guard demo
```

You can inspect the binary version and build metadata:
```bash
go run ./cmd/mcp-guard version
```

---

## 5. What `mcp-guard` Does Not Do (Honest Limitations)

1. **No Database Writes:** `mcp-guard` enforces read-only operations exclusively. `INSERT`, `UPDATE`, `DELETE`, `DROP`, and DDL statements are unconditionally blocked.
2. **Backends Supported:** MySQL 8.0 and embedded SQLite. Other databases (PostgreSQL, SQL Server, Oracle) are out of scope for v0.1.
3. **Indirect Prompt Injection in Content:** While `mcp-guard` protects against SQL injection, data exfiltration, and PII leakage, **it cannot prevent an LLM from interpreting natural-language instructions embedded within legitimate retrieved text**. Security teams must implement secondary input/output guardrails in their LLM orchestrators.

---

## 6. Regulatory & Legal Notice

> [!IMPORTANT]
> **Not Legal Advice:** This tool and documentation are provided for technical security and architecture evaluation purposes only. They do not constitute legal advice regarding compliance with GDPR, HIPAA, EU CRA, or other regulatory frameworks. Consult qualified legal counsel for compliance certification.

---

## 7. License

Distributed under the [MIT License](LICENSE). Copyright (c) 2026 Muhammad Hashim.
