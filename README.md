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

## 2. Implementation Status

| Feature | Status | Description |
| :--- | :---: | :--- |
| **AST SQL Validation** | ✅ Shipped | Strict AST parsing rejecting non-SELECT, stacking, DDL/DML, dangerous routines |
| **Policy Engine** | ✅ Shipped | Table/column allowlists, row limits, result byte caps per agent |
| **PII Masking Engine** | ✅ Shipped | Redaction, partial masking, HMAC-SHA256 hashing, regex pattern auto-detection |
| **Bearer Token Authentication** | ✅ Shipped | SHA-256 token verification and revocation check |
| **Per-Agent Rate Limiting** | ✅ Shipped | Sliding-window query limits per minute |
| **Tool-Definition Pinning** | ✅ Shipped | Cryptographic hashes computed at startup to prevent schema tampering |
| **Hash-Chained Audit Log** | ✅ Shipped | Unbroken HMAC-SHA256 chain over all record fields with `verify-audit` CLI |
| **Zero-Install Demo Mode** | ✅ Shipped | `mcp-guard demo` runs with embedded pure-Go SQLite |

---

## 3. Installation

Download pre-compiled static binaries from [GitHub Releases](https://github.com/hashim-work-svg/Audit-Agnet/releases), or install via Go:

```bash
go install github.com/hashim-work-svg/Audit-Agnet/cmd/mcp-guard@latest
```

Or build from source:

```bash
git clone https://github.com/hashim-work-svg/Audit-Agnet.git
cd Audit-Agnet
make build-static
```

---

## 4. Quickstart

### Zero-Install Interactive Demonstration:
Experience `mcp-guard` immediately with embedded synthetic e-commerce data:

```bash
./bin/mcp-guard demo
```

### Verify Audit Log Cryptographic Integrity:
```bash
./bin/mcp-guard verify-audit
```

### Generate Token Hash for Agent Key Provisioning:
```bash
./bin/mcp-guard hash-token my-secret-agent-token
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
