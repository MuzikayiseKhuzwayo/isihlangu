# Isihlangu: The Shield 🛡️
*Deterministic Security Evaluation & Red-Teaming Harness for Agentic SaaS*

[![CI](https://img.shields.io/badge/Status-Active-brightgreen.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](#)
[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-orange.svg)](#)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](#)

**Isihlangu** (Zulu for *"The Shield"*) is a deterministic, multi-agent security evaluation and automated testing harness designed specifically for modern agentic SaaS architectures (MCP servers, tool-calling agents, multi-tenant RAG, BaaS RLS, and webhook workflows).

---

## 1. Why Isihlangu?

Traditional Dynamic Application Security Testing (DAST) and static code analysis (SAST) fail against modern agentic targets:
* **Semantic & Non-Deterministic Vulnerability Paths:** Flaws in agentic SaaS are contextual—e.g., indirect prompt injection coercing an agent into invoking an administrative MCP tool, or multi-tenant RAG context leakage.
* **The "False Refusal" Bottleneck:** Standard commercial frontier models refuse authorized cybersecurity auditing tasks 20% to 43% of the time due to defensive safety filters. Isihlangu is architected around **local-first abliterated weights** (e.g., `Qwen2.5-Coder-32B` / `DeepSeek-R1-Distill` via vLLM or Ollama) to eliminate false refusals during security assessments.
* **The Zero-Hallucination Guarantee:** Vulnerabilities are **never** declared based purely on LLM conversational output. They require empirical verification via an **Out-of-Band (OOB) Canary Server** (cryptographic UUID ping detection) or **Database State-Diffing** (proving unauthorized entity mutation).

---

## 2. Architecture Blueprint

```
+---------------------------------------------------------------------------------------+
|                                ISIHLANGU: THE SHIELD                                  |
|                 Deterministic Agentic SaaS Security Evaluation Harness                |
+---------------------------------------------------------------------------------------+
|  1. TARGET RECONNAISSANCE LAYER                                                       |
|     - MCP Server & Tool Introspector (tools/list, prompts, resources via SSE & stdio) |
|     - API Parser (OpenAPI 3.0 / Swagger / GraphQL endpoint cataloguer)                |
|     - System Prompt & Guardrail Fuzzer (extracting hidden instructions & tools)       |
+---------------------------------------------------------------------------------------+
|  2. STATEFUL MULTI-AGENT ORCHESTRATOR (Deterministic Workflow Graph)                  |
|     - Scope Guardrails (CIDR, domain whitelisting, rate-limiting, non-destructive)   |
|     - The Strategist Node (Reasoning / hypothesis generation on discovered schemas)   |
|     - The Operator Node (Synthesizes protocol-accurate MCP/HTTP/Vector mutations)     |
|     - Crescendo & Multi-Turn State Machine (incremental context shifting)             |
+---------------------------------------------------------------------------------------+
|  3. DETERMINISTIC EXECUTION ORACLE (Zero-Hallucination Guarantee)                     |
|     - Out-of-Band (OOB) Canary Server (HTTP/DNS listener tracking unique UUIDs)       |
|     - Datastore & State Diff Engine (pre/post snapshot comparison for real mutations)  |
|     - Differential Role-Based Testing (evaluating tenant isolation & RLS policies)   |
+---------------------------------------------------------------------------------------+
|  4. VERIFIABLE REMEDIATION SYNTHESIS & REPORTING                                      |
|     - MCP Argument Constraint & JSON Schema Patcher                                   |
|     - PostgreSQL / Supabase Row-Level Security (RLS) Policy Generator                 |
|     - SARIF 2.1.0 Exporter (OWASP LLM & Agentic Top 10 mapped)                        |
|     - Interactive CLI & CI/CD Gating Reports                                          |
+---------------------------------------------------------------------------------------+
```

---

## 3. Quick Start

### Installation with `uv`

```bash
# Clone the repository
git clone https://github.com/isihlangu/isihlangu.git
cd isihlangu

# Install dependencies and virtual environment
uv sync
```

### Datastore Initialization (DDL Migrations)

```bash
# Applies SQL migrations to SQLite / PostgreSQL and verifies live tables
uv run isihlangu init-db
```

### Inspecting an MCP Server

```bash
# From a JSON schema file
uv run isihlangu inspect-mcp fixtures/sample_mcp_tools.json

# From a live remote HTTP endpoint
uv run isihlangu inspect-mcp http://127.0.0.1:8000/tools

# From a local stdio command
uv run isihlangu inspect-mcp --command "node /path/to/server.js"
```

### Running an Evaluation Scan with SARIF Export

```bash
# Offline simulation benchmark
uv run isihlangu run fixtures/sample_mcp_tools.json --target-name "Sandbox Agent" --output-sarif report.sarif

# Live network target execution against active server
uv run isihlangu run fixtures/sample_mcp_tools.json --live --base-url http://127.0.0.1:8000 --canary-timeout 3.0 --output-sarif report.sarif
```

### Running the Out-of-Band Canary Listener

```bash
uv run isihlangu run-canary --host 127.0.0.1 --port 8877
```

### Next.js Visual Orchestration Dashboard

Isihlangu includes a sleek, dark-mode cyber interface for interactive test orchestration:

```bash
# Run directly from repository root
npm run dev

# Or navigate to web/
cd web && npm run dev
# Open http://localhost:3000 in your browser
```

---

## 4. Docker Deployment

Isihlangu includes a hardened multi-stage Docker build with built-in healthchecks:

```bash
cd docker
docker compose up -d
docker compose ps
```

---

## 5. Security & Scope Guardrails

Isihlangu strictly prohibits unauthorized testing. Target destinations are checked against configured CIDRs and domains:
* In `safe_mode=True`, destructive queries (e.g. `drop_database`, `rm_rf`) are intercepted and rejected prior to protocol dispatch.
* Payloads attempting external egress outside authorized CIDR blocks trigger an immediate `ScopeViolationError`.

---

## 6. License

Apache-2.0. Built in accordance with `/systems-engineering` standards.
