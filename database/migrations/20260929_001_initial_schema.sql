-- Migration: 20260929_001_initial_schema.sql
-- Description: Initial schema for Isihlangu targets, sessions, canary tokens, and findings

-- UP Migration
CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    target_type TEXT NOT NULL, -- 'mcp_server', 'rest_api', 'agent_pipeline'
    base_url TEXT NOT NULL,
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_sessions (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    status TEXT NOT NULL, -- 'pending', 'running', 'completed', 'failed'
    summary_json TEXT NOT NULL DEFAULT '{}',
    error_message TEXT,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attack_hypotheses (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    category TEXT NOT NULL, -- 'mcp_privilege_escalation', 'ssrf_canary', 'rls_bypass', 'indirect_prompt_injection'
    description TEXT NOT NULL,
    target_component TEXT NOT NULL,
    proposed_test TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unverified', -- 'unverified', 'verified', 'refuted'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS execution_logs (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    hypothesis_id TEXT,
    protocol TEXT NOT NULL, -- 'mcp_jsonrpc', 'http_rest', 'oob_canary'
    request_payload TEXT NOT NULL,
    response_payload TEXT NOT NULL,
    status_code INTEGER,
    execution_time_ms INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE,
    FOREIGN KEY(hypothesis_id) REFERENCES attack_hypotheses(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS canary_tokens (
    token_uuid TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    expected_type TEXT NOT NULL, -- 'ssrf_out_of_band', 'blind_injection'
    target_component TEXT NOT NULL,
    callback_received INTEGER NOT NULL DEFAULT 0,
    callback_source_ip TEXT,
    callback_payload TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP,
    FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    hypothesis_id TEXT,
    title TEXT NOT NULL,
    severity TEXT NOT NULL, -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    owasp_category TEXT NOT NULL, -- e.g. 'LLM01:2025-Prompt-Injection', 'LLM06:2025-Excessive-Agency'
    description TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    remediation_patch TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE,
    FOREIGN KEY(hypothesis_id) REFERENCES attack_hypotheses(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_sessions_target ON scan_sessions(target_id);
CREATE INDEX IF NOT EXISTS idx_attack_hypotheses_session ON attack_hypotheses(session_id);
CREATE INDEX IF NOT EXISTS idx_canary_tokens_session ON canary_tokens(session_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_session ON vulnerabilities(session_id);

-- rollback
-- DROP INDEX IF EXISTS idx_vulnerabilities_session;
-- DROP INDEX IF EXISTS idx_canary_tokens_session;
-- DROP INDEX IF EXISTS idx_attack_hypotheses_session;
-- DROP INDEX IF EXISTS idx_scan_sessions_target;
-- DROP TABLE IF EXISTS vulnerabilities;
-- DROP TABLE IF EXISTS canary_tokens;
-- DROP TABLE IF EXISTS execution_logs;
-- DROP TABLE IF EXISTS attack_hypotheses;
-- DROP TABLE IF EXISTS scan_sessions;
-- DROP TABLE IF EXISTS targets;
