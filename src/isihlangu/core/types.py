"""Strongly typed core data structures for Isihlangu."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(UTC)


class TargetType(StrEnum):
    MCP_SERVER = "mcp_server"
    REST_API = "rest_api"
    AGENT_PIPELINE = "agent_pipeline"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class OWASPCategory(StrEnum):
    LLM01_PROMPT_INJECTION = "LLM01:2025-Prompt-Injection"
    LLM02_SENSITIVE_INFO_DISCLOSURE = "LLM02:2025-Sensitive-Information-Disclosure"
    LLM06_EXCESSIVE_AGENCY = "LLM06:2025-Excessive-Agency"
    LLM07_SYSTEM_PROMPT_LEAKAGE = "LLM07:2025-System-Prompt-Leakage"
    LLM08_VECTOR_RAG_POISONING = "LLM08:2025-Vector-and-RAG-Poisoning"
    LLM10_UNBOUNDED_CONSUMPTION = "LLM10:2025-Unbounded-Consumption"
    API01_BOLA = "API01:2023-Broken-Object-Level-Authorization"
    API07_SSRF = "API07:2023-Server-Side-Request-Forgery"


class TargetSpec(BaseModel):
    id: str
    name: str
    target_type: TargetType
    base_url: str
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class MCPToolDefinition(BaseModel):
    name: str
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)
    server_transport: str = "stdio"  # stdio or sse
    is_sensitive: bool = False
    requires_auth: bool = False


class AttackHypothesis(BaseModel):
    id: str
    session_id: str
    category: str
    description: str
    target_component: str
    proposed_test: str
    status: str = "unverified"  # unverified, verified, refuted
    created_at: datetime = Field(default_factory=utc_now)


class ExecutionRecord(BaseModel):
    id: str
    session_id: str
    hypothesis_id: str | None = None
    protocol: str  # mcp_jsonrpc, http_rest, oob_canary
    request_payload: str
    response_payload: str
    status_code: int | None = None
    execution_time_ms: int
    created_at: datetime = Field(default_factory=utc_now)


class OOBToken(BaseModel):
    token_uuid: str
    session_id: str
    expected_type: str
    target_component: str
    callback_received: bool = False
    callback_source_ip: str | None = None
    callback_payload: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    verified_at: datetime | None = None


class VerificationResult(BaseModel):
    is_verified: bool
    confidence: float = 1.0  # 0.0 to 1.0
    evidence: dict[str, Any] = Field(default_factory=dict)
    reasoning: str


class VulnerabilityReport(BaseModel):
    id: str
    session_id: str
    hypothesis_id: str | None = None
    title: str
    severity: Severity
    owasp_category: OWASPCategory
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation_patch: str
    created_at: datetime = Field(default_factory=utc_now)
