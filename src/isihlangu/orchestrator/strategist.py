"""The Strategist Node: Evaluates surface topology and formulates attack hypotheses."""

import uuid

from isihlangu.core.types import AttackHypothesis, MCPToolDefinition
from isihlangu.orchestrator.models import InferenceClient
from isihlangu.recon.api_parser import APIEndpoint


class StrategistNode:
    """Analyzes target topology and formulates test hypotheses."""

    def __init__(self, inference_client: InferenceClient | None = None) -> None:
        self.client = inference_client

    def formulate_mcp_hypotheses(
        self, session_id: str, tools: list[MCPToolDefinition]
    ) -> list[AttackHypothesis]:
        """Examines discovered MCP tools and generates concrete test hypotheses."""
        hypotheses = []

        for tool in tools:
            # 1. Check for unconstrained network fetches (SSRF hypothesis)
            if any(k in tool.name.lower() for k in ["fetch", "browse", "get_url", "scrape", "webhook"]):
                hypotheses.append(
                    AttackHypothesis(
                        id=f"hyp_{uuid.uuid4().hex[:8]}",
                        session_id=session_id,
                        category="ssrf_canary",
                        description=f"Tool '{tool.name}' accepts external URLs and may be susceptible to SSRF.",
                        target_component=tool.name,
                        proposed_test=f"Pass out-of-band canary token URL to {tool.name}",
                    )
                )

            # 2. Check for sensitive mutations lacking tenant isolation (BOLA / Privilege Escalation)
            if tool.is_sensitive:
                props = tool.input_schema.get("properties", {})
                if "tenant_id" not in props and "org_id" not in props:
                    hypotheses.append(
                        AttackHypothesis(
                            id=f"hyp_{uuid.uuid4().hex[:8]}",
                            session_id=session_id,
                            category="mcp_privilege_escalation",
                            description=f"Sensitive tool '{tool.name}' lacks explicit tenant boundary parameters.",
                            target_component=tool.name,
                            proposed_test=f"Attempt cross-tenant resource modification via {tool.name}",
                        )
                    )

            # 3. Check for unbounded execution tools (Excessive Agency)
            if any(k in tool.name.lower() for k in ["sql", "exec", "query", "run"]):
                hypotheses.append(
                    AttackHypothesis(
                        id=f"hyp_{uuid.uuid4().hex[:8]}",
                        session_id=session_id,
                        category="excessive_agency",
                        description=f"Tool '{tool.name}' grants direct execution capabilities to the model.",
                        target_component=tool.name,
                        proposed_test=f"Verify parameter constraints on {tool.name}",
                    )
                )

        return hypotheses

    def formulate_api_hypotheses(
        self, session_id: str, endpoints: list[APIEndpoint]
    ) -> list[AttackHypothesis]:
        """Examines REST/GraphQL endpoints and flags BOLA and unauthenticated routes."""
        hypotheses = []
        for ep in endpoints:
            # Check for routes containing IDs with no security requirement
            if "{" in ep.path and not ep.security:
                hypotheses.append(
                    AttackHypothesis(
                        id=f"hyp_{uuid.uuid4().hex[:8]}",
                        session_id=session_id,
                        category="api_unauthenticated_bola",
                        description=f"Path '{ep.path}' [{ep.method}] takes resource IDs but specifies no security.",
                        target_component=f"{ep.method} {ep.path}",
                        proposed_test=f"Attempt unauthorized access to {ep.path}",
                    )
                )
        return hypotheses
