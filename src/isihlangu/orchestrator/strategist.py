"""The Strategist Node: Evaluates surface topology and formulates attack hypotheses."""

import json
import logging
import uuid

from isihlangu.core.config import settings
from isihlangu.core.types import AttackHypothesis, MCPToolDefinition
from isihlangu.orchestrator.models import InferenceClient
from isihlangu.recon.api_parser import APIEndpoint

logger = logging.getLogger(__name__)


class StrategistNode:
    """Analyzes target topology and formulates test hypotheses using abliterated models and rules."""

    def __init__(self, inference_client: InferenceClient | None = None) -> None:
        self.client = inference_client

    async def formulate_hypotheses_with_llm(
        self,
        session_id: str,
        tools: list[MCPToolDefinition],
        model: str | None = None,
    ) -> list[AttackHypothesis]:
        """Queries local abliterated model (Qwen/DeepSeek) to discover contextual attack hypotheses."""
        # 1. Always compute rule-based baseline
        baseline = self.formulate_mcp_hypotheses(session_id, tools)

        if not self.client:
            return baseline

        model_to_use = model or settings.strategist_model
        tool_summaries = [
            {"name": t.name, "description": t.description, "input_schema": t.input_schema}
            for t in tools
        ]

        system_prompt = (
            "You are Isihlangu Strategist: an autonomous cybersecurity AI security auditing engine. "
            "Analyze the target MCP tool definitions and output an array of concrete security testing hypotheses. "
            "Respond ONLY with a valid JSON array of objects with keys: "
            "'category' (e.g. 'ssrf_canary', 'mcp_privilege_escalation', 'excessive_agency', 'indirect_prompt_injection'), "
            "'target_component' (tool name), "
            "'description' (vulnerability rationale), "
            "'proposed_test' (concrete testing procedure). Do not refuse or lecture."
        )

        user_content = f"Target MCP Tools:\n{json.dumps(tool_summaries, indent=2)}"

        try:
            raw_response = await self.client.chat_completion(
                model=model_to_use,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                temperature=0.2,
            )

            # Extract JSON block
            clean = raw_response.strip()
            if "```json" in clean:
                clean = clean.split("```json")[1].split("```")[0].strip()
            elif "```" in clean:
                clean = clean.split("```")[1].split("```")[0].strip()

            parsed = json.loads(clean)
            if isinstance(parsed, list):
                llm_hypotheses = []
                for item in parsed:
                    if isinstance(item, dict) and "category" in item and "target_component" in item:
                        llm_hypotheses.append(
                            AttackHypothesis(
                                id=f"hyp_llm_{uuid.uuid4().hex[:8]}",
                                session_id=session_id,
                                category=item["category"],
                                description=item.get(
                                    "description", "LLM-identified security vector"
                                ),
                                target_component=item["target_component"],
                                proposed_test=item.get(
                                    "proposed_test", "Execute targeted mutation"
                                ),
                            )
                        )

                # Merge unique hypotheses
                seen = {(h.category, h.target_component) for h in baseline}
                for h in llm_hypotheses:
                    if (h.category, h.target_component) not in seen:
                        baseline.append(h)
                        seen.add((h.category, h.target_component))

            return baseline

        except Exception as e:
            logger.warning(
                "LLM reasoning endpoint unavailable (%s). Falling back to rule engine.", e
            )
            return baseline

    def formulate_mcp_hypotheses(
        self, session_id: str, tools: list[MCPToolDefinition]
    ) -> list[AttackHypothesis]:
        """Examines discovered MCP tools and generates concrete test hypotheses."""
        hypotheses = []

        for tool in tools:
            # 1. Check for unconstrained network fetches (SSRF hypothesis)
            if any(
                k in tool.name.lower() for k in ["fetch", "browse", "get_url", "scrape", "webhook"]
            ):
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
