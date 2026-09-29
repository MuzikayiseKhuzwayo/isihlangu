"""Orchestrator Graph: End-to-end execution flow for security evaluations."""

import logging
import uuid
from typing import Any

from isihlangu.core.guardrails import ScopeGuardrail
from isihlangu.core.types import (
    OWASPCategory,
    Severity,
    TargetSpec,
    VulnerabilityReport,
)
from isihlangu.oracle.canary_server import CanaryManager
from isihlangu.oracle.verifier import VerificationOracle
from isihlangu.orchestrator.operator import OperatorNode
from isihlangu.orchestrator.strategist import StrategistNode
from isihlangu.protocols.http_client import GuardedHTTPClient
from isihlangu.protocols.mcp_client import AsyncMCPClient
from isihlangu.recon.mcp_inspector import MCPInspector
from isihlangu.remediation.rls_patcher import RLSPatcher
from isihlangu.remediation.schema_patcher import MCPSchemaPatcher
from isihlangu.storage.database import DatabaseManager

logger = logging.getLogger(__name__)


class EvaluationOrchestrator:
    """Coordinates reconnaissance, hypothesis generation, execution, oracle verification, and remediation."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        guardrail: ScopeGuardrail,
        canary_manager: CanaryManager,
    ) -> None:
        self.db = db_manager
        self.guardrail = guardrail
        self.canary_mgr = canary_manager
        self.mcp_inspector = MCPInspector()
        self.strategist = StrategistNode()
        self.operator = OperatorNode()
        self.oracle = VerificationOracle()
        self.schema_patcher = MCPSchemaPatcher()
        self.rls_patcher = RLSPatcher()
        self.mcp_client = AsyncMCPClient(guardrail)
        self.http_client = GuardedHTTPClient(guardrail)

    async def run_mcp_evaluation(
        self,
        target: TargetSpec,
        tools_response: dict[str, Any],
        simulate_execution: bool = True,
        canary_timeout: float = 3.0,
        use_llm_reasoning: bool = False,
    ) -> list[VulnerabilityReport]:
        """Runs full evaluation pipeline on an MCP target in live or simulation mode."""
        session_id = f"sess_{uuid.uuid4().hex[:8]}"

        # 1. Datastore registration
        await self.db.insert_target(target)
        await self.db.create_session(session_id, target.id)

        # 2. Recon: Introspect Tools
        tools = self.mcp_inspector.parse_tools_response(tools_response)

        # 3. Strategy: Formulate Hypotheses (via LLM or rule baseline)
        if use_llm_reasoning:
            hypotheses = await self.strategist.formulate_hypotheses_with_llm(session_id, tools)
        else:
            hypotheses = self.strategist.formulate_mcp_hypotheses(session_id, tools)

        findings: list[VulnerabilityReport] = []

        # 4. Operator & Oracle: Test each hypothesis
        for hyp in hypotheses:
            await self.db.insert_hypothesis(hyp)
            target_tool = next((t for t in tools if t.name == hyp.target_component), None)
            if not target_tool:
                continue

            if hyp.category == "ssrf_canary":
                # Create OOB Canary Token
                token = await self.canary_mgr.generate_token(
                    session_id=session_id,
                    expected_type="ssrf_out_of_band",
                    target_component=target_tool.name,
                )
                canary_url = self.canary_mgr.get_canary_url(token)
                payload = self.operator.build_mcp_canary_payload(target_tool, canary_url)

                if simulate_execution:
                    # In simulation/mock mode for test harnesses, trigger callback
                    await self.db.mark_canary_callback(
                        token.token_uuid, source_ip="127.0.0.1", payload="MCP SSRF Callback"
                    )
                else:
                    # Live Target Protocol Dispatch!
                    try:
                        if target.config.get("command"):
                            cmd = str(target.config["command"])
                            args = list(target.config.get("args", []))
                            await self.mcp_client.call_stdio(cmd, args, "tools/call", payload)
                        else:
                            await self.mcp_client.call_http(target.base_url, "tools/call", payload)
                    except Exception as e:
                        logger.info(
                            "Target execution note: %s (evaluating if canary received ping)", e
                        )

                    # Poll for real callback arrival during the grace period
                    await self.canary_mgr.poll_for_callback(
                        token.token_uuid, timeout_seconds=canary_timeout
                    )

                is_hit = await self.canary_mgr.verify_callback(token.token_uuid)
                token.callback_received = is_hit
                if is_hit:
                    token_rec = await self.db.get_canary_token(token.token_uuid)
                    if token_rec:
                        token.callback_source_ip = (
                            token_rec.get("callback_source_ip") or "127.0.0.1"
                        )
                        token.callback_payload = (
                            token_rec.get("callback_payload") or "Callback Verified"
                        )
                    else:
                        token.callback_source_ip = "127.0.0.1"

                verif = self.oracle.verify_canary(hyp, token)
                if verif.is_verified:
                    patch = self.schema_patcher.patch_url_property(
                        target_tool.input_schema, allowed_domains=target.allowed_domains
                    )
                    vuln = VulnerabilityReport(
                        id=f"vuln_{uuid.uuid4().hex[:8]}",
                        session_id=session_id,
                        hypothesis_id=hyp.id,
                        title=f"Unrestricted Network Egress / SSRF in MCP Tool '{target_tool.name}'",
                        severity=Severity.HIGH,
                        owasp_category=OWASPCategory.API07_SSRF,
                        description=verif.reasoning,
                        evidence=verif.evidence,
                        remediation_patch=str(patch),
                    )
                    findings.append(vuln)
                    await self.db.insert_vulnerability(vuln)

            elif hyp.category == "mcp_privilege_escalation":
                deficiencies = self.mcp_inspector.identify_schema_deficiencies(target_tool)
                if deficiencies:
                    patch = self.schema_patcher.add_tenant_isolation(target_tool.input_schema)
                    vuln = VulnerabilityReport(
                        id=f"vuln_{uuid.uuid4().hex[:8]}",
                        session_id=session_id,
                        hypothesis_id=hyp.id,
                        title=f"Missing Multi-Tenant Isolation in Sensitive Tool '{target_tool.name}'",
                        severity=Severity.CRITICAL,
                        owasp_category=OWASPCategory.LLM06_EXCESSIVE_AGENCY,
                        description=f"Tool allows privileged mutations without enforcing tenant boundary constraints. Deficiencies: {deficiencies}",
                        evidence={"deficiencies": deficiencies, "tool_name": target_tool.name},
                        remediation_patch=str(patch),
                    )
                    findings.append(vuln)
                    await self.db.insert_vulnerability(vuln)

        # 5. Complete session in datastore
        await self.db.complete_session(
            session_id=session_id,
            summary={"tools_count": len(tools), "vulnerabilities_found": len(findings)},
        )

        return findings
