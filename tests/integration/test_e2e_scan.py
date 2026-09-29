import json
import os
import tempfile

import pytest

from isihlangu.core.guardrails import ScopeGuardrail
from isihlangu.core.types import TargetSpec, TargetType
from isihlangu.oracle.canary_server import CanaryManager
from isihlangu.orchestrator.graph import EvaluationOrchestrator
from isihlangu.remediation.sarif_exporter import SARIFExporter
from isihlangu.storage.database import DatabaseManager


@pytest.mark.asyncio
async def test_e2e_evaluation_and_sarif_export() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_e2e.db")
        sarif_out_path = os.path.join(tmpdir, "report.sarif")

        db = DatabaseManager(f"sqlite:///{db_path}")
        await db.apply_migrations()

        guardrail = ScopeGuardrail(
            allowed_cidrs=["127.0.0.1/32"],
            allowed_domains=["localhost", "127.0.0.1"],
        )
        canary_mgr = CanaryManager(db, "http://127.0.0.1:8877")
        orchestrator = EvaluationOrchestrator(db, guardrail, canary_mgr)

        sample_tools = {
            "tools": [
                {
                    "name": "fetch_documentation",
                    "description": "Fetches documentation from a URL",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"url": {"type": "string"}},
                    },
                },
                {
                    "name": "delete_customer",
                    "description": "Deletes customer record by id",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"customer_id": {"type": "string"}},
                    },
                },
            ]
        }

        target = TargetSpec(
            id="target_e2e_01",
            name="E2E Mock MCP Target",
            target_type=TargetType.MCP_SERVER,
            base_url="http://127.0.0.1:8000",
            allowed_domains=["localhost", "127.0.0.1"],
        )

        findings = await orchestrator.run_mcp_evaluation(
            target=target,
            tools_response=sample_tools,
            simulate_execution=True,
        )

        assert len(findings) >= 2
        categories = {f.owasp_category.value for f in findings}
        assert "API07:2023-Server-Side-Request-Forgery" in categories
        assert "LLM06:2025-Excessive-Agency" in categories

        # Export SARIF
        sarif = SARIFExporter.to_sarif(findings, target.name)
        with open(sarif_out_path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)

        assert os.path.exists(sarif_out_path)
        with open(sarif_out_path, encoding="utf-8") as f:
            loaded_sarif = json.load(f)

        assert loaded_sarif["version"] == "2.1.0"
        assert len(loaded_sarif["runs"][0]["results"]) == len(findings)
