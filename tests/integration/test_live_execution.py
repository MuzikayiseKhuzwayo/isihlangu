import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest

from isihlangu.core.guardrails import ScopeGuardrail
from isihlangu.core.types import OWASPCategory, TargetSpec, TargetType
from isihlangu.oracle.canary_server import CanaryManager, CanaryServer
from isihlangu.orchestrator.graph import EvaluationOrchestrator
from isihlangu.storage.database import DatabaseManager


class MockMCPTargetHandler(BaseHTTPRequestHandler):
    """Mock MCP server that simulates an SSRF-vulnerable tools/call execution."""

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        import json
        try:
            data = json.loads(body.decode("utf-8"))
            args = data.get("params", {}).get("arguments", {})
            # If a url argument is present, simulate vulnerable egress by pinging it
            if "url" in args:
                target_url = args["url"]
                try:
                    with httpx.Client(timeout=2.0) as client:
                        client.get(target_url)
                except Exception:
                    pass

            response = {
                "jsonrpc": "2.0",
                "id": data.get("id", 1),
                "result": {"content": [{"type": "text", "text": "fetched content"}]},
            }
            res_bytes = json.dumps(response).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(res_bytes)))
            self.end_headers()
            self.wfile.write(res_bytes)
        except Exception as e:
            err_bytes = json.dumps({"error": str(e)}).encode("utf-8")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(err_bytes)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.mark.asyncio
async def test_live_network_dispatch_and_canary_callback() -> None:
    # 1. Start Mock MCP Target Server on ephemeral port
    target_httpd = HTTPServer(("127.0.0.1", 0), MockMCPTargetHandler)
    target_port = target_httpd.server_address[1]
    target_thread = threading.Thread(target=target_httpd.serve_forever, daemon=True)
    target_thread.start()

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_live.db")
        db = DatabaseManager(f"sqlite:///{db_path}")
        await db.apply_migrations()

        # 2. Start Canary Server on ephemeral port
        canary_server = CanaryServer("127.0.0.1", 0, db)
        canary_server.start()
        canary_port = canary_server.server.server_address[1]  # type: ignore[union-attr]
        canary_base_url = f"http://127.0.0.1:{canary_port}"

        try:
            guardrail = ScopeGuardrail(
                allowed_cidrs=["127.0.0.1/32"],
                allowed_domains=["localhost", "127.0.0.1"],
            )
            canary_mgr = CanaryManager(db, canary_base_url)
            orchestrator = EvaluationOrchestrator(db, guardrail, canary_mgr)

            tools_spec = {
                "tools": [
                    {
                        "name": "fetch_external_report",
                        "description": "Fetches external security report",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"url": {"type": "string"}},
                            "required": ["url"],
                        },
                    }
                ]
            }

            target = TargetSpec(
                id="target_live_01",
                name="Live Vulnerable MCP Server",
                target_type=TargetType.MCP_SERVER,
                base_url=f"http://127.0.0.1:{target_port}",
                allowed_domains=["localhost", "127.0.0.1"],
            )

            # Execute LIVE evaluation (simulate_execution=False)
            findings = await orchestrator.run_mcp_evaluation(
                target=target,
                tools_response=tools_spec,
                simulate_execution=False,
                canary_timeout=2.0,
            )

            assert len(findings) >= 1
            ssrf_finding = next((f for f in findings if f.owasp_category == OWASPCategory.API07_SSRF), None)
            assert ssrf_finding is not None
            assert "fetch_external_report" in ssrf_finding.title
            assert "token_uuid" in ssrf_finding.evidence
            assert ssrf_finding.evidence.get("source_ip") == "127.0.0.1"

        finally:
            canary_server.stop()
            target_httpd.shutdown()
            target_httpd.server_close()
