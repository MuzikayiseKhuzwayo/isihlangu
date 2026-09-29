"""Async MCP JSON-RPC protocol client for tools/list and tools/call interactions."""

import asyncio
import json
from typing import Any

from isihlangu.core.errors import ProtocolExecutionError, ScopeViolationError
from isihlangu.core.guardrails import ScopeGuardrail


class AsyncMCPClient:
    """Communicates with MCP servers via stdio or HTTP JSON-RPC."""

    def __init__(self, guardrail: ScopeGuardrail) -> None:
        self.guardrail = guardrail
        self._request_id = 0

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    async def call_stdio(
        self, command: str, args: list[str], method: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Executes a JSON-RPC request against an MCP server running as a local subprocess."""
        req_id = self._next_id()
        payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params or {},
        }

        # Guardrail check on tool calls
        if method == "tools/call":
            tool_name = (params or {}).get("name", "")
            tool_args = (params or {}).get("arguments", {})
            if not self.guardrail.is_safe_tool_call(tool_name, tool_args):
                raise ScopeViolationError(
                    f"Tool call '{tool_name}' with args {tool_args} violates safety guardrail"
                )

        try:
            process = await asyncio.create_subprocess_exec(
                command,
                *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            req_str = json.dumps(payload) + "\n"
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=req_str.encode("utf-8")), timeout=15.0
            )

            if process.returncode != 0:
                raise ProtocolExecutionError(
                    f"MCP process exited with code {process.returncode}: {stderr.decode()}"
                )

            line = stdout.decode().strip()
            if not line:
                raise ProtocolExecutionError("MCP process returned empty response")

            # Parse first valid JSON-RPC line
            for subline in line.splitlines():
                if subline.strip().startswith("{"):
                    return json.loads(subline)

            return json.loads(line)

        except TimeoutError:
            raise ProtocolExecutionError("Timeout waiting for MCP stdio response")
        except json.JSONDecodeError as e:
            raise ProtocolExecutionError(f"Invalid JSON received from MCP server: {e}")
        except Exception as e:
            if isinstance(e, (ScopeViolationError, ProtocolExecutionError)):
                raise
            raise ProtocolExecutionError(f"MCP stdio execution failed: {e}") from e
