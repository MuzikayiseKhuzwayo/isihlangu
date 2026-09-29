"""Async MCP JSON-RPC protocol client for tools/list and tools/call interactions."""

import asyncio
import json
import time
from typing import Any

import httpx

from isihlangu.core.errors import ProtocolExecutionError, ScopeViolationError
from isihlangu.core.guardrails import ScopeGuardrail


class AsyncMCPClient:
    """Communicates with MCP servers via stdio or HTTP JSON-RPC."""

    def __init__(self, guardrail: ScopeGuardrail, timeout_seconds: float = 15.0) -> None:
        self.guardrail = guardrail
        self.timeout = timeout_seconds
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
                process.communicate(input=req_str.encode("utf-8")), timeout=self.timeout
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

    async def call_http(
        self,
        base_url: str,
        method: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Executes a JSON-RPC request over HTTP/HTTPS against a live MCP server."""
        # 1. Enforce Scope Guardrail
        self.guardrail.validate_url(base_url)

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

        req_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **(headers or {}),
        }

        try:
            start_time = time.monotonic()
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                res = await client.post(base_url, headers=req_headers, json=payload)

            latency_ms = int((time.monotonic() - start_time) * 1000)

            if res.status_code != 200:
                raise ProtocolExecutionError(
                    f"MCP HTTP request to '{base_url}' returned HTTP {res.status_code}: {res.text}",
                    details={"status_code": res.status_code, "latency_ms": latency_ms},
                )

            data = res.json()
            if "error" in data:
                error_msg = data["error"].get("message", json.dumps(data["error"]))
                raise ProtocolExecutionError(
                    f"MCP server returned JSON-RPC error: {error_msg}",
                    details={"error": data["error"], "latency_ms": latency_ms},
                )

            return data

        except httpx.TimeoutException as e:
            raise ProtocolExecutionError(
                f"MCP HTTP request timed out connecting to '{base_url}': {e}"
            ) from e
        except httpx.RequestError as e:
            raise ProtocolExecutionError(
                f"MCP HTTP request failed connecting to '{base_url}': {e}"
            ) from e
        except json.JSONDecodeError as e:
            raise ProtocolExecutionError(
                f"Invalid JSON returned from MCP server at '{base_url}': {e}"
            ) from e
