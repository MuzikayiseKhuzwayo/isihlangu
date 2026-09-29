"""MCP Inspector: Introspects Model Context Protocol (MCP) servers and extracts schemas."""

import json
from typing import TYPE_CHECKING, Any

from isihlangu.core.errors import TargetIntrospectionError
from isihlangu.core.types import MCPToolDefinition

if TYPE_CHECKING:
    from isihlangu.protocols.mcp_client import AsyncMCPClient


class MCPInspector:
    """Introspects MCP tool definitions, prompts, and resources."""

    def __init__(self) -> None:
        pass

    async def introspect_live_http(
        self, base_url: str, mcp_client: "AsyncMCPClient"
    ) -> list[MCPToolDefinition]:
        """Introspects a live HTTP MCP server by dispatching tools/list."""
        response = await mcp_client.call_http(base_url=base_url, method="tools/list")
        return self.parse_tools_response(response)

    async def introspect_live_stdio(
        self, command: str, args: list[str], mcp_client: "AsyncMCPClient"
    ) -> list[MCPToolDefinition]:
        """Introspects a local subprocess MCP server by dispatching tools/list."""
        response = await mcp_client.call_stdio(command=command, args=args, method="tools/list")
        return self.parse_tools_response(response)

    def parse_tools_response(self, response_data: dict[str, Any]) -> list[MCPToolDefinition]:
        """Parses the result of a JSON-RPC 'tools/list' request into structured tool definitions."""
        if "tools" in response_data:
            raw_tools = response_data["tools"]
        elif "result" in response_data and "tools" in response_data["result"]:
            raw_tools = response_data["result"]["tools"]
        else:
            raise TargetIntrospectionError(
                "Invalid MCP tools/list response: missing 'tools' key",
                details={"response": response_data},
            )

        tools_list = []
        for tool in raw_tools:
            name = tool.get("name", "unnamed_tool")
            description = tool.get("description", "")
            input_schema = tool.get("inputSchema", {}) or tool.get("input_schema", {})

            # Analyze sensitivity heuristics
            is_sensitive = self._is_sensitive_tool(name, description, input_schema)

            tools_list.append(
                MCPToolDefinition(
                    name=name,
                    description=description,
                    input_schema=input_schema,
                    is_sensitive=is_sensitive,
                    requires_auth=tool.get("requires_auth", False),
                )
            )

        return tools_list

    def _is_sensitive_tool(self, name: str, description: str, input_schema: dict[str, Any]) -> bool:
        """Determines if an MCP tool executes sensitive or privileged actions."""
        text_corpus = f"{name} {description} {json.dumps(input_schema)}".lower()
        sensitive_keywords = [
            "sql",
            "exec",
            "bash",
            "shell",
            "eval",
            "file",
            "write",
            "delete",
            "drop",
            "admin",
            "user",
            "token",
            "secret",
            "credential",
            "payment",
            "stripe",
            "webhook",
            "ssrf",
            "fetch",
            "http",
            "transfer",
            "export",
        ]
        return any(k in text_corpus for k in sensitive_keywords)

    def identify_schema_deficiencies(self, tool: MCPToolDefinition) -> list[str]:
        """Audits tool schema for missing constraints, unvalidated inputs, or broad wildcard parameters."""
        findings = []
        schema = tool.input_schema
        properties = schema.get("properties", {})

        if not properties and schema.get("type") == "object":
            findings.append("Unconstrained object: 'properties' is empty or missing.")

        for prop_name, prop_spec in properties.items():
            prop_type = prop_spec.get("type")
            # Check for unbounded strings
            if (
                prop_type == "string"
                and "maxLength" not in prop_spec
                and "pattern" not in prop_spec
                and "enum" not in prop_spec
            ):
                findings.append(
                    f"Unbounded string parameter: '{prop_name}' has no maxLength, pattern, or enum constraint."
                )
            # Check for lack of tenant identification
            if (
                prop_name in ["id", "record_id", "user_id", "account_id"]
                and "tenant_id" not in properties
                and "org_id" not in properties
            ):
                findings.append(
                    f"Potential multi-tenant risk: Parameter '{prop_name}' exists without tenant isolation parameter."
                )

        return findings
