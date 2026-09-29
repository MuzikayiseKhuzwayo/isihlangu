"""The Operator Node: Synthesizes protocol-accurate payloads for execution."""

from typing import Any

from isihlangu.core.types import MCPToolDefinition


class OperatorNode:
    """Specialist node that crafts valid protocol payloads."""

    def build_mcp_canary_payload(
        self, tool: MCPToolDefinition, canary_url: str
    ) -> dict[str, Any]:
        """Crafts JSON-RPC arguments for an MCP tool that accepts URLs."""
        args: dict[str, Any] = {}
        props = tool.input_schema.get("properties", {})

        # Search for property expecting a URL
        url_key = None
        for key, prop in props.items():
            if "url" in key.lower() or "link" in key.lower() or "uri" in key.lower():
                url_key = key
                break

        if url_key:
            args[url_key] = canary_url
        else:
            # If no obvious key, populate first string property or generic 'url'
            for key, prop in props.items():
                if prop.get("type") == "string":
                    args[key] = canary_url
                    break
            if not args:
                args["url"] = canary_url

        return {
            "name": tool.name,
            "arguments": args,
        }

    def build_tenant_test_payload(
        self, tool: MCPToolDefinition, foreign_tenant_id: str = "tenant_test_999"
    ) -> dict[str, Any]:
        """Crafts JSON-RPC arguments attempting cross-tenant manipulation."""
        args: dict[str, Any] = {}
        props = tool.input_schema.get("properties", {})

        for key, prop in props.items():
            if "tenant" in key.lower() or "org" in key.lower():
                args[key] = foreign_tenant_id
            elif "id" in key.lower():
                args[key] = "record_victim_456"
            elif prop.get("type") == "string":
                args[key] = "probe"

        return {
            "name": tool.name,
            "arguments": args,
        }
