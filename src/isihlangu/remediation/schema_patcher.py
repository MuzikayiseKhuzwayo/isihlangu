"""MCP Schema Patcher: Synthesizes defensive JSON schema constraints for vulnerable tools."""

import copy
from typing import Any


class MCPSchemaPatcher:
    """Generates hardened JSON schemas for MCP tools."""

    def patch_url_property(
        self, original_schema: dict[str, Any], allowed_domains: list[str] | None = None
    ) -> dict[str, Any]:
        """Adds domain/regex constraints to URL properties in tool schemas to prevent SSRF."""
        patched = copy.deepcopy(original_schema)
        props = patched.get("properties", {})

        domains = allowed_domains or ["localhost", "127.0.0.1"]
        escaped_domains = [d.replace(".", r"\.") for d in domains]
        domain_pattern = (
            r"^https?:\/\/(?:[a-zA-Z0-9_\-]+\.)*(?:"
            + "|".join(escaped_domains)
            + r")(?::\d+)?(?:\/.*)?$"
        )

        for key, prop in props.items():
            if "url" in key.lower() or "uri" in key.lower():
                prop["pattern"] = domain_pattern
                prop["description"] = (
                    prop.get("description", "")
                    + f" [SECURED: Destination strictly restricted to: {', '.join(domains)}]"
                ).strip()

        return patched

    def add_tenant_isolation(self, original_schema: dict[str, Any]) -> dict[str, Any]:
        """Injects mandatory tenant_id parameter with UUID pattern into tool inputSchema."""
        patched = copy.deepcopy(original_schema)
        props = patched.setdefault("properties", {})
        required = patched.setdefault("required", [])

        if "tenant_id" not in props:
            props["tenant_id"] = {
                "type": "string",
                "format": "uuid",
                "pattern": r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
                "description": "[MANDATORY ISOLATION] The verified tenant UUID of the requesting organization.",
            }

        if "tenant_id" not in required:
            required.append("tenant_id")

        return patched
