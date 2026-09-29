"""Scope guardrails: Strict boundary enforcement to prevent out-of-scope actions."""

import ipaddress
import urllib.parse

from isihlangu.core.errors import ScopeViolationError


class ScopeGuardrail:
    """Evaluates target hostnames, IPs, and URLs against authorized boundaries."""

    def __init__(self, allowed_cidrs: list[str], allowed_domains: list[str]) -> None:
        self.allowed_cidrs = [ipaddress.ip_network(cidr.strip()) for cidr in allowed_cidrs]
        self.allowed_domains = [d.strip().lower() for d in allowed_domains]

    def validate_url(self, url: str) -> None:
        """Validates that a URL's destination is within the authorized scope."""
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            raise ScopeViolationError(f"Invalid URL without hostname: '{url}'")

        hostname = hostname.lower()

        # 1. Check exact domain or subdomain match
        for domain in self.allowed_domains:
            if hostname == domain or hostname.endswith("." + domain):
                return

        # 2. Check if hostname is an IP within allowed CIDRs
        try:
            ip = ipaddress.ip_address(hostname)
            for cidr in self.allowed_cidrs:
                if ip in cidr:
                    return
        except ValueError:
            pass

        raise ScopeViolationError(
            f"Access blocked by scope guardrail: Hostname '{hostname}' is not authorized. "
            f"Allowed domains: {self.allowed_domains}, Allowed CIDRs: {[str(c) for c in self.allowed_cidrs]}"
        )

    def is_safe_tool_call(self, tool_name: str, arguments: dict) -> bool:
        """Inspects tool call arguments for safety violation or unauthorized egress."""
        tool_name_lower = tool_name.lower()

        # Dangerous destructive tool calls in safe mode
        forbidden_substrings = ["drop_database", "delete_all", "rm_rf", "format_disk"]
        for bad in forbidden_substrings:
            if bad in tool_name_lower:
                return False

        # If argument contains a target URL, validate it
        for val in arguments.values():
            if isinstance(val, str) and (val.startswith("http://") or val.startswith("https://")):
                try:
                    self.validate_url(val)
                except ScopeViolationError:
                    return False

        return True
