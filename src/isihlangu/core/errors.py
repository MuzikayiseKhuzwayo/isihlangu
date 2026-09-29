"""Core error hierarchy for Isihlangu with explicit typed contracts."""

from typing import Any


class IsihlanguError(Exception):
    """Base exception for all Isihlangu errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ScopeViolationError(IsihlanguError):
    """Raised when an action violates declared CIDR, IP, or domain scope guardrails."""


class TargetIntrospectionError(IsihlanguError):
    """Raised when target introspection (OpenAPI, GraphQL, MCP tools/list) fails."""


class ProtocolExecutionError(IsihlanguError):
    """Raised when protocol execution (MCP JSON-RPC, HTTP client) fails unexpectedly."""


class OracleVerificationError(IsihlanguError):
    """Raised when oracle verification fails or canary tracking encounters a fatal state."""


class DatastoreIntegrityError(IsihlanguError):
    """Raised when datastore schema or migration invariants fail."""


class RemediationError(IsihlanguError):
    """Raised when automated schema or RLS policy synthesis fails."""
