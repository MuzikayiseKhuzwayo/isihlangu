"""Async HTTP client with strict scope guardrails and error contracts."""

from typing import Any

import httpx

from isihlangu.core.errors import ProtocolExecutionError
from isihlangu.core.guardrails import ScopeGuardrail


class GuardedHTTPClient:
    """HTTP client enforcing scope guardrails, timeouts, and structured error responses."""

    def __init__(self, guardrail: ScopeGuardrail, timeout_seconds: float = 15.0) -> None:
        self.guardrail = guardrail
        self.timeout = timeout_seconds

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Executes an HTTP request after strictly validating destination against scope guardrails."""
        # 1. Invariant: Validate target URL against authorized CIDRs / domains
        self.guardrail.validate_url(url)

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.request(
                    method=method.upper(),
                    url=url,
                    headers=headers,
                    json=json_body,
                    params=params,
                )
                return response
        except httpx.TimeoutException as e:
            raise ProtocolExecutionError(
                f"HTTP request timed out connecting to '{url}': {e}"
            ) from e
        except httpx.RequestError as e:
            raise ProtocolExecutionError(f"HTTP request failed for '{url}': {e}") from e
