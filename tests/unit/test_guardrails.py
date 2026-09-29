import pytest

from isihlangu.core.errors import ScopeViolationError
from isihlangu.core.guardrails import ScopeGuardrail


def test_scope_guardrail_allowed_domains() -> None:
    guardrail = ScopeGuardrail(
        allowed_cidrs=["127.0.0.1/32"],
        allowed_domains=["localhost", "api.internal"],
    )

    # Valid domains
    guardrail.validate_url("http://localhost:8000/api")
    guardrail.validate_url("https://sub.api.internal/v1/resource")
    guardrail.validate_url("http://127.0.0.1:8877/c/test-token")

    # Out of scope domain must raise ScopeViolationError
    with pytest.raises(ScopeViolationError):
        guardrail.validate_url("https://unauthorized-domain.com/secret")

    with pytest.raises(ScopeViolationError):
        guardrail.validate_url("http://8.8.8.8/exploit")


def test_scope_guardrail_safe_tool_calls() -> None:
    guardrail = ScopeGuardrail(
        allowed_cidrs=["127.0.0.1/32"],
        allowed_domains=["localhost"],
    )

    # Benign tool call
    assert guardrail.is_safe_tool_call("fetch_data", {"url": "http://localhost:8000"}) is True

    # Destructive tool call blocked
    assert guardrail.is_safe_tool_call("drop_database", {"table": "users"}) is False

    # Out-of-scope URL argument blocked
    assert guardrail.is_safe_tool_call("fetch_data", {"url": "http://evil.com"}) is False
