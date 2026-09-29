"""Deterministic Verification Oracle: The Zero-Hallucination Gate."""

from typing import Any

from isihlangu.core.types import (
    AttackHypothesis,
    ExecutionRecord,
    OOBToken,
    VerificationResult,
)
from isihlangu.oracle.state_diff import StateDiffEngine, StateSnapshot


class VerificationOracle:
    """Evaluates whether an attack hypothesis has succeeded based on concrete empirical evidence."""

    def __init__(self) -> None:
        self.diff_engine = StateDiffEngine()

    def verify_canary(self, hypothesis: AttackHypothesis, token: OOBToken) -> VerificationResult:
        """Verifies if an out-of-band network ping was recorded by the canary server."""
        if token.callback_received:
            return VerificationResult(
                is_verified=True,
                confidence=1.0,
                evidence={
                    "type": "oob_canary_callback",
                    "token_uuid": token.token_uuid,
                    "source_ip": token.callback_source_ip,
                    "payload": token.callback_payload,
                },
                reasoning=f"Out-of-band network connection confirmed from target IP {token.callback_source_ip}.",
            )
        return VerificationResult(
            is_verified=False,
            confidence=1.0,
            evidence={"token_uuid": token.token_uuid},
            reasoning="No out-of-band callback was received by the canary listener.",
        )

    def verify_unauthorized_access(
        self,
        hypothesis: AttackHypothesis,
        record: ExecutionRecord,
        expected_status: int = 403,
    ) -> VerificationResult:
        """Verifies if an unauthorized request bypassed access control."""
        if record.status_code is not None and record.status_code == 200:
            return VerificationResult(
                is_verified=True,
                confidence=0.95,
                evidence={
                    "status_code": record.status_code,
                    "response_payload": record.response_payload[:500],
                },
                reasoning=f"Expected authorization refusal ({expected_status}) but endpoint returned HTTP 200.",
            )
        return VerificationResult(
            is_verified=False,
            confidence=0.95,
            evidence={"status_code": record.status_code},
            reasoning="Endpoint correctly enforced authorization boundaries.",
        )

    def verify_state_mutation(
        self,
        hypothesis: AttackHypothesis,
        before_state: dict[str, Any],
        after_state: dict[str, Any],
        target_entity: str,
    ) -> VerificationResult:
        """Verifies if an unauthorized mutation actually occurred in target database or state."""
        snap_before = StateSnapshot.from_dict(before_state)
        snap_after = StateSnapshot.from_dict(after_state)
        diff = self.diff_engine.compute_diff(snap_before, snap_after)

        if self.diff_engine.has_unauthorized_mutation(diff, allowed_keys=[]):
            return VerificationResult(
                is_verified=True,
                confidence=1.0,
                evidence={"state_diff": diff, "target_entity": target_entity},
                reasoning=f"Unauthorized state modification confirmed for entity {target_entity}.",
            )

        return VerificationResult(
            is_verified=False,
            confidence=1.0,
            evidence={"state_diff": diff},
            reasoning="Target state remained unmodified. Finding refuted as zero side-effect.",
        )
