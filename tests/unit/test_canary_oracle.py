from isihlangu.core.types import AttackHypothesis, OOBToken
from isihlangu.oracle.state_diff import StateDiffEngine, StateSnapshot
from isihlangu.oracle.verifier import VerificationOracle


def test_oracle_canary_verification() -> None:
    oracle = VerificationOracle()
    hyp = AttackHypothesis(
        id="hyp_1",
        session_id="sess_1",
        category="ssrf_canary",
        description="SSRF test",
        target_component="fetch_tool",
        proposed_test="ping canary",
    )

    # 1. Negative case: no callback
    token_unverified = OOBToken(
        token_uuid="test-uuid-1",
        session_id="sess_1",
        expected_type="ssrf_out_of_band",
        target_component="fetch_tool",
        callback_received=False,
    )
    result_neg = oracle.verify_canary(hyp, token_unverified)
    assert result_neg.is_verified is False

    # 2. Positive case: verified callback
    token_verified = OOBToken(
        token_uuid="test-uuid-2",
        session_id="sess_1",
        expected_type="ssrf_out_of_band",
        target_component="fetch_tool",
        callback_received=True,
        callback_source_ip="10.0.0.5",
    )
    result_pos = oracle.verify_canary(hyp, token_verified)
    assert result_pos.is_verified is True
    assert "10.0.0.5" in result_pos.reasoning


def test_state_diff_engine() -> None:
    before = StateSnapshot.from_dict({"user_1": {"role": "member", "status": "active"}})
    after_tampered = StateSnapshot.from_dict({"user_1": {"role": "admin", "status": "active"}})

    diff = StateDiffEngine.compute_diff(before, after_tampered)
    assert "user_1" in diff["modified"]
    assert diff["modified"]["user_1"]["after"]["role"] == "admin"
    assert StateDiffEngine.has_unauthorized_mutation(diff, allowed_keys=[]) is True
