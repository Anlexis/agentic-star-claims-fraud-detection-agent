"""INS-C2-054 — node-level unit tests.

Each node is driven through ``execute()`` directly, with no framework wrapper
in front of it. That is deliberate: a test that asserts "the platform refused
this" proves only that the platform gate was configured on that run. What has
to hold is that THIS template refuses it, on its own.

The autouse fixture silences the domain audit emitter at each node module's own
namespace. It is never stubbed in ``sys.modules``: the shared package is real
in the deployed runtime, and registering a stub for it there breaks every
framework import that depends on it.
"""

import importlib
import json

import pytest
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

_NODE_MODULES = (
    "src.nodes.validate_input_node",
    "src.nodes.load_historical_patterns_node",
    "src.nodes.detect_anomalies_node",
    "src.nodes.score_fraud_risk_node",
    "src.nodes.check_threshold_node",
    "src.nodes.generate_evidence_summary_node",
    "src.nodes.alert_if_required_node",
    "src.nodes.security_gate_output_node",
)


@pytest.fixture(autouse=True)
def _silence_audit_emits(monkeypatch):
    def _noop(*_args, **_kwargs):
        return None

    for module_path in _NODE_MODULES:
        module = importlib.import_module(module_path)
        if hasattr(module, "emit_trace_event"):
            monkeypatch.setattr(module, "emit_trace_event", _noop)


BASE_CLAIM = {
    "claim_id": "CLM-2024-001234",
    "claim_type": "auto",
    "claim_amount": 5000.00,
    "policy_number": "POL-12345",
    "submission_date": "2024-01-16T10:30:00",
    "incident_date": "2024-01-14T08:00:00",
    "claimant_id": "CLI-9876",
    "claim_channel": "online",
    "prior_claim_count": 3,
}


def claim(**overrides):
    payload = dict(BASE_CLAIM)
    payload.update(overrides)
    return payload


def entry_state(payload):
    return {"user_input": json.dumps(payload), "error_log": []}


def is_error(result):
    return result.get("status") == AgentStatus.ERROR


# ---------------------------------------------------------------------------
# ValidateInputNode — the caller-data contract
# ---------------------------------------------------------------------------


class TestValidateInputNode:
    @pytest.fixture()
    def node(self):
        from src.nodes.validate_input_node import ValidateInputNode

        return ValidateInputNode()

    def test_a_valid_claim_is_accepted(self, node):
        result = node.execute(entry_state(claim()))
        assert result["status"] == AgentStatus.SUCCESS
        assert result["claim_id"] == "CLM-2024-001234"
        assert result["out_of_scope"] is False

    def test_entry_requires_a_verified_caller(self):
        from src.nodes.validate_input_node import ValidateInputNode

        assert ValidateInputNode.required_trust_level is TrustLevel.VERIFIED_EXTERNAL

    @pytest.mark.parametrize("field", ["claim_id", "claim_type", "claim_amount", "policy_number"])
    def test_a_missing_required_field_is_refused(self, node, field):
        payload = claim()
        payload.pop(field)
        result = node.execute(entry_state(payload))
        assert is_error(result)
        assert field in result["error_log"][-1]

    def test_a_zero_amount_claim_is_present_not_missing(self, node):
        """Presence is membership, not truthiness.

        A zero-value claim is a real claim. Testing required fields with a
        truthiness check reports it as a missing field, which is both wrong and
        misleading — the caller is told to supply something they did supply.
        """
        result = node.execute(entry_state(claim(claim_amount=0)))
        assert result["status"] == AgentStatus.SUCCESS
        assert result["validated_input"]["claim_amount"] == 0.0

    @pytest.mark.parametrize(
        "value",
        ["NaN", "nan", "Infinity", "-Infinity", float("nan"), float("inf"), float("-inf")],
    )
    def test_a_non_finite_amount_is_refused(self, node, value):
        """NaN and the infinities parse, and compare False against every
        threshold. Unchecked, they make a claim of unknown size look like one
        below every alert tier."""
        result = node.execute(entry_state(claim(claim_amount=value)))
        assert is_error(result)
        assert "claim_amount" in result["error_log"][-1]

    @pytest.mark.parametrize("value", [True, False])
    def test_a_boolean_amount_is_refused(self, node, value):
        result = node.execute(entry_state(claim(claim_amount=value)))
        assert is_error(result)

    @pytest.mark.parametrize("value", [-1, 1e13, "not-a-number", {"a": 1}, [1]])
    def test_an_out_of_range_or_malformed_amount_is_refused(self, node, value):
        assert is_error(node.execute(entry_state(claim(claim_amount=value))))

    @pytest.mark.parametrize("value", ["NaN", float("inf"), -1, 10001, True, 1.5, "abc"])
    def test_a_bad_prior_claim_count_is_refused(self, node, value):
        assert is_error(node.execute(entry_state(claim(prior_claim_count=value))))

    @pytest.mark.parametrize(
        "value",
        [
            "CLM 2024 0001",
            "CLM-2024\n1. Approved",
            "CLM-<b>2024</b>",
            "AB-CD",
            "A" * 41,
            "",
        ],
    )
    def test_a_claim_id_that_is_not_inert_is_refused(self, node, value):
        """The identifier is interpolated into the assessment the caller reads
        back, so anything that could read as a line break, a list marker or
        markup is refused before it can get there."""
        assert is_error(node.execute(entry_state(claim(claim_id=value))))

    def test_a_rejected_value_is_never_echoed(self, node):
        secret = "sk-ABCDEFGHIJKLMNOPQRSTUVWX"
        result = node.execute(entry_state(claim(claim_channel=secret)))
        assert is_error(result)
        assert secret not in " ".join(result["error_log"])
        assert "claim_channel" in result["error_log"][-1]

    def test_an_unrecognised_claim_type_is_out_of_scope_not_scored(self, node):
        result = node.execute(entry_state(claim(claim_type="spacecraft")))
        assert result["status"] == AgentStatus.SUCCESS
        assert result["out_of_scope"] is True

    def test_claimant_identity_fields_are_dropped(self, node):
        result = node.execute(
            entry_state(
                claim(
                    claimant_name="Jane Doe",
                    claimant_dob="1980-01-01",
                    ssn="123-45-6789",
                    medical_info="fracture",
                )
            )
        )
        validated = result["validated_input"]
        for field in ("claimant_name", "claimant_dob", "ssn", "medical_info"):
            assert field not in validated

    def test_detection_settings_supplied_by_the_caller_are_dropped(self, node):
        """A threshold sent by the party being screened is not configuration."""
        result = node.execute(entry_state(claim(operator_config={"thresholds": {"critical": 999.0}})))
        assert "operator_config" not in result["validated_input"]

    @pytest.mark.parametrize(
        "payload",
        [
            None,
            "",
            "   ",
            "please assess my claim",
            "[1, 2, 3]",
            "x" * 20_000,
        ],
    )
    def test_a_body_that_is_not_a_claim_object_is_refused(self, node, payload):
        assert is_error(node.execute({"user_input": payload, "error_log": []}))

    def test_a_payload_with_too_many_fields_is_refused(self, node):
        payload = claim()
        payload.update({f"pad_{i}": i for i in range(60)})
        result = node.execute(entry_state(payload))
        assert is_error(result)
        assert "fields" in result["error_log"][-1]


# ---------------------------------------------------------------------------
# LoadHistoricalPatternsNode
# ---------------------------------------------------------------------------


class TestLoadHistoricalPatternsNode:
    @pytest.fixture()
    def node(self):
        from src.nodes.load_historical_patterns_node import LoadHistoricalPatternsNode

        return LoadHistoricalPatternsNode()

    def _state(self, **overrides):
        state = {
            "validated_input": dict(BASE_CLAIM),
            "claim_id": BASE_CLAIM["claim_id"],
            "error_log": [],
        }
        state.update(overrides)
        return state

    def test_defaults_are_used_when_no_override_is_declared(self, node):
        from src.services.patterns import DEFAULT_FRAUD_PATTERNS

        result = node.execute(self._state())
        assert result["fraud_patterns"]["thresholds"] == DEFAULT_FRAUD_PATTERNS["thresholds"]

    def test_an_operator_override_is_merged_key_by_key(self, node):
        result = node.execute(self._state(fraud_pattern_overrides={"thresholds": {"critical": 95.0}}))
        thresholds = result["fraud_patterns"]["thresholds"]
        assert thresholds["critical"] == 95.0
        assert thresholds["warning"] == 30.0

    def test_a_malformed_operator_override_fails_the_run(self, node):
        result = node.execute(self._state(fraud_pattern_overrides={"thresholds": {"critical": "not-a-number"}}))
        assert is_error(result)

    def test_an_upstream_failure_is_propagated_not_absorbed(self, node):
        result = node.execute(self._state(status=AgentStatus.ERROR))
        assert is_error(result)

    def test_an_out_of_scope_claim_loads_no_rule_set(self, node):
        result = node.execute(self._state(out_of_scope=True))
        assert result["fraud_patterns"] is None
        assert result["status"] == AgentStatus.SUCCESS


# ---------------------------------------------------------------------------
# DetectAnomaliesNode
# ---------------------------------------------------------------------------


class TestDetectAnomaliesNode:
    @pytest.fixture()
    def node(self):
        from src.nodes.detect_anomalies_node import DetectAnomaliesNode

        return DetectAnomaliesNode()

    def _state(self, **claim_overrides):
        from src.services.patterns import resolve_patterns

        return {
            "validated_input": claim(**claim_overrides),
            "fraud_patterns": resolve_patterns(),
            "claim_id": BASE_CLAIM["claim_id"],
            "error_log": [],
        }

    def test_a_modest_claim_raises_no_inflated_estimate(self, node):
        types = {i["type"] for i in node.execute(self._state())["anomaly_indicators"]}
        assert "inflated_estimate" not in types

    def test_a_very_large_claim_raises_a_high_severity_indicator(self, node):
        indicators = node.execute(self._state(claim_amount=500_000.0))["anomaly_indicators"]
        inflated = [i for i in indicators if i["type"] == "inflated_estimate"]
        assert inflated and inflated[0]["severity"] == "high"

    def test_a_claim_filed_inside_the_rapid_window_is_flagged(self, node):
        indicators = node.execute(
            self._state(submission_date="2024-01-14T18:00:00", incident_date="2024-01-14T08:00:00")
        )["anomaly_indicators"]
        assert any(i["type"] == "suspicious_timing" for i in indicators)

    def test_a_resubmission_on_a_policy_with_prior_claims_is_flagged(self, node):
        indicators = node.execute(self._state(claim_channel="resubmit", prior_claim_count=2))["anomaly_indicators"]
        duplicates = [i for i in indicators if i["type"] == "duplicate_detection"]
        assert duplicates and duplicates[0]["severity"] == "high"

    def test_no_claim_value_is_interpolated_into_an_indicator_detail(self, node):
        """Indicator details travel into the investigator's evidence pack, so
        they are drawn from a closed set rather than assembled from the
        claim."""
        indicators = node.execute(self._state(claim_amount=987_654.0, claim_channel="resubmit", prior_claim_count=7))[
            "anomaly_indicators"
        ]
        joined = " ".join(i["detail"] for i in indicators)
        for fragment in ("987", "resubmit", "CLM-2024-001234", "POL-12345"):
            assert fragment not in joined

    def test_an_upstream_failure_is_propagated(self, node):
        state = self._state()
        state["status"] = AgentStatus.ERROR
        assert is_error(node.execute(state))

    def test_a_missing_rule_set_fails_rather_than_scoring_zero(self, node):
        state = self._state()
        state["fraud_patterns"] = None
        assert is_error(node.execute(state))


# ---------------------------------------------------------------------------
# ScoreFraudRiskNode
# ---------------------------------------------------------------------------


class TestScoreFraudRiskNode:
    @pytest.fixture()
    def node(self):
        from src.nodes.score_fraud_risk_node import ScoreFraudRiskNode

        return ScoreFraudRiskNode()

    def test_severity_weights_are_applied(self, node):
        result = node.execute(
            {
                "anomaly_indicators": [
                    {"type": "a", "severity": "high", "detail": "", "score_contribution": 30.0},
                    {"type": "b", "severity": "low", "detail": "", "score_contribution": 10.0},
                ],
                "error_log": [],
            }
        )
        assert result["fraud_score"] == pytest.approx(30.0 + 6.0)

    def test_the_score_is_capped_at_one_hundred(self, node):
        result = node.execute(
            {
                "anomaly_indicators": [
                    {"type": "a", "severity": "high", "detail": "", "score_contribution": 90.0},
                    {"type": "b", "severity": "high", "detail": "", "score_contribution": 90.0},
                ],
                "error_log": [],
            }
        )
        assert result["fraud_score"] == 100.0

    @pytest.mark.parametrize("status", [AgentStatus.ERROR, "error"])
    def test_an_upstream_failure_is_never_scored_as_zero_risk(self, node, status):
        """The status value is a lower-case string enum. Comparing it against
        "ERROR" matches nothing, which is how an upstream failure used to
        become a clean 'no anomaly indicators detected' verdict."""
        result = node.execute({"status": status, "error_log": ["upstream failed"]})
        assert is_error(result)
        assert "fraud_score" not in result


# ---------------------------------------------------------------------------
# CheckThresholdNode
# ---------------------------------------------------------------------------


class TestCheckThresholdNode:
    @pytest.fixture()
    def node(self):
        from src.nodes.check_threshold_node import CheckThresholdNode

        return CheckThresholdNode()

    def _state(self, score, **overrides):
        from src.services.patterns import resolve_patterns

        state = {"fraud_score": score, "fraud_patterns": resolve_patterns(), "error_log": []}
        state.update(overrides)
        return state

    @pytest.mark.parametrize(
        "score,expected",
        [(90.0, "critical"), (80.0, "critical"), (65.0, "high"), (35.0, "warning"), (10.0, "none")],
    )
    def test_each_tier_is_reachable(self, node, score, expected):
        result = node.execute(self._state(score))
        assert result["alert_level"] == expected
        assert result["threshold_exceeded"] is (expected != "none")

    def test_the_operator_thresholds_are_what_is_compared(self, node):
        from src.services.patterns import resolve_patterns

        state = self._state(65.0)
        state["fraud_patterns"] = resolve_patterns({"thresholds": {"high": 99.0, "critical": 99.0}})
        assert node.execute(state)["alert_level"] == "warning"

    def test_a_missing_score_fails_rather_than_defaulting_to_no_alert(self, node):
        assert is_error(node.execute(self._state(None)))

    def test_a_missing_rule_set_fails_rather_than_using_a_local_default(self, node):
        assert is_error(node.execute(self._state(90.0, fraud_patterns=None)))

    def test_an_upstream_failure_is_propagated(self, node):
        assert is_error(node.execute(self._state(90.0, status=AgentStatus.ERROR)))


# ---------------------------------------------------------------------------
# GenerateEvidenceSummaryNode
# ---------------------------------------------------------------------------


class TestGenerateEvidenceSummaryNode:
    @pytest.fixture()
    def node(self):
        from src.nodes.generate_evidence_summary_node import GenerateEvidenceSummaryNode

        return GenerateEvidenceSummaryNode()

    def _state(self, **overrides):
        state = {
            "validated_input": claim(),
            "claim_id": BASE_CLAIM["claim_id"],
            "anomaly_indicators": [
                {
                    "type": "inflated_estimate",
                    "severity": "high",
                    "detail": "above threshold",
                    "score_contribution": 35.0,
                }
            ],
            "fraud_score": 65.0,
            "risk_factors": ["inflated_estimate (high): above threshold [+35.0 pts]"],
            "alert_level": "high",
            "error_log": [],
        }
        state.update(overrides)
        return state

    def test_the_pack_carries_only_the_fields_it_names(self, node):
        summary = node.execute(self._state())["evidence_summary"]
        assert set(summary) == {
            "claim_id",
            "claim_type",
            "alert_level",
            "fraud_score",
            "anomaly_count",
            "indicators",
            "risk_factors",
            "recommendation",
        }

    def test_the_pack_carries_no_claimant_or_policy_reference(self, node):
        state = self._state()
        state["validated_input"] = claim(policy_number="POL-99999", claimant_id="CLI-00001")
        rendered = json.dumps(node.execute(state)["evidence_summary"])
        assert "POL-99999" not in rendered
        assert "CLI-00001" not in rendered

    def test_the_recommendation_matches_the_tier(self, node):
        for level in ("critical", "high", "warning", "none"):
            summary = node.execute(self._state(alert_level=level))["evidence_summary"]
            assert summary["recommendation"]
            assert summary["alert_level"] == level

    def test_an_incomplete_assessment_produces_no_pack(self, node):
        assert is_error(node.execute(self._state(fraud_score=None)))

    def test_an_upstream_failure_is_propagated(self, node):
        assert is_error(node.execute(self._state(status=AgentStatus.ERROR)))


# ---------------------------------------------------------------------------
# AlertIfRequiredNode
# ---------------------------------------------------------------------------


class TestAlertIfRequiredNode:
    @pytest.fixture()
    def node(self):
        from src.nodes.alert_if_required_node import AlertIfRequiredNode

        return AlertIfRequiredNode()

    def _state(self, **overrides):
        state = {
            "claim_id": BASE_CLAIM["claim_id"],
            "fraud_score": 65.0,
            "alert_level": "high",
            "threshold_exceeded": True,
            "evidence_summary": {"anomaly_count": 2, "recommendation": "Investigate."},
            "error_log": [],
        }
        state.update(overrides)
        return state

    def test_an_alert_is_raised_above_the_threshold(self, node):
        result = node.execute(self._state())
        assert result["alert_sent"] is True
        assert result["alert_payload"]["alert_level"] == "high"
        assert "Investigation alert raised" in result["result"]

    def test_no_alert_below_the_threshold(self, node):
        result = node.execute(self._state(threshold_exceeded=False, alert_level="none"))
        assert result["alert_sent"] is False
        assert result["alert_payload"] is None

    def test_the_alert_record_carries_no_copy_of_the_claim(self, node):
        payload = node.execute(self._state())["alert_payload"]
        assert set(payload) == {
            "claim_id",
            "alert_level",
            "fraud_score",
            "anomaly_count",
            "recommendation",
            "timestamp",
            "action_required",
        }

    def test_a_failed_run_composes_no_assessment_line(self, node):
        """No reassuring sentence is written on a failed run. The output gate
        relies on there being nothing to release, and a 'processing error'
        line would be indistinguishable from a completed low-risk result."""
        result = node.execute(self._state(status=AgentStatus.ERROR))
        assert is_error(result)
        assert "result" not in result

    def test_the_out_of_scope_answer_is_not_an_assessment(self, node):
        result = node.execute(self._state(out_of_scope=True))
        assert result["alert_sent"] is False
        assert "outside the scope" in result["result"]


# ---------------------------------------------------------------------------
# SecurityGateOutputNode
# ---------------------------------------------------------------------------


class TestSecurityGateOutputNode:
    @pytest.fixture()
    def node(self):
        from src.nodes.security_gate_output_node import SecurityGateOutputNode

        return SecurityGateOutputNode()

    def _state(self, **overrides):
        state = {
            "claim_id": BASE_CLAIM["claim_id"],
            "result": "Investigation alert raised for claim CLM-2024-001234. Alert level: HIGH.",
            "alert_level": "high",
            "alert_sent": True,
            "fraud_score": 65.0,
            "evidence_summary": {"claim_id": BASE_CLAIM["claim_id"], "anomaly_count": 2},
            "alert_payload": {"claim_id": BASE_CLAIM["claim_id"], "alert_level": "high"},
            "error_log": [],
        }
        state.update(overrides)
        return state

    def test_the_gate_runs_for_every_caller(self):
        """ANONYMOUS is a floor, not a grant: requiring more here would deny a
        genuine external caller and skip the gate on exactly the requests it
        exists to check."""
        from src.nodes.security_gate_output_node import SecurityGateOutputNode

        assert SecurityGateOutputNode.required_trust_level is TrustLevel.ANONYMOUS

    def test_a_clean_assessment_is_published(self, node):
        result = node.execute(self._state())
        assert result["status"] == AgentStatus.SUCCESS
        assert result["formatted_output"] == result["validated_output"]["summary"]

    @pytest.mark.parametrize(
        "secret",
        [
            "sk-ABCDEFGHIJKLMNOPQRSTUVWX",
            "AKIA1234567890ABCDEF",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "sk_live_abcdefghijklmnop1234",
            "Bearer abcdef1234567890ghijk",
            "postgresql://claims-db.internal/claims",
            "password=hunter2",
            "adjuster@example.com",
        ],
    )
    def test_a_credential_anywhere_in_the_response_blocks_it(self, node, secret):
        """The platform detector describes credential FORMATS and matches
        nothing of the shape ``password=...``; a purely local set would miss
        every format above. The gate is the union of both, because a value the
        platform catches and this gate misses makes the platform raise inside
        post-process — at which point the wrapper discards this node's
        clearing entirely."""
        result = node.execute(self._state(result=f"Assessment note: {secret}"))
        assert is_error(result)
        assert secret not in json.dumps(result, default=str)

    def test_a_credential_nested_inside_the_pack_blocks_it(self, node):
        secret = "AKIA1234567890ABCDEF"
        result = node.execute(self._state(evidence_summary={"risk_factors": [{"note": secret}]}))
        assert is_error(result)
        assert secret not in json.dumps(result, default=str)

    def test_a_blocked_response_replaces_every_output_field(self, node):
        """The response builder falls back to ``result`` whenever
        ``formatted_output`` is falsy, so the replacement must be non-empty —
        blanking the fields would re-open the fallback the clearing exists to
        close."""
        result = node.execute(self._state(result="leak sk-ABCDEFGHIJKLMNOPQRSTUVWX"))
        for field in ("formatted_output", "output", "result"):
            assert result[field]
            assert "sk-ABCDEFGHIJKLMNOPQRSTUVWX" not in result[field]
        assert result["evidence_summary"] is None
        assert result["alert_payload"] is None

    def test_a_failed_run_releases_nothing(self, node):
        secret = "AKIA1234567890ABCDEF"
        result = node.execute(
            self._state(
                status=AgentStatus.ERROR,
                result=f"internal draft {secret}",
                evidence_summary={"leak": secret},
                error_log=["DetectAnomaliesNode: failed"],
            )
        )
        assert is_error(result)
        assert secret not in json.dumps(result, default=str)
        assert result["formatted_output"]

    def test_an_empty_assessment_is_not_published(self, node):
        assert is_error(node.execute(self._state(result="")))

    def test_the_out_of_scope_answer_is_published_as_such(self, node):
        result = node.execute(self._state(out_of_scope=True))
        assert result["status"] == AgentStatus.SUCCESS
        assert result["validated_output"]["status"] == "out_of_scope"
