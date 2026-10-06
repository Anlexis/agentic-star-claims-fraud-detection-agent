"""INS-C2-054 — the two properties that only hold across the whole graph.

1. A value declared in ``config/config.yaml`` reaches the detectors and changes
   the answer. The subgraph boundary hands one string to the inner graph and
   nothing else, so a declared setting has four links to cross before a
   detector reads it. A test at any single link would pass on a chain that is
   broken further along, and the symptom of a broken chain is not an error —
   it is an agent that quietly runs on defaults while the file that declares
   the settings still reads as authoritative.

2. Nothing reaches the caller that the output gate did not pass. The response
   builder falls back to the raw result whenever the formatted output is
   absent or empty, so containment is a property of the whole invocation, not
   of one node's return value.
"""

import json

import pytest
from framework.errors import ConfigError
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel

from src.graph.graph import InsuranceClaimsFraudDetectionInvestigatorAlertAgent

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


def run(payload, config=None):
    agent = InsuranceClaimsFraudDetectionInvestigatorAlertAgent(config=config)
    ctx = InvocationContext(caller_trust_level=TrustLevel.VERIFIED_EXTERNAL)
    return agent.invoke(json.dumps(payload), ctx=ctx)


HOT_CLAIM = claim(claim_amount=999_999.0, claim_channel="resubmit")


class TestDeclaredConfigReachesTheDetectors:
    def test_the_shipped_config_file_is_what_the_entry_point_loads(self):
        """The deployment file itself, not a fixture: a config the tests
        construct by hand proves the plumbing and not the file."""
        import src.api.server as server

        assert server.agent.config["max_retry"] == 3
        assert server.agent.config["fraud_patterns"]["thresholds"]["critical"] == 75.0

    def test_raising_the_thresholds_changes_the_tier(self):
        default = run(HOT_CLAIM)
        raised = run(
            HOT_CLAIM,
            {"fraud_patterns": {"thresholds": {"warning": 99.0, "high": 99.0, "critical": 99.0}}},
        )
        assert "Alert level: HIGH" in default["output"]
        assert "Alert level: none" in raised["output"]

    def test_lowering_an_amount_band_changes_the_score(self):
        default = run(claim())
        lowered = run(
            claim(),
            {
                "fraud_patterns": {
                    "inflated_estimate": {"high_amount_threshold": 1.0, "very_high_amount_threshold": 2.0}
                }
            },
        )
        assert "Risk score: 0.0" in default["output"]
        assert "Risk score: 35.0" in lowered["output"]

    def test_disabling_a_detector_removes_its_contribution(self):
        enabled = run(HOT_CLAIM)
        disabled = run(HOT_CLAIM, {"fraud_patterns": {"duplicate_detection": {"enabled": False}}})
        assert "Risk score: 65.0" in enabled["output"]
        assert "Risk score: 35.0" in disabled["output"]

    @pytest.mark.parametrize(
        "bad",
        [
            {"fraud_patterns": {"thresholds": {"critical": float("nan")}}},
            {"fraud_patterns": {"thresholds": {"warning": 90.0, "high": 10.0}}},
            {"fraud_patterns": {"unknown_section": {"x": 1}}},
            {"fraud_patterns": {"thresholds": {"criticall": 80.0}}},
        ],
    )
    def test_a_malformed_config_fails_at_startup(self, bad):
        """At construction, not at the moment a claim needed escalating."""
        with pytest.raises(ConfigError):
            InsuranceClaimsFraudDetectionInvestigatorAlertAgent(config=bad).compile()


class TestCallerDataCannotSupplyDetectionSettings:
    def test_a_threshold_in_the_claim_payload_does_not_apply(self):
        """A detection threshold sent by the party being screened is not a
        setting. Merged, it let a claim scoring 65 report 'no alert required'."""
        tampered = dict(HOT_CLAIM)
        tampered["operator_config"] = {"thresholds": {"warning": 999.0, "high": 999.0, "critical": 999.0}}
        assert "Alert level: HIGH" in run(tampered)["output"]

    def test_the_same_tampering_on_the_out_of_scope_path_does_not_apply(self):
        """The out-of-scope path was where it landed: the scope decision did
        not cross the subgraph boundary, so an unrecognised claim type was
        scored anyway — on the raw payload, thresholds and all."""
        tampered = dict(HOT_CLAIM, claim_type="spacecraft")
        tampered["operator_config"] = {"thresholds": {"critical": 999.0}}
        body = run(tampered)
        assert "outside the scope" in body["output"]
        assert "Risk score" not in body["output"]


class TestContainment:
    def test_a_failed_run_publishes_no_partial_assessment(self):
        body = run({"claim_id": "CLM-2024-001234"})
        assert body["status"] != "success"
        assert not body.get("output")

    def test_no_traceback_or_source_path_reaches_the_caller(self):
        rendered = json.dumps(run(claim(claim_amount="NaN")))
        assert "Traceback" not in rendered
        assert "site-packages" not in rendered
        assert "/src/nodes/" not in rendered

    @staticmethod
    def _leaking_alert_node(monkeypatch, secret):
        """Fault the DATA path: make the alert node compose an assessment that
        carries *secret*. The gate is left exactly as shipped."""
        import src.nodes.alert_if_required_node as alert_module

        original = alert_module.AlertIfRequiredNode.execute

        def leak(self, state):
            result = original(self, state)
            if "result" in result:
                result["result"] = f"{result['result']} contact ops at {secret}"
            return result

        monkeypatch.setattr(alert_module.AlertIfRequiredNode, "execute", leak)

    def test_a_credential_the_platform_detector_carries_is_not_published(self, monkeypatch):
        """A platform-shaped credential never reaches the caller.

        Which LAYER stops it is not asserted, because it is not this template's
        to promise: the platform's own output gate refuses the offending node
        result before the assessment is assembled, so the run ends with nothing
        published at all. Kept as the outer proof; the test below is the one
        that exercises this template's gate.
        """
        secret = "AKIA1234567890ABCDEF"
        self._leaking_alert_node(monkeypatch, secret)
        body = run(HOT_CLAIM)
        assert secret not in json.dumps(body)
        assert body["status"] != "success"
        assert not body.get("output")

    def test_a_credential_only_this_gate_carries_is_contained_by_this_gate(self, monkeypatch):
        """The load-bearing containment case.

        `password=...` is a credential HABIT, not a credential FORMAT, so the
        platform detector matches nothing of that shape and the assessment
        arrives at this template's gate intact. That makes this the only
        containment test whose result depends on what THIS gate does — the
        platform-shaped case above passes even with the clearing removed,
        because the platform had already refused the run.

        Both halves of the assertion matter: the secret is gone, AND the fixed
        notice is what was published in its place. The response builder falls
        back to the raw result whenever the formatted output is falsy, so a
        blank replacement would re-open the channel the clearing exists to
        close, and only the second assertion would notice.
        """
        from src.nodes.security_gate_output_node import _BLOCKED_NOTICE

        secret = "password=hunter2"
        self._leaking_alert_node(monkeypatch, secret)
        body = run(HOT_CLAIM)
        rendered = json.dumps(body)
        assert secret not in rendered
        assert "Risk score" not in rendered
        assert body["status"] != "success"
        # Asserted independently of the constant: an empty body is
        # indistinguishable from a crashed request, and a falsy replacement is
        # what re-opens the `formatted_output or result` fallback.
        assert body.get("output")
        assert body.get("output") == _BLOCKED_NOTICE

    def test_the_out_of_scope_answer_carries_no_assessment(self):
        body = run(claim(claim_type="spacecraft"))
        rendered = json.dumps(body)
        assert "Risk score" not in rendered
        assert "Alert level" not in rendered
