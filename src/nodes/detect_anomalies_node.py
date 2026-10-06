"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return AgentStatus enum constants — never plain strings
#  - Never import from mediator/, api/, or other agents
#
# INS-C2-054 — DetectAnomaliesNode
# Second node of the inner domain workflow: apply the resolved rule-set to the
# validated claim and produce the anomaly indicators the score is built from.
# Rule-based throughout — no model call and no outbound request.
#
# It reads `validated_input` and nothing else. An earlier revision re-parsed
# the claim out of `user_input` as a fallback, which meant the detectors could
# run against the RAW submission on any path where validation had not written
# `validated_input` — the one payload the entry gate had refused to vouch for.
#
# Input state keys:
#   validated_input: dict — validated claim payload
#   fraud_patterns:  dict — rule-set from LoadHistoricalPatternsNode
#
# Output state keys (partial dict returned):
#   anomaly_indicators: list[dict] — {"type", "severity", "detail",
#                                     "score_contribution"}
#   status:             AgentStatus.SUCCESS or AgentStatus.ERROR
#   error_log:          list[str]
#
# Indicator `detail` strings are drawn from a closed set written here. No claim
# value is interpolated into them: they are carried into the investigator's
# evidence pack, and a detail line assembled from caller text would be caller-
# controlled prose inside a document a reader attributes to the agent.

import logging
from datetime import datetime
from typing import Any, ClassVar, Dict, List, Optional

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.services.status import is_error_state

logger = logging.getLogger(__name__)

#: Claim channels that mark a submission as a repeat of an earlier one.
_RESUBMISSION_CHANNELS = frozenset({"resubmit", "amended", "re-submission", "resubmission"})


def _detect_inflated_estimate(
    claim: Dict[str, Any],
    rules: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Return an indicator when the claimed amount sits above a rule threshold."""
    if not rules.get("enabled", True):
        return None
    amount = claim.get("claim_amount")
    if not isinstance(amount, (int, float)) or isinstance(amount, bool):
        return None

    if amount >= float(rules["very_high_amount_threshold"]):
        return {
            "type": "inflated_estimate",
            "severity": "high",
            "detail": "Claimed amount is above the very-high review threshold",
            "score_contribution": float(rules["high_score_contribution"]),
        }
    if amount >= float(rules["high_amount_threshold"]):
        return {
            "type": "inflated_estimate",
            "severity": "medium",
            "detail": "Claimed amount is above the high review threshold",
            "score_contribution": float(rules["moderate_score_contribution"]),
        }
    return None


def _detect_suspicious_timing(
    claim: Dict[str, Any],
    rules: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Return indicators for submission-timing patterns."""
    if not rules.get("enabled", True):
        return []
    indicators: List[Dict[str, Any]] = []

    submission = claim.get("submission_date", "")
    incident = claim.get("incident_date", "")
    if submission and incident:
        try:
            sub = datetime.fromisoformat(str(submission).replace("Z", "+00:00"))
            inc = datetime.fromisoformat(str(incident).replace("Z", "+00:00"))
            delta_hours = (sub - inc).total_seconds() / 3600
        except (ValueError, TypeError):
            delta_hours = None  # unparseable dates are not evidence either way
        if delta_hours is not None and 0 <= delta_hours <= float(rules["rapid_submission_hours"]):
            indicators.append(
                {
                    "type": "suspicious_timing",
                    "severity": "medium",
                    "detail": "Claim submitted within the rapid-report window after the incident",
                    "score_contribution": float(rules["rapid_submission_score"]),
                }
            )

    if claim.get("prior_claim_count") == 0:
        indicators.append(
            {
                "type": "suspicious_timing",
                "severity": "low",
                "detail": "First claim recorded against this policy",
                "score_contribution": float(rules["first_claim_score"]),
            }
        )

    return indicators


def _detect_duplicate_pattern(
    claim: Dict[str, Any],
    rules: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Return an indicator when the claim looks like a repeat submission."""
    if not rules.get("enabled", True):
        return None

    channel = str(claim.get("claim_channel", "")).lower()
    if channel not in _RESUBMISSION_CHANNELS:
        return None

    prior_count = claim.get("prior_claim_count")
    contribution = float(rules["score_contribution"])
    if isinstance(prior_count, int) and not isinstance(prior_count, bool) and prior_count > 0:
        return {
            "type": "duplicate_detection",
            "severity": "high",
            "detail": "Resubmission on a policy that already carries prior claims",
            "score_contribution": contribution,
        }
    return {
        "type": "duplicate_detection",
        "severity": "medium",
        "detail": "Claim submitted through a resubmission channel",
        "score_contribution": contribution * 0.5,
    }


class DetectAnomaliesNode(FunctionNode):
    """Apply the fraud pattern rules to the validated claim."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        error_log: List[str] = list(state.get("error_log") or [])

        if is_error_state(state):
            return {"status": AgentStatus.ERROR, "error_log": error_log}

        if state.get("out_of_scope"):
            return {
                "anomaly_indicators": [],
                "status": AgentStatus.SUCCESS,
                "error_log": error_log,
            }

        claim = state.get("validated_input")
        patterns = state.get("fraud_patterns")
        if not claim or not patterns:
            return {
                "status": AgentStatus.ERROR,
                "error_log": error_log + ["DetectAnomaliesNode: the validated claim or the rule-set is absent"],
            }

        indicators: List[Dict[str, Any]] = []
        inflated = _detect_inflated_estimate(claim, patterns["inflated_estimate"])
        if inflated is not None:
            indicators.append(inflated)
        indicators.extend(_detect_suspicious_timing(claim, patterns["suspicious_timing"]))
        duplicate = _detect_duplicate_pattern(claim, patterns["duplicate_detection"])
        if duplicate is not None:
            indicators.append(duplicate)

        logger.info(
            "DetectAnomaliesNode: claim_id=%s anomaly_count=%d",
            state.get("claim_id"),
            len(indicators),
        )
        emit_trace_event(
            "anomalies_detected",
            {
                "claim_id": state.get("claim_id"),
                "anomaly_count": len(indicators),
                "anomaly_types": sorted({i["type"] for i in indicators}),
                "severities": sorted({i["severity"] for i in indicators}),
            },
            state,
        )

        return {
            "anomaly_indicators": indicators,
            "status": AgentStatus.SUCCESS,
            "error_log": error_log,
        }
