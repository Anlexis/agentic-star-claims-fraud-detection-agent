"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return AgentStatus enum constants — never plain strings
#  - Never import from mediator/, api/, or other agents
#
# INS-C2-054 — GenerateEvidenceSummaryNode
# Fifth node of the inner domain workflow: assemble the structured evidence
# pack an investigator reads.
#
# The pack is built by NAMING the fields it contains, never by copying the
# claim and removing what should not travel. Enumerating what goes in is the
# only construction whose failure mode is a missing field rather than a leaked
# one — a denylist grows a hole every time the claim schema does.
#
# Concretely, the pack carries: the claim identifier, the claim type, the tier,
# the score, the indicator list (type / severity / closed-set detail) and the
# recommendation. It does not carry the claimant reference, the policy number,
# the amount, the incident description, or any field this agent did not itself
# compute.
#
# Input state keys:
#   validated_input, anomaly_indicators, fraud_score, risk_factors, alert_level
#
# Output state keys (partial dict returned):
#   evidence_summary: dict
#   status:           AgentStatus.SUCCESS or AgentStatus.ERROR
#   error_log:        list[str]

import logging
from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.services.status import is_error_state

logger = logging.getLogger(__name__)

#: Recommendation text per tier. Fixed strings — nothing here is assembled from
#: claim data.
_RECOMMENDATIONS: Dict[str, str] = {
    "critical": (
        "Immediate special-investigation escalation required. Place the claim on hold pending "
        "investigation, assign a senior investigator, and review all associated policies."
    ),
    "high": (
        "Special investigation required. Obtain additional documentation and cross-reference "
        "against historical fraud patterns."
    ),
    "warning": (
        "Flag for enhanced review. Request supporting documentation from the claimant and "
        "monitor for additional anomalies."
    ),
    "none": ("No significant fraud indicators detected. Process the claim through the standard workflow."),
}

#: Fields the pack is allowed to copy from the claim, and nothing else.
_CLAIM_FIELDS_CARRIED = ("claim_type",)


class GenerateEvidenceSummaryNode(FunctionNode):
    """Assemble the investigator-facing evidence pack."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        error_log: List[str] = list(state.get("error_log") or [])

        if is_error_state(state):
            return {"status": AgentStatus.ERROR, "error_log": error_log}

        if state.get("out_of_scope"):
            return {
                "evidence_summary": None,
                "status": AgentStatus.SUCCESS,
                "error_log": error_log,
            }

        claim: Dict[str, Any] = state.get("validated_input") or {}
        indicators: List[Dict[str, Any]] = list(state.get("anomaly_indicators") or [])
        alert_level = str(state.get("alert_level") or "none")
        claim_id = state.get("claim_id")
        if not claim_id or state.get("fraud_score") is None:
            return {
                "status": AgentStatus.ERROR,
                "error_log": error_log
                + ["GenerateEvidenceSummaryNode: the assessment is incomplete — no pack produced"],
            }

        summarised_indicators = [
            {
                "type": str(indicator.get("type", "unknown")),
                "severity": str(indicator.get("severity", "medium")),
                "detail": str(indicator.get("detail", "")),
            }
            for indicator in indicators
        ]

        evidence_summary: Dict[str, Any] = {
            "claim_id": claim_id,
            "alert_level": alert_level,
            "fraud_score": round(float(state["fraud_score"]), 2),
            "anomaly_count": len(indicators),
            "indicators": summarised_indicators,
            "risk_factors": list(state.get("risk_factors") or []),
            "recommendation": _RECOMMENDATIONS.get(alert_level, _RECOMMENDATIONS["none"]),
        }
        for field in _CLAIM_FIELDS_CARRIED:
            evidence_summary[field] = claim.get(field, "unknown")

        logger.info(
            "GenerateEvidenceSummaryNode: claim_id=%s alert_level=%s anomaly_count=%d",
            claim_id,
            alert_level,
            len(indicators),
        )
        emit_trace_event(
            "evidence_summary_generated",
            {
                "claim_id": claim_id,
                "alert_level": alert_level,
                "anomaly_count": len(indicators),
                "indicator_types": sorted({i["type"] for i in summarised_indicators}),
            },
            state,
        )

        return {
            "evidence_summary": evidence_summary,
            "status": AgentStatus.SUCCESS,
            "error_log": error_log,
        }
