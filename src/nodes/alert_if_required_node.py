"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return AgentStatus enum constants — never plain strings
#  - Never import from mediator/, api/, or other agents
#
# INS-C2-054 — AlertIfRequiredNode
# Final node of the inner domain workflow: raise the investigation alert when
# the tier calls for one, and compose the assessment line the caller reads.
#
# Input state keys:
#   threshold_exceeded, alert_level, evidence_summary, fraud_score, claim_id
#
# Output state keys (partial dict returned):
#   alert_payload: dict | None — alert record (None when no alert is raised)
#   alert_sent:    bool
#   result:        str — the assessment line surfaced to the caller
#   status:        AgentStatus.SUCCESS or AgentStatus.ERROR
#   error_log:     list[str]
#
# `result` is the one string that leaves the agent, so everything in it is
# either a fixed phrase, a number this agent computed, or the claim identifier
# — which the entry gate has already locked to letters, digits and hyphens.
# No claim free text reaches it, and no line break can be introduced into it,
# so a caller cannot manufacture a sentence a reader would attribute to the
# assessment.

import logging
from datetime import datetime, timezone
from typing import Any, ClassVar, Dict, List, Optional

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.services.status import is_error_state

logger = logging.getLogger(__name__)

#: Action text per tier — fixed strings, never assembled from claim data.
_ACTION_REQUIRED: Dict[str, str] = {
    "critical": "Immediate: place the claim on hold and escalate to a senior investigator.",
    "high": "Required: open an investigation within 24 hours.",
    "warning": "Recommended: enhanced review within 72 hours; request additional documentation.",
}


class AlertIfRequiredNode(FunctionNode):
    """Raise the investigation alert and compose the caller-facing assessment."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        error_log: List[str] = list(state.get("error_log") or [])

        if is_error_state(state):
            # No assessment line is composed on a failed run. The output gate
            # relies on there being nothing to release, and a reassuring
            # "processing error" sentence here would be indistinguishable from
            # a completed low-risk assessment.
            return {
                "alert_payload": None,
                "alert_sent": False,
                "status": AgentStatus.ERROR,
                "error_log": error_log,
            }

        if state.get("out_of_scope"):
            return {
                "alert_payload": None,
                "alert_sent": False,
                "result": "This claim type is outside the scope of automated fraud screening.",
                "status": AgentStatus.SUCCESS,
                "error_log": error_log,
            }

        claim_id = state.get("claim_id")
        alert_level = str(state.get("alert_level") or "none")
        fraud_score = state.get("fraud_score")
        if not claim_id or fraud_score is None:
            return {
                "alert_payload": None,
                "alert_sent": False,
                "status": AgentStatus.ERROR,
                "error_log": error_log + ["AlertIfRequiredNode: the assessment is incomplete — no result composed"],
            }

        score = round(float(fraud_score), 1)

        if not bool(state.get("threshold_exceeded", False)):
            logger.info("AlertIfRequiredNode: claim_id=%s no alert raised", claim_id)
            emit_trace_event(
                "alert_decision",
                {"claim_id": claim_id, "alert_sent": False, "alert_level": alert_level},
                state,
            )
            return {
                "alert_payload": None,
                "alert_sent": False,
                "result": (
                    f"Fraud risk assessment complete for claim {claim_id}. "
                    f"Alert level: {alert_level}. Risk score: {score}. No investigation alert required."
                ),
                "status": AgentStatus.SUCCESS,
                "error_log": error_log,
            }

        evidence: Optional[Dict[str, Any]] = state.get("evidence_summary")
        anomaly_count = int(evidence.get("anomaly_count", 0)) if evidence else 0
        recommendation = str(evidence.get("recommendation", "")) if evidence else ""
        action_required = _ACTION_REQUIRED.get(alert_level, "Review the claim for potential fraud.")

        alert_payload: Dict[str, Any] = {
            "claim_id": claim_id,
            "alert_level": alert_level,
            "fraud_score": round(float(fraud_score), 2),
            "anomaly_count": anomaly_count,
            "recommendation": recommendation,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action_required": action_required,
        }

        logger.info("AlertIfRequiredNode: claim_id=%s alert raised at %s", claim_id, alert_level)
        emit_trace_event(
            "alert_decision",
            {
                "claim_id": claim_id,
                "alert_sent": True,
                "alert_level": alert_level,
                "anomaly_count": anomaly_count,
            },
            state,
        )

        return {
            "alert_payload": alert_payload,
            "alert_sent": True,
            "result": (
                f"Investigation alert raised for claim {claim_id}. "
                f"Alert level: {alert_level.upper()}. Risk score: {score}. "
                f"Action required: {action_required}"
            ),
            "status": AgentStatus.SUCCESS,
            "error_log": error_log,
        }
