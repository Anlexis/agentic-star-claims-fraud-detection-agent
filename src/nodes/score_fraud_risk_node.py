"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return AgentStatus enum constants — never plain strings
#  - Never import from mediator/, api/, or other agents
#
# INS-C2-054 — ScoreFraudRiskNode
# Third node of the inner domain workflow: aggregate the anomaly indicators
# into a 0–100 risk score and the human-readable factor list that goes into the
# investigator's evidence pack.
#
# Scoring:
#   score = min(sum(contribution x severity weight), 100.0)
#   high x 1.00, medium x 0.85, low x 0.60
#
# Input state keys:
#   anomaly_indicators: list[dict] — from DetectAnomaliesNode
#
# Output state keys (partial dict returned):
#   fraud_score:  float in [0.0, 100.0]
#   risk_factors: list[str]
#   status:       AgentStatus.SUCCESS or AgentStatus.ERROR
#   error_log:    list[str]
#
# An upstream failure is propagated, never absorbed. Returning SUCCESS with a
# zero score after the detector failed is how a broken pipeline reports "no
# fraud indicators detected" — the single most expensive wrong answer this
# agent can give.

import logging
from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.services.status import is_error_state

logger = logging.getLogger(__name__)

#: Severity weight applied to each indicator's own contribution.
_SEVERITY_WEIGHTS: Dict[str, float] = {"high": 1.00, "medium": 0.85, "low": 0.60}


def _score_bucket(score: float) -> str:
    if score >= 80.0:
        return "critical"
    if score >= 60.0:
        return "high"
    if score >= 30.0:
        return "medium"
    return "low"


class ScoreFraudRiskNode(FunctionNode):
    """Aggregate the anomaly indicators into a fraud risk score."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        error_log: List[str] = list(state.get("error_log") or [])

        if is_error_state(state):
            return {"status": AgentStatus.ERROR, "error_log": error_log}

        if state.get("out_of_scope"):
            return {
                "fraud_score": 0.0,
                "risk_factors": [],
                "status": AgentStatus.SUCCESS,
                "error_log": error_log,
            }

        indicators: List[Dict[str, Any]] = list(state.get("anomaly_indicators") or [])

        total_score = 0.0
        risk_factors: List[str] = []
        for indicator in indicators:
            severity = str(indicator.get("severity", "medium")).lower()
            weight = _SEVERITY_WEIGHTS.get(severity, _SEVERITY_WEIGHTS["medium"])
            weighted = float(indicator.get("score_contribution", 0.0)) * weight
            total_score += weighted
            risk_factors.append(
                f"{indicator.get('type', 'unknown')} ({severity}): "
                f"{indicator.get('detail', '')} [+{weighted:.1f} pts]"
            )

        fraud_score = min(total_score, 100.0)
        if not risk_factors:
            risk_factors = ["No anomaly indicators detected"]

        logger.info(
            "ScoreFraudRiskNode: claim_id=%s bucket=%s",
            state.get("claim_id"),
            _score_bucket(fraud_score),
        )
        emit_trace_event(
            "fraud_score_computed",
            {
                "claim_id": state.get("claim_id"),
                "score_bucket": _score_bucket(fraud_score),
                "factor_count": len(indicators),
                "anomaly_types": sorted({str(i.get("type", "unknown")) for i in indicators}),
            },
            state,
        )

        return {
            "fraud_score": fraud_score,
            "risk_factors": risk_factors,
            "status": AgentStatus.SUCCESS,
            "error_log": error_log,
        }
