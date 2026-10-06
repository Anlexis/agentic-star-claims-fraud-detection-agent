"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return AgentStatus enum constants — never plain strings
#  - Never import from mediator/, api/, or other agents
#
# INS-C2-054 — CheckThresholdNode
# Fourth node of the inner domain workflow: compare the risk score against the
# operator's alert thresholds and set the tier the alert node acts on.
#
#   score >= critical -> "critical", alert required
#   score >= high     -> "high",     alert required
#   score >= warning  -> "warning",  enhanced review
#   otherwise         -> "none",     no alert
#
# Input state keys:
#   fraud_score:    float — from ScoreFraudRiskNode
#   fraud_patterns: dict  — thresholds, already validated as finite and ordered
#
# Output state keys (partial dict returned):
#   alert_level:        str — "none" | "warning" | "high" | "critical"
#   threshold_exceeded: bool
#   status:             AgentStatus.SUCCESS or AgentStatus.ERROR
#   error_log:          list[str]
#
# The thresholds are read from the resolved rule-set only. There is no local
# fallback constant: a missing rule-set is a broken pipeline, and quietly
# substituting a default here would hide it behind a plausible answer.

import logging
import math
from typing import Any, ClassVar, Dict, List, Optional

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.services.status import is_error_state

logger = logging.getLogger(__name__)


class CheckThresholdNode(FunctionNode):
    """Map the risk score onto the operator's alert tiers."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        error_log: List[str] = list(state.get("error_log") or [])

        if is_error_state(state):
            return {"status": AgentStatus.ERROR, "error_log": error_log}

        if state.get("out_of_scope"):
            return {
                "alert_level": "none",
                "threshold_exceeded": False,
                "status": AgentStatus.SUCCESS,
                "error_log": error_log,
            }

        fraud_score: Optional[float] = state.get("fraud_score")
        patterns = state.get("fraud_patterns") or {}
        thresholds = patterns.get("thresholds")
        if fraud_score is None or not isinstance(fraud_score, (int, float)) or not thresholds:
            return {
                "status": AgentStatus.ERROR,
                "error_log": error_log + ["CheckThresholdNode: no score or no thresholds to compare it against"],
            }
        if not math.isfinite(float(fraud_score)):
            return {
                "status": AgentStatus.ERROR,
                "error_log": error_log + ["CheckThresholdNode: the score is not a finite number"],
            }

        score = float(fraud_score)
        if score >= float(thresholds["critical"]):
            alert_level, threshold_exceeded = "critical", True
        elif score >= float(thresholds["high"]):
            alert_level, threshold_exceeded = "high", True
        elif score >= float(thresholds["warning"]):
            alert_level, threshold_exceeded = "warning", True
        else:
            alert_level, threshold_exceeded = "none", False

        logger.info(
            "CheckThresholdNode: claim_id=%s alert_level=%s",
            state.get("claim_id"),
            alert_level,
        )
        emit_trace_event(
            "threshold_evaluated",
            {
                "claim_id": state.get("claim_id"),
                "alert_level": alert_level,
                "threshold_exceeded": threshold_exceeded,
            },
            state,
        )

        return {
            "alert_level": alert_level,
            "threshold_exceeded": threshold_exceeded,
            "status": AgentStatus.SUCCESS,
            "error_log": error_log,
        }
