"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return AgentStatus enum constants — never plain strings
#  - Never import from mediator/, api/, or other agents
#
# INS-C2-054 — SecurityGateOutputNode
# Outer backbone post_process slot: the last node before the response is
# assembled, and the only place that decides what leaves the agent.
#
# TWO THINGS THIS GATE HAS TO GET RIGHT
# -------------------------------------
# 1. WHAT IT SCANS. The response the caller receives is
#    `formatted_output or result`, but the assessment also travels through
#    `validated_output`, which nests the evidence pack and the alert record.
#    A gate that scanned only the top-level assessment line would report zero
#    findings on a value one level down. It therefore walks every string in
#    every representation it is about to publish, nested structures included.
#
# 2. WHAT IT DOES ON A VIOLATION. Raising is not containment: the response
#    builder falls back to `result` even on an error status, so a gate that
#    merely raised — or returned an error without clearing — would still ship
#    the ungated text inside the error envelope. On a violation this node
#    replaces every output-bearing field with a fixed refusal notice. The
#    replacement is deliberately non-empty: a falsy value re-opens the same
#    fallback the clearing exists to close.
#
# The credential check is the UNION of the platform detector and this
# template's own patterns. Neither half is redundant: the platform patterns
# describe credential FORMATS (`sk-...`, `AKIA...`, `eyJ...`, bearer tokens,
# database URIs) and match nothing of the shape `password=...`, while a purely
# local set would miss every format above — and a value the platform catches
# and this gate missed makes the platform raise inside post-process, at which
# point the wrapper discards this node's clearing entirely. Narrowing either
# half is a bypass; the union is the floor.
#
# Input state keys:
#   result, evidence_summary, alert_payload, alert_sent, claim_id,
#   alert_level, fraud_score, out_of_scope
#
# Output state keys (partial dict returned):
#   validated_output, formatted_output, output, status, error_log

import logging
from typing import Any, ClassVar, Dict, List, Optional

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.services.security import detect_secrets_in_value
from src.services.status import is_error_state

logger = logging.getLogger(__name__)

#: The fixed text published in place of a response that failed the gate.
_BLOCKED_NOTICE = "The assessment could not be released because it failed the output safety check."

#: The response when the pipeline did not complete. It carries no detail: the
#: reason lives in the audit trail, where the reader is the operator rather
#: than whoever sent the request.
_UNAVAILABLE_NOTICE = "No fraud risk assessment could be produced for this request."


def _security_gate_output(content: object) -> Optional[str]:
    """Return the name of the first credential pattern in *content*, or None.

    A module-level function rather than a node method: the two hook names the
    platform reserves on a node are enforced as non-overridable, and a
    similarly named method is the shape that gets mistaken for one.
    """
    return detect_secrets_in_value(content)


class SecurityGateOutputNode(FunctionNode):
    """Decide what the agent publishes, and refuse to publish anything else.

    Declared ANONYMOUS on purpose. Trust ordering is
    ANONYMOUS < VERIFIED_EXTERNAL < INTERNAL, and a node's requirement is a
    FLOOR the caller must clear — so declaring INTERNAL here would deny a
    genuine external caller and skip the output gate on exactly the requests it
    exists to check. ANONYMOUS admits every caller, so the gate always runs.
    The agent's own entry requirement stays where it belongs, on the node that
    reads the caller's data.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def _blocked(self, state: Dict[str, Any], error_log: List[str], violation: str, claim_id: str) -> Dict[str, Any]:
        """Return the contained response for a run that must not be published."""
        emit_trace_event(
            "s3_gate_violation",
            {"claim_id": claim_id, "violation_type": violation, "action": "output_blocked"},
            state,
        )
        return {
            # Every output-bearing field is replaced, not emptied: the response
            # builder falls back to `result` whenever `formatted_output` is
            # falsy, so a blank here would republish what was just refused.
            "validated_output": {"claim_id": claim_id, "status": "blocked", "message": _BLOCKED_NOTICE},
            "formatted_output": _BLOCKED_NOTICE,
            "output": _BLOCKED_NOTICE,
            "result": _BLOCKED_NOTICE,
            "evidence_summary": None,
            "alert_payload": None,
            "status": AgentStatus.ERROR,
            "error_log": error_log + [f"SecurityGateOutputNode: output blocked ({violation})"],
        }

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        error_log: List[str] = list(state.get("error_log") or [])
        raw_claim_id = state.get("claim_id")
        claim_id = raw_claim_id if isinstance(raw_claim_id, str) and raw_claim_id else "unknown"

        # 1. A failed run publishes a fixed notice and nothing else. The
        #    upstream partial results are cleared here rather than trusted to
        #    be absent — this is the last node that can do it.
        if is_error_state(state):
            emit_trace_event(
                "output_withheld",
                {"claim_id": claim_id, "reason": "pipeline_incomplete"},
                state,
            )
            return {
                "validated_output": {"claim_id": claim_id, "status": "unavailable", "message": _UNAVAILABLE_NOTICE},
                "formatted_output": _UNAVAILABLE_NOTICE,
                "output": _UNAVAILABLE_NOTICE,
                "result": _UNAVAILABLE_NOTICE,
                "evidence_summary": None,
                "alert_payload": None,
                "status": AgentStatus.ERROR,
                "error_log": error_log,
            }

        # 2. Assemble the response.
        if state.get("out_of_scope"):
            message = (
                "The submitted claim type is outside the scope of automated fraud screening. "
                "Process it through the standard workflow."
            )
            validated_output: Dict[str, Any] = {
                "claim_id": claim_id,
                "status": "out_of_scope",
                "alert_sent": False,
                "message": message,
            }
            summary_text = message
        else:
            fraud_score = state.get("fraud_score")
            summary_text = str(state.get("result") or "")
            validated_output = {
                "claim_id": claim_id,
                "status": "processed",
                "alert_sent": bool(state.get("alert_sent", False)),
                "alert_level": state.get("alert_level") or "none",
                "fraud_score": round(float(fraud_score), 2) if fraud_score is not None else 0.0,
                "evidence_summary": state.get("evidence_summary"),
                "alert_payload": state.get("alert_payload"),
                "summary": summary_text,
            }

        # 3. Scan every representation that is about to be published, walking
        #    nested structures — not just the top-level assessment line.
        for candidate in (summary_text, validated_output):
            violation = _security_gate_output(candidate)
            if violation is not None:
                logger.warning("SecurityGateOutputNode: output blocked for claim_id=%s", claim_id)
                return self._blocked(state, error_log, violation, claim_id)

        if not summary_text:
            return self._blocked(state, error_log, "empty_assessment", claim_id)

        logger.info("SecurityGateOutputNode: claim_id=%s gate=PASS", claim_id)
        emit_trace_event(
            "output_gate_pass",
            {
                "claim_id": claim_id,
                "alert_sent": bool(state.get("alert_sent", False)),
                "alert_level": state.get("alert_level") or "none",
                "out_of_scope": bool(state.get("out_of_scope", False)),
            },
            state,
        )

        return {
            "validated_output": validated_output,
            "formatted_output": summary_text,
            # The response builder reads `formatted_output` first and falls back
            # to `result`; `output` is set for callers that read the state.
            "output": summary_text,
            "status": AgentStatus.SUCCESS,
            "error_log": error_log,
        }
