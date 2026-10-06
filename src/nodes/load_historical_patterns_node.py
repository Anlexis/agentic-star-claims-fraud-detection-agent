"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return AgentStatus enum constants -- never plain strings
#  - Never import from mediator/, api/, or other agents
#
# INS-C2-054 -- LoadHistoricalPatternsNode
# First node of the inner domain workflow: resolve the fraud pattern rule-set
# for this invocation and hand it to the detectors.
#
# WHERE THE RULE-SET COMES FROM, AND WHERE IT DOES NOT
# ---------------------------------------------------
# The rule-set is the OPERATOR's setting. It arrives from config/config.yaml
# under `fraud_patterns:`, is validated when the graph is constructed, and is
# seeded into the inner state by the graph itself.
#
# It is deliberately NOT read from:
#
#   * the claim payload. An earlier revision merged an `operator_config` block
#     found in the submitted claim, which let the submitting party raise its own
#     alert thresholds out of reach: a claim scoring 65 with a suppressed
#     threshold reported "no alert required". Detection settings supplied by the
#     party being screened are not settings, they are an exploit.
#   * a per-call `config` argument. The node entry point calls `execute(state)`
#     with one argument, so a `config=None` parameter is always None and any
#     override keyed on it is dead code that reads as a working feature.
#
# Input state keys:
#   validated_input:       dict -- validated claim (seeded by the graph)
#   fraud_pattern_overrides: dict | None -- operator settings (seeded by the graph)
#
# Output state keys (partial dict returned):
#   fraud_patterns: dict -- the resolved rule-set
#   status:         AgentStatus.SUCCESS or AgentStatus.ERROR
#   error_log:      list[str]
#
# The audit event records the rule-set's shape, never its contents: the
# thresholds are what a fraudulent claimant would most like to learn.

import logging
from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.services.patterns import DEFAULT_FRAUD_PATTERNS, PatternConfigError, resolve_patterns
from src.services.status import is_error_state

logger = logging.getLogger(__name__)


class LoadHistoricalPatternsNode(FunctionNode):
    """Resolve the fraud pattern rule-set for the current invocation."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        error_log: List[str] = list(state.get("error_log") or [])

        if is_error_state(state):
            return {"status": AgentStatus.ERROR, "error_log": error_log}

        # Out-of-scope claims are answered without scoring, so there is no
        # rule-set to resolve.
        if state.get("out_of_scope"):
            return {
                "fraud_patterns": None,
                "status": AgentStatus.SUCCESS,
                "error_log": error_log,
            }

        if not state.get("validated_input"):
            return {
                "status": AgentStatus.ERROR,
                "error_log": error_log
                + ["LoadHistoricalPatternsNode: no validated claim reached the detection pipeline"],
            }

        overrides = state.get("fraud_pattern_overrides")
        try:
            patterns: Dict[str, Any] = resolve_patterns(overrides)
        except PatternConfigError as exc:
            return {
                "status": AgentStatus.ERROR,
                "error_log": error_log + [f"LoadHistoricalPatternsNode: {exc}"],
            }

        logger.info(
            "LoadHistoricalPatternsNode: rule-set resolved (operator overrides applied: %s)",
            bool(overrides),
        )
        emit_trace_event(
            "patterns_loaded",
            {
                "claim_id": state.get("claim_id"),
                "sections": sorted(patterns.keys()),
                "operator_override": bool(overrides),
                "default_section_count": len(DEFAULT_FRAUD_PATTERNS),
            },
            state,
        )

        return {
            "fraud_patterns": patterns,
            "status": AgentStatus.SUCCESS,
            "error_log": error_log,
        }
