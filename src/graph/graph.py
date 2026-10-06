"""AgentCore Platform v1.0"""

# INS-C2-054 — outer graph (two-layer nested Cat 2 architecture).
#
# Backbone (fixed — never override add_edges()):
#
#   START -> initialize -> pre_process -> main -> {route} -> post_process
#            -> finalize -> END
#                     |
#                     +-- RETRY re-enters pre_process (bounded by max_retry)
#
#   pre_process   ValidateInputNode         owns the caller-data contract
#   main          FraudDetectionWorkflowNode delegates to the inner graph
#   post_process  SecurityGateOutputNode     decides what is published
#
# Domain complexity lives entirely inside the inner graph; the backbone above
# is the framework's and is not modified.
#
# Directory layout:
#   src/graph/graph.py                 <- outer graph (this file)
#   src/graph/domain_workflow_graph.py <- inner graph (the detection pipeline)
#   src/graph/context_bridge.py        <- outer-to-inner hand-off
#
# HOW OPERATOR SETTINGS REACH THE DETECTORS
# -----------------------------------------
# `config/config.yaml` -> `Graph(config=...)` -> `_extra_initial_state()` puts
# the operator's `fraud_patterns` block into the outer state -> the subgraph
# node stashes it on the bridge -> the inner graph seeds it -> the pattern
# loader resolves the rule-set from it. Every link in that chain is covered by
# an end-to-end test that changes a declared threshold and asserts the alert
# tier moves; without one, a declared value that never reaches the detector
# looks exactly like a working configuration.

import logging
from typing import Any, ClassVar, Dict, Optional

from framework.errors import ConfigError
from framework.graph.agent_base_graph import AgentBaseGraph
from framework.nodes.graph_node import GraphNode
from framework.schemas.agent_state import AgentState

from src.graph import context_bridge
from src.nodes.security_gate_output_node import SecurityGateOutputNode
from src.nodes.validate_input_node import ValidateInputNode
from src.schemas.state import State
from src.services.patterns import PatternConfigError, resolve_patterns

logger = logging.getLogger(__name__)


class FraudDetectionWorkflowNode(GraphNode):
    """The `main` backbone slot: runs the detection pipeline as a subgraph.

    The subgraph contract passes one string to the inner graph and nothing
    else — the inner graph then builds a fresh initial state. Everything the
    detectors need beyond that string (the validated claim, the scope decision,
    the operator's rule-set) travels on the bridge in
    :mod:`src.graph.context_bridge`.
    """

    #: Re-raise an inner failure rather than degrading. A fraud screening that
    #: half-ran must not be reported as one that found nothing.
    error_strategy: ClassVar[str] = "propagate"

    #: Human review, where used, is handled inside the inner graph.
    propagate_hitl: ClassVar[bool] = False

    def get_subgraph(self) -> Any:
        """Return the inner detection pipeline.

        Imported inside the method to keep module import order free of a cycle.
        """
        from src.graph.domain_workflow_graph import FraudDetectionDomainWorkflowGraph

        return FraudDetectionDomainWorkflowGraph()

    def extract_input(self, state: AgentState) -> str:
        """Publish the hand-off and return the inner graph's user_input.

        This runs on the caller's own thread immediately before
        ``subgraph.invoke()``, so the context variable it sets is the one the
        inner graph reads a moment later.
        """
        claim_id = state.get("claim_id") or ""
        context_bridge.set_handoff(
            {
                "validated_input": state.get("validated_input"),
                "claim_id": claim_id,
                "out_of_scope": bool(state.get("out_of_scope", False)),
                "fraud_pattern_overrides": state.get("fraud_pattern_overrides"),
            }
        )
        # The inner graph does not parse this; the claim travels on the bridge.
        # It is the correlation handle that appears in the inner audit trail.
        return str(claim_id)

    def merge_output(self, state: AgentState, sub_result: Dict[str, Any]) -> Dict[str, Any]:
        """Fold the inner result back into the outer state, changed keys only.

        `out_of_scope` and `claim_id` are floored at the outer values. The
        entry gate decided both, and an inner default of `False`/`None` must
        not be able to overwrite a decision that was already made — an earlier
        revision lost the scope decision exactly that way, and the out-of-scope
        response became unreachable.
        """
        return {
            "result": sub_result.get("result"),
            "evidence_summary": sub_result.get("evidence_summary"),
            "alert_payload": sub_result.get("alert_payload"),
            "alert_sent": sub_result.get("alert_sent", False),
            "alert_level": sub_result.get("alert_level"),
            "fraud_score": sub_result.get("fraud_score"),
            "risk_factors": sub_result.get("risk_factors"),
            "claim_id": sub_result.get("claim_id") or state.get("claim_id"),
            "out_of_scope": bool(sub_result.get("out_of_scope") or state.get("out_of_scope", False)),
            "status": sub_result.get("status"),
        }


class InsuranceClaimsFraudDetectionInvestigatorAlertAgent(AgentBaseGraph):
    """Insurance claims fraud screening agent (outer graph).

    Inherits the framework base graph directly. `register_nodes()` is the only
    override; the backbone wiring belongs to the framework.
    """

    @property
    def name(self) -> str:
        """Identifier this agent registers under."""
        return "ins_c2_054"

    @property
    def state_schema(self) -> type:
        return State

    def _validate_config(self) -> None:
        """Validate the runtime configuration before the graph is built.

        The base checks cover `max_retry`, `memory_enabled` and the human-review
        block. The `fraud_patterns` block is resolved here as well, so a
        deployment whose thresholds are malformed, non-finite or out of order
        fails at startup — rather than at the moment a real claim needed
        escalating.
        """
        super()._validate_config()
        try:
            resolve_patterns(self.config.get("fraud_patterns"))
        except PatternConfigError as exc:
            raise ConfigError(f"[{self.__class__.__name__}] {exc}") from None

    def _extra_initial_state(self) -> Dict[str, Any]:
        """Seed the operator's rule-set overrides into every invocation."""
        overrides: Optional[Dict[str, Any]] = self.config.get("fraud_patterns")
        return {"fraud_pattern_overrides": overrides}

    def register_nodes(self) -> None:
        """Fill the five backbone slots.

        `super().register_nodes()` must run first: it installs the framework's
        own initialize and finalize nodes.
        """
        super().register_nodes()
        self._nodes["pre_process"] = ValidateInputNode()
        self._nodes["main"] = FraudDetectionWorkflowNode()
        self._nodes["post_process"] = SecurityGateOutputNode()

    # add_edges() is NOT overridden — backbone wiring belongs to the framework.


#: Alias used by the standalone entry point.
Graph = InsuranceClaimsFraudDetectionInvestigatorAlertAgent
