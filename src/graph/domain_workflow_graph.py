"""AgentCore Platform v1.0"""

# INS-C2-054 — the detection pipeline (inner graph).
#
#   START
#     -> load_historical_patterns   resolve the operator's rule-set
#     -> detect_anomalies           apply the rules to the validated claim
#     -> score_fraud_risk           aggregate the indicators into a score
#     -> check_threshold            map the score onto an alert tier
#     -> generate_evidence_summary  assemble the investigator's evidence pack
#     -> alert_if_required          raise the alert and compose the assessment
#     -> END
#
# The topology is linear on purpose: every step runs on every in-scope claim so
# the audit trail is the same shape for a claim that scored zero and one that
# was escalated. Steps that have nothing to do short-circuit inside their own
# node rather than being routed around, which keeps the trail complete.
#
# The graph is entered from `FraudDetectionWorkflowNode.get_subgraph()`; its
# `get_output()` and that node's `merge_output()` are one contract and are
# written together.

from typing import Any, Dict

from langgraph.graph import END, START

from framework.graph.base_graph import BaseGraph
from framework.schemas.agent_state import AgentState

from src.graph import context_bridge
from src.nodes.alert_if_required_node import AlertIfRequiredNode
from src.nodes.check_threshold_node import CheckThresholdNode
from src.nodes.detect_anomalies_node import DetectAnomaliesNode
from src.nodes.generate_evidence_summary_node import GenerateEvidenceSummaryNode
from src.nodes.load_historical_patterns_node import LoadHistoricalPatternsNode
from src.nodes.score_fraud_risk_node import ScoreFraudRiskNode
from src.schemas.state import State


class FraudDetectionDomainWorkflowGraph(BaseGraph):
    """The fraud detection pipeline, run as a subgraph of the outer backbone."""

    # ── Identity ──────────────────────────────────────────────────────────────

    @property
    def name(self) -> str:
        """Identifier for this pipeline."""
        return "ins_c2_054_fraud_detection_domain_workflow"

    @property
    def state_schema(self) -> type:
        """The state shape shared with the outer graph."""
        return State

    # ── Config validation ─────────────────────────────────────────────────────

    def _validate_config(self) -> None:
        """No configuration of its own.

        The rule-set is validated once, when the outer graph is constructed,
        and arrives here already resolved. Re-deriving it from a second source
        would be a second place for the two to disagree.
        """

    # ── Initial state ─────────────────────────────────────────────────────────

    def _extra_initial_state(self) -> Dict[str, Any]:
        """Seed the outer hand-off into this graph's initial state.

        The subgraph contract carries one string across the boundary, so
        everything else — the validated claim, the scope decision, the
        operator's rule-set — arrives on the bridge that the subgraph node
        published a moment earlier on this same thread.
        """
        handoff = context_bridge.take_handoff()
        return {
            "validated_input": handoff.get("validated_input"),
            "claim_id": handoff.get("claim_id"),
            "out_of_scope": bool(handoff.get("out_of_scope", False)),
            "fraud_pattern_overrides": handoff.get("fraud_pattern_overrides"),
            "threshold_exceeded": False,
            "alert_sent": False,
        }

    # ── Node registration ─────────────────────────────────────────────────────

    def register_nodes(self) -> None:
        """Register the six pipeline steps.

        No `super()` call — the base declares this abstract. `initialize` and
        `finalize` are outer-backbone concerns and are not registered here.
        Nodes take no constructor arguments; per-invocation data reaches them
        through state.
        """
        self._nodes["load_historical_patterns"] = LoadHistoricalPatternsNode()
        self._nodes["detect_anomalies"] = DetectAnomaliesNode()
        self._nodes["score_fraud_risk"] = ScoreFraudRiskNode()
        self._nodes["check_threshold"] = CheckThresholdNode()
        self._nodes["generate_evidence_summary"] = GenerateEvidenceSummaryNode()
        self._nodes["alert_if_required"] = AlertIfRequiredNode()

    # ── Edge wiring ───────────────────────────────────────────────────────────

    def add_edges(self) -> None:
        """Wire the linear pipeline."""
        self._sg.add_edge(START, "load_historical_patterns")
        self._sg.add_edge("load_historical_patterns", "detect_anomalies")
        self._sg.add_edge("detect_anomalies", "score_fraud_risk")
        self._sg.add_edge("score_fraud_risk", "check_threshold")
        self._sg.add_edge("check_threshold", "generate_evidence_summary")
        self._sg.add_edge("generate_evidence_summary", "alert_if_required")
        self._sg.add_edge("alert_if_required", END)

    # ── Routing ───────────────────────────────────────────────────────────────

    def route(self, state: AgentState) -> str:
        """Required by the base contract; unused by this linear topology.

        No conditional edge references it, so it is never called at runtime.
        It returns END rather than a node name so that a future edge wired to
        it cannot re-enter the pipeline by accident.
        """
        return END

    # ── Output shape ──────────────────────────────────────────────────────────

    def get_output(self, state: AgentState) -> Dict[str, Any]:
        """Shape the result the subgraph node folds back into the outer state.

        Written together with `FraudDetectionWorkflowNode.merge_output()`; the
        key names on both sides are one contract.
        """
        return {
            "result": state.get("result"),
            "evidence_summary": state.get("evidence_summary"),
            "alert_payload": state.get("alert_payload"),
            "alert_sent": state.get("alert_sent", False),
            "alert_level": state.get("alert_level"),
            "fraud_score": state.get("fraud_score"),
            "risk_factors": state.get("risk_factors"),
            "claim_id": state.get("claim_id"),
            "out_of_scope": state.get("out_of_scope", False),
            "status": state.get("status"),
            "trace_id": state.get("trace_id"),
            "correlation_id": state.get("correlation_id"),
            "node_history": state.get("node_history", []),
            "error_log": state.get("error_log", []),
        }

    # ── Lifecycle helpers ─────────────────────────────────────────────────────

    def get_state_class(self) -> type:
        """Return the state shape shared with the outer graph."""
        return State
