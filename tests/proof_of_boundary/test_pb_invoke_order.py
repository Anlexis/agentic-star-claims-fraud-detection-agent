# PB-6 - Invoke Execution Order Verification
# Verifies BaseNode.__call__() enforces: S-1 trust gate -> S-4 node_start ->
# S-2 _security_gate_input() -> execute() -> S-3 _security_gate_output() ->
# S-4 node_complete, for every concrete node under src/nodes/.
#
# Also verifies the full Graph().invoke() backbone order (graph-level PB-6):
#   InitializeNode -> ValidateInputNode(pre_process) ->
#   FraudDetectionWorkflowNode(main) -> SecurityGateOutputNode(post_process) ->
#   FinalizeNode
#
# Invoke uses InvocationContext(caller_trust_level=VERIFIED_EXTERNAL) so the
# call exercises the REAL external path: the inner domain nodes declare
# ANONYMOUS (admitted by any caller) and the backbone pre_process gate admits
# the VERIFIED_EXTERNAL caller.  See a peer template canonical PB-6 for the pattern.
#
# INS-C2-054 identity (PB-6 graph-level constants):
#   _MAIN_SLOT_NODE -- GraphNode subclass in the outer backbone `main` slot
#   _VALID_PAYLOAD  -- a SUCCESS-yielding fraud claim payload

import importlib
import inspect
import pkgutil
import json

import pytest


# ---------------------------------------------------------------------------
# INS-C2-054 graph-level PB-6 constants
# ---------------------------------------------------------------------------

_MAIN_SLOT_NODE = "FraudDetectionWorkflowNode"  # from src/graph/graph.py

# Clean auto claim: small amount, 50h submission gap, no resubmit channel.
# Expected inner flow: LoadHistoricalPatternsNode parses this from user_input ->
# DetectAnomaliesNode finds 1 low indicator (first-claim) -> fraud_score ~ 3 pts
# -> alert_level="none" -> SecurityGateOutputNode passes -> SUCCESS.
_VALID_PAYLOAD = json.dumps(
    {
        "claim_id": "CLM-2024-001234",
        "claim_type": "auto",
        "claim_amount": 5000.00,
        "policy_number": "POL-12345",
        "submission_date": "2024-01-16T10:30:00",
        "incident_date": "2024-01-14T08:00:00",
        "claimant_id": "CLI-9876",
        "claim_channel": "online",
        "prior_claim_count": 0,
    }
)

# Canonical AgentBaseGraph backbone execution order, by node class name.
# Four entries are framework/scaffold-fixed; only _MAIN_SLOT_NODE is template-specific.
_EXPECTED_BACKBONE_ORDER = [
    "InitializeNode",  # framework default (initialize slot)
    "ValidateInputNode",  # domain pre_process (S-1)
    _MAIN_SLOT_NODE,  # TEMPLATE-SPECIFIC  (main slot GraphNode)
    "SecurityGateOutputNode",  # domain post_process (S-3/S-4)
    "FinalizeNode",  # framework default (finalize slot)
]


# ---------------------------------------------------------------------------
# Autouse fixture -- silence domain emit_trace_event (NOT sys.modules stub)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _silence_domain_audit_emits(monkeypatch):
    """Patch emit_trace_event at each domain node module namespace.

    Domain nodes import emit_trace_event directly from shared.utils.audit_logger.
    Patching at the node-module level silences backend calls while keeping the
    real shared.* package importable.

    NEVER stub shared.* in sys.modules -- the CI wheel ships a real shared package;
    a sys.modules stub registers shared as a non-package and breaks all
    framework imports (from shared.security... raises ModuleNotFoundError).
    """
    _noop = lambda *a, **k: None  # noqa: E731
    node_module_names = [
        "src.nodes.validate_input_node",
        "src.nodes.load_historical_patterns_node",
        "src.nodes.detect_anomalies_node",
        "src.nodes.score_fraud_risk_node",
        "src.nodes.check_threshold_node",
        "src.nodes.generate_evidence_summary_node",
        "src.nodes.alert_if_required_node",
        "src.nodes.security_gate_output_node",
    ]
    for mod_path in node_module_names:
        try:
            mod = importlib.import_module(mod_path)
            if hasattr(mod, "emit_trace_event"):
                monkeypatch.setattr(mod, "emit_trace_event", _noop)
        except ImportError:
            pass  # not yet importable -- skip silently


# ---------------------------------------------------------------------------
# Node-level invoke order (auto-discovery)
# ---------------------------------------------------------------------------


def _discover_node_classes() -> list:
    """Import every module under src/nodes/ and collect concrete BaseNode subclasses."""
    from framework.nodes.base_node import BaseNode

    try:
        pkg = importlib.import_module("src.nodes")
    except ImportError:
        return []

    seen = set()
    discovered = []
    for _, modname, _ in pkgutil.walk_packages(pkg.__path__, prefix="src.nodes."):
        module = importlib.import_module(modname)
        for attr in vars(module).values():
            if (
                isinstance(attr, type)
                and issubclass(attr, BaseNode)
                and attr is not BaseNode
                and attr.__module__ == modname
                and not inspect.isabstract(attr)
                and attr not in seen
            ):
                seen.add(attr)
                discovered.append(attr)
    return discovered


class TestInvokeOrder:
    """PB-6a: __call__ must run S-1 -> node_start -> S-2 -> execute() -> S-3 -> node_complete."""

    def test_call_order_for_every_node(self, monkeypatch):
        node_classes = _discover_node_classes()
        if not node_classes:
            pytest.skip("no concrete BaseNode subclasses found under src/nodes/")

        import framework.nodes.base_node as base_node_module

        failures = []
        for node_cls in node_classes:
            order = []
            monkeypatch.setattr(
                base_node_module,
                "emit_trace_event",
                lambda event_type, _payload, _state, _o=order: _o.append(f"event:{event_type}"),
            )

            for method_name, label in (
                ("_security_gate_input", "security_gate_input"),
                ("execute", "execute"),
                ("_security_gate_output", "security_gate_output"),
            ):
                original = getattr(node_cls, method_name)

                def spy(self, arg, _o=order, _label=label, _orig=original):
                    _o.append(_label)
                    return _orig(self, arg)

                monkeypatch.setattr(node_cls, method_name, spy)

            instance = node_cls()
            state = {
                "caller_trust_level": node_cls.required_trust_level.value,
                "correlation_id": "pb6-invoke-order-test",
            }
            instance(state)

            expected = [
                "event:node_start",
                "security_gate_input",
                "execute",
                "security_gate_output",
                "event:node_complete",
            ]
            if order != expected:
                failures.append(
                    f"{node_cls.__name__}: invoke order violation.\n" f"expected: {expected}\nactual:   {order}"
                )

        assert not failures, "\n\n".join(failures)


# ---------------------------------------------------------------------------
# Graph-level invoke order (PB-6b) — uses _MAIN_SLOT_NODE + _VALID_PAYLOAD
# ---------------------------------------------------------------------------


def _run() -> dict:
    """Run a full end-to-end invocation on the REAL external path and return the output.

    Uses InvocationContext(caller_trust_level=VERIFIED_EXTERNAL) so the call
    exercises the genuine external caller path: the backbone pre_process gate
    (ValidateInputNode, VERIFIED_EXTERNAL) admits it, and the inner domain
    nodes (TrustLevel.ANONYMOUS) are admitted by any caller.  Mirror of
    A peer template canonical _run() pattern.
    """
    from framework.schemas.invocation_context import InvocationContext
    from framework.schemas.trust_level import TrustLevel
    from src.graph.graph import InsuranceClaimsFraudDetectionInvestigatorAlertAgent

    ctx = InvocationContext(caller_trust_level=TrustLevel.VERIFIED_EXTERNAL)
    return InsuranceClaimsFraudDetectionInvestigatorAlertAgent().invoke(_VALID_PAYLOAD, ctx=ctx)


class TestFullGraphInvokeOrder:
    """PB-6b: Graph().invoke() must traverse the backbone in the correct sequence.

    Uses _MAIN_SLOT_NODE (FraudDetectionWorkflowNode) and _VALID_PAYLOAD
    (a clean auto claim that yields SUCCESS through the full pipeline).
    Confirms: InitializeNode -> ValidateInputNode -> FraudDetectionWorkflowNode
              -> SecurityGateOutputNode -> FinalizeNode.

    All invocations use InvocationContext(caller_trust_level=VERIFIED_EXTERNAL)
    so the REAL external path is exercised: inner domain nodes
    (TrustLevel.ANONYMOUS) are admitted by any caller, and the backbone
    pre_process gate admits the VERIFIED_EXTERNAL caller.
    """

    def test_full_invoke_returns_success(self):
        """Full pipeline invoke with a valid claim payload must return SUCCESS."""
        from framework.schemas.agent_status import AgentStatus

        result = _run()
        assert result.get("status") == AgentStatus.SUCCESS.value, (
            f"Expected SUCCESS from valid claim.\n"
            f"status={result.get('status')!r}\n"
            f"error_log={result.get('error_log')!r}"
        )

    def test_output_surfaced_by_gate(self):
        """SecurityGateOutputNode must populate the 'output' framework key.

        FinalizeNode (framework default) reads state.get('output') and includes
        it in the invoke() return dict.  Our SecurityGateOutputNode returns
        'output': result_text in its success path so the gated result is visible
        through the framework's canonical key — matching the peer template pattern
        `assert _run().get("output")`.

        Checking that 'output' is non-empty AND references the claim_id verifies:
          - Inner domain pipeline ran to completion (AlertIfRequiredNode set result)
          - SecurityGateOutputNode S-3 scan passed (output not blocked)
          - FinalizeNode surfaced the gated result via the framework key
        """
        result = _run()
        output_text = str(result.get("output") or "")
        assert output_text, (
            f"'output' key absent/empty in invoke() result — SecurityGateOutputNode "
            f"may not have run or may have blocked the output.\n"
            f"status={result.get('status')!r}\n"
            f"node_history={result.get('node_history')!r}"
        )
        assert "CLM-2024-001234" in output_text, f"claim_id not in invoke() output text: {output_text!r}"

    def test_main_slot_is_correct_type(self):
        """The `main` backbone slot must be an instance of FraudDetectionWorkflowNode."""
        from src.graph.graph import (
            InsuranceClaimsFraudDetectionInvestigatorAlertAgent,
            FraudDetectionWorkflowNode,
        )

        agent = InsuranceClaimsFraudDetectionInvestigatorAlertAgent()
        agent.compile()
        main_node = agent._nodes.get("main")
        assert main_node is not None, "No node registered at `main` slot"
        assert isinstance(
            main_node, FraudDetectionWorkflowNode
        ), f"Expected {_MAIN_SLOT_NODE} at `main` slot, got {type(main_node).__name__}"

    def test_backbone_node_history_order(self):
        """node_history (if populated) must list backbone class names in order.

        Expected order: InitializeNode < ValidateInputNode
                        < FraudDetectionWorkflowNode < SecurityGateOutputNode
                        < FinalizeNode.
        If node_history is not populated by this SDK version, the test is skipped.
        """
        result = _run()
        history = result.get("node_history") or []
        if not history:
            pytest.skip("node_history not populated by this SDK version -- backbone order check skipped")

        # node_history contains class name strings (SDK v1 format).
        def _entry_name(entry) -> str:
            if isinstance(entry, str):
                return entry
            if isinstance(entry, type):
                return entry.__name__
            if isinstance(entry, dict):
                return entry.get("class") or entry.get("node") or ""
            return type(entry).__name__

        names = [_entry_name(e) for e in history]

        # Assert the exact canonical backbone order.
        assert names == _EXPECTED_BACKBONE_ORDER, (
            f"Backbone node_history does not match canonical order.\n"
            f"  expected: {_EXPECTED_BACKBONE_ORDER}\n"
            f"  actual:   {names}"
        )
