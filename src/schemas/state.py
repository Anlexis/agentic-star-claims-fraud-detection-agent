"""AgentCore Platform v1.0"""

# State is a flat TypedDict, never a model object: checkpoints are serialised
# with msgpack, and a model instance there corrupts silently rather than
# failing. Extend the framework state with this agent's own fields only; never
# put credentials or secrets in it.
#
# INS-C2-054 — insurance claims fraud screening. The same shape is used by both
# layers of the graph, so a field written by an inner node is readable by the
# outer one after the subgraph result is merged.
#
# What must never enter this state: raw claimant identity. The entry gate drops
# those fields, so `validated_input` holds claim-level facts and reference
# codes only, and everything downstream is built from that.

from typing import Any, Dict, List, Optional

from framework.schemas.agent_state import AgentState


class State(AgentState):
    """Fields this agent adds to the framework state.

    Everything shared — user_input, status, session_id, node_history,
    error_log, the human-review fields — is inherited.
    """

    # ------------------------------------------------------------------
    # Entry gate — ValidateInputNode (pre_process)
    # ------------------------------------------------------------------

    # The validated claim. Only fields the entry gate recognised and bounded:
    # claim_id, claim_type, claim_amount, policy_number, submission_date,
    # incident_date, claimant_id, claim_channel, incident_description,
    # prior_claim_count. Nothing the caller sent that is not in that list
    # survives into it.
    validated_input: Optional[Dict[str, Any]]

    # The claim identifier, locked to letters, digits and hyphens. It is the
    # correlation key across the pipeline and the audit trail, and the only
    # caller-derived value that is rendered back into the assessment text.
    claim_id: Optional[str]

    # True when the claim type has no detection rules. Such a claim is answered
    # with the out-of-scope response and is NOT scored: a fabricated "no
    # indicators found" verdict would be worse than declining to assess.
    out_of_scope: bool

    # ------------------------------------------------------------------
    # Operator configuration
    # ------------------------------------------------------------------

    # The `fraud_patterns` block from config/config.yaml, seeded into every
    # invocation by the graph. Operator setting, never caller input — a
    # detection threshold supplied by the party being screened is an exploit,
    # not a configuration.
    fraud_pattern_overrides: Optional[Dict[str, Any]]

    # ------------------------------------------------------------------
    # Detection pipeline
    # ------------------------------------------------------------------

    # The resolved rule-set: duplicate_detection, inflated_estimate,
    # suspicious_timing and thresholds, each already validated as finite and
    # in range. None on the out-of-scope path.
    fraud_patterns: Optional[Dict[str, Any]]

    # Detected indicators; each is
    # {"type", "severity", "detail", "score_contribution"}. The detail strings
    # come from a closed set — no claim value is interpolated into them.
    anomaly_indicators: Optional[List[Dict[str, Any]]]

    # Aggregate risk score in [0.0, 100.0].
    fraud_score: Optional[float]

    # Human-readable contributing factors, one line per indicator.
    risk_factors: Optional[List[str]]

    # Alert tier: "none" | "warning" | "high" | "critical".
    alert_level: Optional[str]

    # True when the score reached a tier that requires an alert.
    threshold_exceeded: bool

    # The investigator's evidence pack: claim_id, claim_type, alert_level,
    # fraud_score, anomaly_count, indicators, risk_factors, recommendation.
    # Built by naming its fields, never by copying the claim and removing what
    # should not travel.
    evidence_summary: Optional[Dict[str, Any]]

    # The alert record, populated only when an alert is raised. Carries the
    # minimum an investigator needs to open the case — never a copy of the
    # claim.
    alert_payload: Optional[Dict[str, Any]]

    # True when an alert was raised.
    alert_sent: bool

    # ------------------------------------------------------------------
    # Output gate — SecurityGateOutputNode (post_process)
    # ------------------------------------------------------------------

    # The structured response, published only after the output gate has walked
    # every string in it.
    validated_output: Optional[Dict[str, Any]]
