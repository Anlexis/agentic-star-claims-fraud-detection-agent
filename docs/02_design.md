# INS-C2-054 — Insurance Claims Fraud Detection & Investigator Alert Agent — design

## Template Metadata

| Field | Value |
|---|---|
| Template ID | INS-C2-054 |
| Category | Cat 2 |
| Industry | INS (Insurance) |
| L1 Base (framework base class) | AgentBaseGraph — direct framework inheritance |
| Pattern | Rule-based anomaly detection with an alert decision |
| Generation mode | deterministic (no model call anywhere in the pipeline) |
| Entry trust level | VERIFIED_EXTERNAL |

---

## What the agent does

A claims system submits one claim record. The agent applies a configured set of
fraud-pattern rules to it, aggregates the matches into a 0–100 risk score, maps
the score onto an alert tier, and — when the tier calls for it — produces an
alert record and an evidence pack an investigator can act on.

Everything is rule-based and deterministic. There is no model call, no
retrieval, and no outbound request: the same claim scores the same way every
time, which is what makes the result defensible in a claims dispute.

---

## Architecture

```
Outer backbone (AgentBaseGraph — fixed; add_edges() is not overridden):
  START -> initialize -> pre_process -> main -> {route} -> post_process
           -> finalize -> END
                    |
                    +-- RETRY re-enters pre_process (bounded by max_retry)

  pre_process  : ValidateInputNode          owns the caller-data contract
  main         : FraudDetectionWorkflowNode runs the pipeline as a subgraph
  post_process : SecurityGateOutputNode     decides what is published

Detection pipeline (FraudDetectionDomainWorkflowGraph — BaseGraph):
  START
    -> load_historical_patterns   resolve the operator's rule-set
    -> detect_anomalies           apply the rules to the validated claim
    -> score_fraud_risk           aggregate the indicators into a score
    -> check_threshold            map the score onto an alert tier
    -> generate_evidence_summary  assemble the investigator's evidence pack
    -> alert_if_required          raise the alert, compose the assessment
    -> END
```

The pipeline is linear on purpose: every step runs on every in-scope claim, so
the audit trail has the same shape for a claim that scored zero and one that
was escalated. Steps with nothing to do short-circuit inside their own node
rather than being routed around.

### File layout

```
src/api/server.py                          standalone HTTP entry point
src/graph/graph.py                         outer graph + the subgraph node
src/graph/domain_workflow_graph.py         the detection pipeline
src/graph/context_bridge.py                outer-to-inner hand-off
src/nodes/validate_input_node.py           caller-data contract (pre_process)
src/nodes/load_historical_patterns_node.py pipeline step 1
src/nodes/detect_anomalies_node.py         pipeline step 2
src/nodes/score_fraud_risk_node.py         pipeline step 3
src/nodes/check_threshold_node.py          pipeline step 4
src/nodes/generate_evidence_summary_node.py pipeline step 5
src/nodes/alert_if_required_node.py        pipeline step 6
src/nodes/security_gate_output_node.py     output gate (post_process)
src/schemas/state.py                       flat TypedDict shared by both layers
src/services/security.py                   input-safety helpers
src/services/patterns.py                   the rule-set and its validation
src/services/status.py                     status comparison helper
config/agent.yaml                          discovery manifest (flat, root-level keys)
config/config.yaml                         runtime parameters and the rule-set
```

---

## Node configuration

| Layer | Slot | Node | Required trust level |
|---|---|---|---|
| Outer | `pre_process` | `ValidateInputNode` | `VERIFIED_EXTERNAL` |
| Outer | `main` | `FraudDetectionWorkflowNode` | `ANONYMOUS` (framework default for a subgraph node) |
| Pipeline | `load_historical_patterns` | `LoadHistoricalPatternsNode` | `ANONYMOUS` |
| Pipeline | `detect_anomalies` | `DetectAnomaliesNode` | `ANONYMOUS` |
| Pipeline | `score_fraud_risk` | `ScoreFraudRiskNode` | `ANONYMOUS` |
| Pipeline | `check_threshold` | `CheckThresholdNode` | `ANONYMOUS` |
| Pipeline | `generate_evidence_summary` | `GenerateEvidenceSummaryNode` | `ANONYMOUS` |
| Pipeline | `alert_if_required` | `AlertIfRequiredNode` | `ANONYMOUS` |
| Outer | `post_process` | `SecurityGateOutputNode` | `ANONYMOUS` |

A node's declared level is a FLOOR the caller must clear, not a grant. The
agent's entry requirement therefore sits on the one node that reads the
caller's data; requiring more on the output gate would deny a genuine external
caller and skip the gate on exactly the requests it exists to check.

---

## State

Defined in `src/schemas/state.py` as a flat TypedDict extending the framework
state. Both graph layers share it.

| Field | Written by | Purpose |
|---|---|---|
| `validated_input` | ValidateInputNode | the validated claim — allowlisted fields only |
| `claim_id` | ValidateInputNode | correlation key; the only caller value that is rendered |
| `out_of_scope` | ValidateInputNode | claim type has no rules; answered, not scored |
| `fraud_pattern_overrides` | the graph | the operator's `fraud_patterns` block |
| `fraud_patterns` | LoadHistoricalPatternsNode | the resolved rule-set |
| `anomaly_indicators` | DetectAnomaliesNode | matched rules with severity and weight |
| `fraud_score` | ScoreFraudRiskNode | 0–100 aggregate |
| `risk_factors` | ScoreFraudRiskNode | one readable line per indicator |
| `alert_level` | CheckThresholdNode | `none` / `warning` / `high` / `critical` |
| `threshold_exceeded` | CheckThresholdNode | whether an alert is required |
| `evidence_summary` | GenerateEvidenceSummaryNode | the investigator's evidence pack |
| `alert_payload` | AlertIfRequiredNode | the alert record |
| `alert_sent` | AlertIfRequiredNode | whether an alert was raised |
| `validated_output` | SecurityGateOutputNode | the published response |

---

## The caller-data contract

| Field | Required | Accepted |
|---|---|---|
| `claim_id` | yes | 6–40 characters of letters, digits and hyphens |
| `claim_type` | yes | one of auto, property, health, life, liability, workers_compensation, marine, travel — anything else is answered as out of scope |
| `claim_amount` | yes | a finite number in [0, 1e12] |
| `policy_number` | yes | 1–64 characters of letters, digits, hyphens and underscores |
| `claimant_id` | no | same shape as `policy_number` |
| `submission_date`, `incident_date`, `claim_channel` | no | text, at most 64 characters |
| `prior_claim_count` | no | a whole number in [0, 10000] |

Everything else the caller sends is dropped at this node. That includes
claimant identity fields, free-text notes no rule reads, and any attempt to
supply detection settings — those are the operator's and never the claimant's.

Refusals name the field and never the value: the message reaches the audit
trail, so echoing it would re-publish what was just refused.

### Bounds and screens

* **Numbers** go through a finite, range-checked parser that also rejects
  booleans. `NaN` parses and compares False against every threshold, so an
  unchecked one makes a claim of unknown size look like one below every tier.
* **Identifiers** rendered back to the caller are locked to letters, digits and
  hyphens, so nothing that reads as a line break, a list marker or markup can
  enter the assessment text.
* **Structure** is capped: request size, field count, list length and nesting
  depth.
* **Content** is screened for directive phrases and chat-template control
  tokens (`<|...|>`, `[INST]`, `<<SYS>>`), over keys as well as values, on the
  raw text and again after a markup strip. Both passes matter: stripping markup
  can delete a control token and forward the rest as ordinary prose, and it can
  re-assemble a directive the raw pass could not see.
* **Credential shapes** are refused with a message naming the field. The
  platform scans the result of every node and raises on a credential pattern,
  so such a claim fails here either way; catching it deliberately turns an
  opaque failure into one the caller can act on.

The screens live in the template rather than relying on the platform input
gate: that gate is configuration, and where it is absent or off the payload
would reach the detection rules unchecked. The tests drive them directly, with
no framework wrapper in front.

---

## The detection rules

Defined and validated in `src/services/patterns.py`; tuned in
`config/config.yaml` under `fraud_patterns`.

| Rule | Fires when | Severity | Default weight |
|---|---|---|---|
| `inflated_estimate` | amount ≥ very-high band (200 000) | high | 35.0 |
| `inflated_estimate` | amount ≥ high band (50 000) | medium | 20.0 |
| `suspicious_timing` | filed within 24 h of the incident | medium | 15.0 |
| `suspicious_timing` | first claim on the policy | low | 5.0 |
| `duplicate_detection` | resubmission with prior claims | high | 30.0 |
| `duplicate_detection` | resubmission, no prior claims | medium | 15.0 |

`score = min(sum(weight x severity multiplier), 100)`, with multipliers
high 1.00, medium 0.85, low 0.60.

| Tier | Boundary |
|---|---|
| `critical` | ≥ 75.0 |
| `high` | ≥ 60.0 |
| `warning` | ≥ 30.0 |
| `none` | below 30.0 |

The `critical` boundary is 75.0 rather than a rounder 80.0 for a reason worth
stating: the highest score these rules can produce is 77.75 (inflated 35.0 +
duplicate 30.0 + rapid report 12.75). A boundary above that names a tier no
claim can reach — which reads in a report as "no critical cases have occurred"
rather than as a setting that can never fire. `test_every_tier_is_reachable`
pins the arithmetic so a weight change cannot restore it quietly.

Indicator detail strings come from a closed set written in the node. No claim
value is interpolated into them: they travel into the evidence pack, and a
detail line assembled from caller text would be caller-controlled prose inside
a document a reader attributes to the agent.

---

## How operator settings reach the detectors

```
config/config.yaml
  -> Graph(config=...)                     the entry point loads the file
  -> _extra_initial_state()                seeded into the outer state
  -> FraudDetectionWorkflowNode.extract_input()   published on the bridge
  -> FraudDetectionDomainWorkflowGraph._extra_initial_state()   seeded inward
  -> LoadHistoricalPatternsNode            resolved into the rule-set
```

The subgraph contract hands the inner graph one string and nothing else — the
inner graph then builds a fresh initial state — so a declared setting has four
links to cross before a rule reads it. The failure mode of a broken link is not
an error: it is an agent quietly running on defaults while the file that
declares the settings still reads as authoritative. `tests/integration/`
therefore changes a declared value and asserts the alert tier moves, rather
than asserting any single link.

The same bridge carries the scope decision and the validated claim. Without it
the pipeline re-parsed the raw request in each step and never saw the scope
decision at all.

Malformed settings — a non-finite threshold, a tier order that makes a tier
unreachable, an unrecognised key — fail when the graph is constructed, not at
the moment a claim needed escalating.

---

## What is published, and what is not

The response the caller receives is the formatted output, falling back to the
raw result. `SecurityGateOutputNode` therefore walks every string in every
representation it is about to publish — including values nested inside the
evidence pack and the alert record — before any of it leaves.

On a violation it replaces every output-bearing field with a fixed notice.
Raising is not containment: the response builder falls back to the raw result
even on an error status, so a gate that merely raised would still ship the
ungated text inside the error envelope. The replacement is non-empty on
purpose — a blank value re-opens the same fallback the clearing exists to
close.

The credential check is the union of the platform detector and the template's
own patterns. Neither half is redundant: the platform patterns describe
credential formats and match nothing of the shape `password=...`, while a
purely local set would miss every format they cover. A value the platform
catches and this gate misses makes the platform raise inside post-process, at
which point the wrapper discards the clearing entirely — so narrowing either
half is a bypass.

The evidence pack is built by naming the fields it contains, never by copying
the claim and removing what should not travel. That is the only construction
whose failure mode is a missing field rather than a leaked one.

---

## Cat 2 nested contract

### FraudDetectionWorkflowNode (GraphNode)

| Member | Behaviour |
|---|---|
| `get_subgraph()` | instantiates the detection pipeline (imported inside the method) |
| `extract_input()` | publishes the hand-off; returns the claim identifier as the inner input |
| `merge_output()` | folds the pipeline result back, changed keys only; floors `out_of_scope` and `claim_id` at the outer values |
| `error_strategy` | `"propagate"` — a half-run screening must not be reported as one that found nothing |

### FraudDetectionDomainWorkflowGraph (BaseGraph)

`name`, `state_schema`, `_validate_config()`, `_extra_initial_state()`,
`register_nodes()`, `add_edges()`, `route()`, `get_output()`,
`get_state_class()`. Nodes take no constructor arguments; per-invocation data
reaches them through state.

---

## Framework use

* `AgentBaseGraph` — outer graph, direct framework inheritance
* `BaseGraph` — the detection pipeline
* `GraphNode` — the `main` slot
* `FunctionNode` — every domain node, `execute(self, state) -> dict`, returning
  only the keys it changes
* `AgentState` — the base the shared state extends
* `AgentStatus` enum constants, never plain status strings

No platform-internal imports; everything is from the framework and shared
packages.

---

## Design decisions

| Decision | Alternatives | Chosen | Why |
|---|---|---|---|
| Base class | AgentBaseGraph / AutonomousBaseGraph | AgentBaseGraph | fixed pipeline; no reasoning loop |
| Composition | one main node / nested subgraph | nested subgraph | six ordered steps need orchestration |
| Pipeline shape | linear / conditional | linear | every claim produces the same audit shape |
| Scoring | external model / rule aggregate | rule aggregate | deterministic and defensible in a dispute |
| Scope handling | score anyway / answer as out of scope | answer | a fabricated "no indicators" verdict is worse than declining |
| Rule-set source | caller payload / deployment config | deployment config | a threshold from the party being screened is an exploit |
| Alert delivery | outbound call / alert record | alert record | delivery is an operator integration concern |
| Context channel | accept structured context / input only | input only | a value on that channel is returned verbatim by the first node and then scanned, so an ordinary document containing a token-shaped string fails at node one |
