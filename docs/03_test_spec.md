# INS-C2-054 — test specification

## Metadata

| Field | Value |
|---|---|
| Template ID | INS-C2-054 |
| Category | Cat 2 (nested: outer backbone + detection pipeline) |
| Suite | `tests/unit/`, `tests/integration/`, `tests/proof_of_boundary/` |
| Totals | 251 passing, 2 skipped |

## Strategy

Three layers, each proving something the others cannot.

**Unit** — every node is driven through `execute()` directly, with no framework
wrapper in front of it. A test that asserts "the platform refused this" proves
only that the platform gate was configured on that run; what has to hold is
that this template refuses it on its own.

**Integration** — the two properties that only exist across the whole graph: a
value declared in `config/config.yaml` reaching the detectors and changing the
answer, and nothing reaching the caller that the output gate did not pass.

**Proof of boundary** — framework compliance, plus the caller contract driven
through the real ASGI entry point as an ASGI application, so the request model,
the entry-point authentication, the adapter bounds and the compiled graph are
all in the path.

Audit emitters are patched at each node module's own namespace and never
stubbed in `sys.modules`: the shared package is real in the deployed runtime,
and registering a stub for it there breaks every framework import that depends
on it.

Every screen is probed in both directions — the attack forms are refused, and
ordinary insurance prose containing the same words is not. A screen that fires
on "the adjuster gave the claimant instructions" is not a stricter screen, it
is a refusal to process real claims.

---

## Framework compliance — `tests/proof_of_boundary/`

| ID | File | Checks |
|---|---|---|
| PB-1 | `test_import_isolation.py` | no platform-internal import anywhere in `src/` |
| PB-2 | `test_state_safety.py` | no credential-shaped field name in the state |
| PB-5 | `test_state_safety.py` | the state is a flat TypedDict — no model classes |
| PB-6a | `test_pb_invoke_order.py` | per-node call order: trust gate, start event, input gate, `execute()`, output gate, complete event |
| PB-6b | `test_pb_invoke_order.py` | a full invocation with the standard claim returns success |
| PB-6c | `test_pb_invoke_order.py` | the `main` slot holds the subgraph node |
| PB-6d | `test_pb_invoke_order.py` | backbone order: initialize, pre_process, main, post_process, finalize |
| PB-7 | `test_pb7_hitl_interrupt_propagation.py` | human-review propagation — skipped; this agent declares no review step |
| TC-06/07 | `tests/unit/test_framework_compliance_tc06_tc07.py` | the framework security gates cannot be overridden |

## The HTTP boundary — `tests/proof_of_boundary/test_pb_http_invoke.py`

| Group | Checks |
|---|---|
| Authentication | health answers without a credential; a missing, wrong or malformed bearer is refused with one uniform message; an authenticated request is served |
| Adapter bounds | an oversized body is refused with 400 before the graph runs |
| Outcome paths | no alert; warning; high; critical; out of scope — each reachable end to end |
| Refusal paths | invalid claim, non-finite amount, non-inert identifier, negative count, each injection form, prose instead of a claim |
| The response | carries no policy or claimant reference; no traceback or source path survives a failure |
| Deploy payload | the committed first-invoke payload satisfies the entry contract |

The authentication group is not a formality. The entry gate requires a verified
external caller and nothing upstream establishes that in a standalone
deployment, so without the adapter's bearer check every invoke is refused
before any node runs — while the health endpoint stays green.

## End to end — `tests/integration/test_config_and_containment.py`

| Group | Checks |
|---|---|
| Declared config | the shipped file is what the entry point loads; raising the thresholds changes the tier; lowering an amount band changes the score; disabling a detector removes its contribution |
| Startup validation | a non-finite threshold, an out-of-order tier set, an unknown section and an unknown key each fail at construction |
| Caller tampering | detection settings in the claim payload do not apply — on the normal path and on the out-of-scope path |
| Containment | a failed run publishes no partial assessment; no traceback or source path reaches the caller; a credential faulted onto the data path never reaches the caller — measured for both credential classes below; the out-of-scope answer carries no assessment |

The containment cases fault the DATA path, not the gate: the alert node is made
to compose an assessment carrying a credential, and the gate is left exactly as
shipped.

Two credential classes are used, because they exercise different layers and only
one of them says anything about this template:

* a **platform-shaped** credential (`AKIA…`) is refused by the platform's own
  output gate before the assessment is assembled, so the run ends with nothing
  published at all. That case passes even with this agent's gate removed — it is
  the outer proof, not a statement about this code.
* a credential **habit** (`password=…`) matches no platform pattern, so the
  assessment reaches this agent's gate intact. That case is the one whose result
  depends on what the gate does, and it is what the mutant matrix is measured
  against.

The second case asserts both halves: the credential is gone, and the fixed
notice is what was published in its place. The response builder falls back to
the raw result whenever the formatted output is falsy, so a blank replacement
would re-open the channel the clearing exists to close and only the second
assertion would catch it.

---

## Unit tests

### `ValidateInputNode` — the caller-data contract

| Checks |
|---|
| a valid claim is accepted; the entry level is VERIFIED_EXTERNAL |
| each required field, missing, is refused and named |
| a zero-amount claim is present, not missing — presence is membership, not truthiness |
| `NaN`, `nan`, `Infinity`, `-Infinity` and their float forms are refused, as strings and as raw values |
| a boolean amount is refused — `isinstance(True, int)` is True, so it would otherwise score as 1.0 |
| negative, over-range and malformed amounts are refused |
| a bad `prior_claim_count` (non-finite, negative, over-range, fractional, boolean) is refused |
| an identifier carrying a line break, markup or a space is refused |
| a rejected value is never echoed into the error |
| an unrecognised claim type is out of scope, not scored |
| claimant identity fields are dropped |
| detection settings in the payload are dropped |
| a body that is not a claim object, is empty, or is oversized is refused |
| a payload with too many fields is refused |

### `LoadHistoricalPatternsNode`

Defaults when nothing is declared; an override merged key by key; a malformed
override fails the run; an upstream failure is propagated, not absorbed; an
out-of-scope claim loads no rule-set.

### `DetectAnomaliesNode`

Each detector fires on its own signal and not otherwise; no claim value is
interpolated into an indicator detail; an upstream failure is propagated; a
missing rule-set fails rather than scoring zero.

### `ScoreFraudRiskNode`

Severity weights are applied; the score is capped at 100; an upstream failure
is never scored as zero risk. That last one is the fail-open case: the status
value is a lower-case string enum, so a comparison against `"ERROR"` matches
nothing — which is how an upstream failure became a clean "no anomaly
indicators detected" verdict.

### `CheckThresholdNode`

Every tier is reachable; the operator's thresholds are what is compared; a
missing score fails rather than defaulting to no alert; a missing rule-set
fails rather than falling back to a local constant.

### `GenerateEvidenceSummaryNode`

The pack carries exactly the fields it names; no claimant or policy reference
appears in it; the recommendation matches the tier; an incomplete assessment
produces no pack.

### `AlertIfRequiredNode`

An alert is raised above the threshold and not below; the alert record carries
no copy of the claim; a failed run composes no assessment line; the
out-of-scope answer is not an assessment.

### `SecurityGateOutputNode`

The gate runs for every caller; a clean assessment is published; a credential
in any published representation blocks it — for each pattern in the union,
including one nested inside the evidence pack; a blocked response replaces
every output-bearing field with a non-empty notice; a failed run releases
nothing; an empty assessment is not published.

### `src/services/security.py` — `tests/unit/test_input_safety.py`

The finite parser's rejection matrix per field; identifier and code shapes;
the injection screen against each attack form, a spliced directive, a hidden
control token, a hostile field name, an escaped payload, a nested payload and
zero-width characters — and against seven pieces of ordinary insurance prose
that must pass; structural caps; the credential union in both halves.

### `src/services/patterns.py` — `tests/unit/test_patterns.py`

The defaults resolve and are copied, not shared; a single key can be moved; a
detector can be switched off; an unrecognised section or key is refused rather
than ignored; non-finite and out-of-range values are refused; tiers out of
order and inverted amount bands are refused; the error names the key; every
tier is reachable with the shipped weights.

---

## Security coverage

| Concern | Where it is proved |
|---|---|
| Caller authentication | `TestEntryPointAuthentication` — the deployed path, not a unit call |
| Input validation | `TestValidateInputNode` + `TestFiniteParsing` + the HTTP refusal paths |
| Injection screening | `TestInjectionScreen` + `TestRefusalPathsAreReachable`, both directions |
| Output containment | `TestSecurityGateOutputNode` + `TestContainment`, with a data-path mutant |
| Credential detection | `TestCredentialUnion` — each half proved to catch what the other misses |
| Audit trail | every node's domain event, and the gate script that enforces their presence |
| Configuration integrity | `TestOverrides` + `test_a_malformed_config_fails_at_startup` |
