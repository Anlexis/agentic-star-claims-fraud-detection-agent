# Claims Fraud Detection Agent

AI agent for detecting insurance claims fraud and alerting investigators, built with Agentic Star.

> **Category**: Cat 2 (Domain-specific pipeline)
> **Industry**: Insurance
> **Template ID**: INS-C2-054

## Overview

Screens a submitted insurance claim for fraud indicators and decides whether it should go to a
special investigation unit. A claims system posts one claim record — identifier, type, amount,
policy reference, submission and incident dates, claim channel, prior-claim count — and the agent
applies a configured set of fraud-pattern rules to it, aggregates the matches into a 0–100 risk
score, maps the score onto an alert tier, and returns a short assessment. Above the alert
threshold it also produces an alert record and an evidence pack: the matched indicators, the
contributing factors and a recommended next step, in the form an investigator opens a case from.

The pipeline is deterministic and rule-based. There is no model call, no retrieval and no
outbound request, so the same claim scores the same way every time — which is what makes the
result defensible when a claimant disputes it. The rules themselves (amount bands, timing
windows, resubmission weights, tier boundaries) are deployment configuration, not code, and are
validated when the agent starts rather than when a claim first needs escalating.

Two things it deliberately does not do. A claim type it has no rules for is answered as out of
scope rather than scored — a fabricated "no fraud indicators found" verdict is worse than
declining to assess. And detection settings are never taken from the claim payload: a threshold
supplied by the party being screened is not configuration.

This is an agent template built with the **AGENTIC STAR** development platform and the
**AgentCore Framework**. It is intended to be taken as a starting point: fork it, adapt it to
your own data and policies, and run it inside your own AGENTIC STAR deployment.

## Requirements

**This template does not run standalone.** It requires:

| Requirement | Notes |
|---|---|
| **AGENTIC STAR platform** | The agent connects to the platform at start-up. Without it, start-up fails immediately (see *Behaviour without the platform* below). Deployment guides and API documentation: [AGENTIC STAR Developers](https://developers.fd.agenticstar.tm.softbank.jp/) |
| **AgentCore Framework** (`agenticstar-agentcore`) | Installed from PyPI as a dependency. |
| Python | >=3.11 |

```bash
pip install -e .
```

### Behaviour without the platform

The framework is designed to run **only** on AGENTIC STAR. There is no fallback or degraded
mode. If the platform is unreachable or the installed framework version does not match, graph
compilation and start-up preflight fail and the agent refuses to start rather than coming up in a
partially working state. This is intentional — a half-running agent is worse than one that
refuses to start.

## Quick Start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Tests run without a platform connection. Running the agent itself does not.

### Calling the agent

The whole request is the claim record, JSON-encoded into `input`. There is no side channel:

```json
{
  "input": "{\"claim_id\": \"CLM-2024-001234\", \"claim_type\": \"auto\", \"claim_amount\": 5000.0, \"policy_number\": \"POL-12345\", \"submission_date\": \"2024-01-16T10:30:00\", \"incident_date\": \"2024-01-14T08:00:00\", \"claimant_id\": \"CLI-9876\", \"claim_channel\": \"online\", \"prior_claim_count\": 0}"
}
```

`claim_id`, `claim_type`, `claim_amount` and `policy_number` are required; `submission_date`,
`incident_date`, `claimant_id`, `claim_channel` and `prior_claim_count` are optional and feed
individual rules. Every field is bounded and shape-checked, and anything else the caller sends is
dropped — including claimant identity fields, which no rule reads and which must not travel into
an evidence pack. A refusal names the field and never repeats the value.

The standalone entry point authenticates the caller: set `INVOKE_AUTH_TOKEN` in the server
environment and present it as `Authorization: Bearer <token>`.

### Tuning the rules

`config/config.yaml` holds the alert tier boundaries, the amount bands, the timing windows and
the per-rule weights. Only the keys documented there are tunable — an unrecognised key is refused
at start-up rather than ignored, so a typo cannot quietly disable a detector. Raising a tier
boundary above the highest score the rules can produce is also refused, because a tier that can
never fire reads in a report as a tier that has never occurred.

## Project Structure

```
src/          agent implementation (nodes, graph, services, schemas)
tests/        unit, integration and boundary tests
config/       agent manifest (agent.yaml) and runtime parameters (config.yaml)
docs/         design specification and test specification
```

See `docs/02_design.md` for the architecture, the caller contract and the output boundary, and
`docs/03_test_spec.md` for what the suite proves.

## Customising

1. Adjust `config/config.yaml` — tier boundaries, amount bands, timing windows, rule weights.
2. Add or replace detectors in `src/nodes/detect_anomalies_node.py`, and declare their bounds in
   `src/services/patterns.py` so a misconfigured weight fails at start-up.
3. Extend the accepted claim fields in `src/nodes/validate_input_node.py`; every new field needs
   a bound, and every value that reaches the assessment text needs an inert shape.
4. Re-run the test suite.

## License

MIT — see [LICENSE](LICENSE).

## Status of this repository

This template is published **as is**, by its individual author, under the MIT license. It carries
**no warranty and no support commitment**, and no organisation stands behind its behaviour or
fitness for any purpose. Issues and pull requests may or may not receive a response; that is at
the sole discretion of the repository owner.
