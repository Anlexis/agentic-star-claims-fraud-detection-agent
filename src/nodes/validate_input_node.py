"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return AgentStatus enum constants — never plain strings
#  - Never import from mediator/, api/, or other agents
#
# INS-C2-054 — ValidateInputNode
# Outer backbone pre_process slot (AgentBaseGraph).
# Owns the caller-data contract: it is the only place a raw claim submission is
# read, and nothing downstream sees a field this node did not validate.
#
# Input state keys:
#   user_input: str | dict — raw claim submission payload
#
# Output state keys (partial dict returned):
#   validated_input:  cleaned claim payload dict (only validated fields)
#   claim_id:         inert identifier extracted from the payload
#   out_of_scope:     bool — True when the claim type is outside this agent's remit
#   status:           AgentStatus.SUCCESS or AgentStatus.ERROR
#   error_log:        list[str] — appended errors; field names only, never values
#
# What this node refuses, and why each matters here:
#   * a payload that is not a JSON object, is oversized, or carries too many
#     fields — one request must not buy unbounded work;
#   * a claim_id that is not an inert identifier — it is interpolated into the
#     assessment text the caller reads back;
#   * a non-finite or out-of-range amount — NaN parses and compares False
#     against every threshold, so an unchecked NaN scores as a small claim;
#   * directive phrases and chat-template control tokens anywhere in the parsed
#     payload, keys included.
#
# The audit trail records the claim identifier and structural metadata only:
# claimant identity, amounts and free text never reach an audit event.

import json
import logging
from typing import Any, ClassVar, Dict, FrozenSet, List, Optional

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.services.security import (
    MAX_CLAIM_AMOUNT,
    MAX_CLAIM_COUNT,
    MAX_CLAIM_FIELDS,
    MAX_INPUT_CHARS,
    ClaimValidationError,
    bounded_text,
    detect_secrets_in_value,
    finite_in_range,
    finite_int_in_range,
    inert_code,
    inert_identifier,
    mask_field_name,
    screen_for_injection,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Claim contract
# ---------------------------------------------------------------------------

#: Claim types this agent has detection rules for. Anything else is answered
#: with the out-of-scope response rather than a fabricated risk assessment.
_RECOGNISED_CLAIM_TYPES: FrozenSet[str] = frozenset(
    {
        "auto",
        "property",
        "health",
        "life",
        "liability",
        "workers_compensation",
        "marine",
        "travel",
    }
)

#: Fields a claim must carry before any rule runs. Membership, not truthiness:
#: a zero-amount claim is a real claim and must be range-checked, not reported
#: as a missing field.
_REQUIRED_KEYS: List[str] = ["claim_id", "claim_type", "claim_amount", "policy_number"]

#: Reference codes carried forward but never rendered back to the caller.
_CODE_FIELDS: List[str] = ["policy_number", "claimant_id"]

#: Short free-text fields, length-bounded and carried forward.
_TEXT_FIELDS: List[str] = ["submission_date", "incident_date", "claim_channel"]

#: Fields never carried past this node. They exist in real claim systems and
#: callers do send them; the detection rules have no use for them, so the
#: cheapest way to keep them out of the evidence pack is to drop them here.
_DROPPED_PII_FIELDS: FrozenSet[str] = frozenset(
    {
        "claimant_name",
        "claimant_address",
        "claimant_dob",
        "claimant_phone",
        "claimant_email",
        "medical_info",
        "ssn",
        "national_id",
    }
)

# Nothing else is carried. Free-text fields a claim system routinely sends —
# `incident_description`, adjuster notes — are dropped even though they are
# harmless-looking: no detection rule reads them, an unread field still travels
# through every downstream scan, and free text is where a credential-shaped
# string would turn an ordinary claim into an unexplainable failure.


def _resolve_payload(user_input: Any) -> Optional[Dict[str, Any]]:
    """Parse user_input into a dict, or return None if it is not one."""
    if isinstance(user_input, dict):
        return user_input
    if isinstance(user_input, str):
        text = user_input.strip()
        if not text or len(text) > MAX_INPUT_CHARS:
            return None
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return None
        if isinstance(parsed, dict):
            return parsed
    return None


class ValidateInputNode(FunctionNode):
    """Validate and bound the incoming claim submission.

    Outer backbone pre_process slot. Produces the only claim payload the rest
    of the pipeline is allowed to read.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        error_log: List[str] = list(state.get("error_log") or [])

        def refuse(reason: str, event: str, detail: Dict[str, Any]) -> Dict[str, Any]:
            emit_trace_event(event, detail, state)
            return {
                "status": AgentStatus.ERROR,
                "error_log": error_log + [f"ValidateInputNode: {reason}"],
            }

        # 1. Shape — a claim submission is a JSON object, bounded in size.
        raw = _resolve_payload(state.get("user_input"))
        if raw is None:
            return refuse(
                "the request body is absent, oversized, or not a JSON claim object",
                "input_validation_failed",
                {"reason": "unparseable_payload"},
            )
        if len(raw) > MAX_CLAIM_FIELDS:
            return refuse(
                f"the claim payload carries more than {MAX_CLAIM_FIELDS} fields",
                "input_validation_failed",
                {"reason": "too_many_fields", "field_count": len(raw)},
            )

        # 2. Content screen — directive phrases and chat-template control
        #    tokens, over keys as well as values, raw and markup-stripped.
        try:
            injection = screen_for_injection(raw)
        except ClaimValidationError as exc:
            return refuse(str(exc), "input_validation_failed", {"reason": "payload_structure"})
        if injection is not None:
            return refuse(
                f"the claim payload contains content refused by the input screen ({injection})",
                "input_injection_blocked",
                {"reason": injection},
            )

        # 3. Required fields — membership, so amount 0 is present, not missing.
        missing = [k for k in _REQUIRED_KEYS if k not in raw or raw[k] is None]
        if missing:
            return refuse(
                f"missing required field(s): {', '.join(missing)}",
                "input_validation_failed",
                {"reason": "missing_fields", "missing_fields": missing},
            )

        # 4. Field-by-field validation. Every rejection names the field and
        #    never the value.
        cleaned: Dict[str, Any] = {}
        try:
            claim_id = inert_identifier("claim_id", raw["claim_id"])
            cleaned["claim_id"] = claim_id

            claim_type = bounded_text("claim_type", raw["claim_type"], max_chars=64).lower()
            cleaned["claim_type"] = claim_type

            cleaned["claim_amount"] = finite_in_range("claim_amount", raw["claim_amount"], 0.0, MAX_CLAIM_AMOUNT)

            for field in _CODE_FIELDS:
                if field in raw:
                    cleaned[field] = inert_code(field, raw[field])

            for field in _TEXT_FIELDS:
                if field in raw:
                    cleaned[field] = bounded_text(field, raw[field], max_chars=64)

            if "prior_claim_count" in raw:
                cleaned["prior_claim_count"] = finite_int_in_range(
                    "prior_claim_count",
                    raw["prior_claim_count"],
                    0,
                    MAX_CLAIM_COUNT,
                    allow_absent=True,
                )
        except ClaimValidationError as exc:
            return refuse(str(exc), "input_validation_failed", {"reason": "field_validation"})

        # 5. Fields that are neither validated nor needed are dropped rather
        #    than carried. Anything the caller sent that is not in `cleaned`
        #    stops here — including an attempt to supply detection thresholds,
        #    which are the operator's setting and never the claimant's.
        dropped = sorted(k for k in raw if k not in cleaned)
        pii_dropped = sorted(_DROPPED_PII_FIELDS.intersection(raw))

        # 6. Credential shapes in what survives. The platform scans the result
        #    of every node and raises on a credential pattern — so a claim
        #    carrying one fails at this node either way. Catching it here is
        #    what turns an opaque traceback into a refusal the caller can act
        #    on: it names the field, never the value.
        secret_field = next(
            (name for name, value in cleaned.items() if detect_secrets_in_value(value)),
            None,
        )
        if secret_field is not None:
            return refuse(
                f"'{secret_field}' looks like a credential and was refused",
                "input_credential_blocked",
                {"field": mask_field_name(secret_field)},
            )

        # 7. Scope decision. An unrecognised claim type gets the out-of-scope
        #    answer; it is NOT scored, because there are no rules for it and a
        #    fabricated "no fraud indicators" verdict would be worse than none.
        if claim_type not in _RECOGNISED_CLAIM_TYPES:
            logger.info("ValidateInputNode: claim_type not in recognised set — out of scope")
            emit_trace_event(
                "input_out_of_scope",
                {"claim_id": claim_id, "recognised": False},
                state,
            )
            return {
                "validated_input": cleaned,
                "claim_id": claim_id,
                "out_of_scope": True,
                "status": AgentStatus.SUCCESS,
                "error_log": error_log,
            }

        amount = float(cleaned["claim_amount"])
        logger.info("ValidateInputNode: validated claim_id=%s claim_type=%s", claim_id, claim_type)
        emit_trace_event(
            "input_validated",
            {
                "claim_id": claim_id,
                "claim_type": claim_type,
                # Bucket, not amount: an audit sink is a different trust domain
                # from the claims system that owns the figure.
                "amount_range": ("low" if amount < 10000 else "medium" if amount < 100000 else "high"),
                "field_count": len(cleaned),
                "dropped_field_count": len(dropped),
                "pii_fields_dropped": [mask_field_name(k, i) for i, k in enumerate(pii_dropped)],
            },
            state,
        )

        return {
            "validated_input": cleaned,
            "claim_id": claim_id,
            "out_of_scope": False,
            "status": AgentStatus.SUCCESS,
            "error_log": error_log,
        }
