"""AgentCore Platform v1.0"""

# Input-safety helpers for the claims fraud detection agent.
#
# Everything a caller can influence passes through this module before any
# detection rule reads it:
#
#   * numbers    -> _finite_in_range(): rejects bool, NaN, +/-Infinity and
#                   out-of-range magnitudes. float("nan") parses fine and every
#                   comparison against it is False, so an unchecked NaN amount
#                   silently scores as a small claim - fail-OPEN on the exact
#                   decision this agent exists to make.
#   * strings    -> bounded length, and locked to an inert character set when
#                   the value is rendered back to the caller.
#   * structure  -> field-count and nesting caps, so a hostile payload cannot
#                   turn one request into an unbounded amount of work.
#   * content    -> screen_for_injection(): directive phrases AND chat-template
#                   control tokens, checked on the raw text and again after a
#                   markup strip, over keys as well as values.
#
# The screens live here rather than relying on the platform input gate: that
# gate is configuration, and where it is absent or off the payload would reach
# the detection path unchecked. This node-owned screen is what the tests drive
# directly, with no framework wrapper in front of it.

from __future__ import annotations

import math
import re
import unicodedata
from typing import Any, Iterable

from framework.security.credential_detector import detect_credentials

# ---------------------------------------------------------------------------
# Structural limits
# ---------------------------------------------------------------------------

#: Largest request body the entry point will consider, in characters.
MAX_INPUT_CHARS: int = 16_000
#: Largest number of top-level fields a claim payload may carry.
MAX_CLAIM_FIELDS: int = 40
#: Largest length of any single caller-supplied string field.
MAX_FIELD_CHARS: int = 1_024
#: Largest number of entries in a caller-supplied list field.
MAX_LIST_ITEMS: int = 50
#: Deepest nesting the screen will walk before refusing the payload.
MAX_DEPTH: int = 6

#: Absolute bound on a monetary amount, in the claim's own currency units.
MAX_CLAIM_AMOUNT: float = 1e12
#: Absolute bound on a claim count.
MAX_CLAIM_COUNT: int = 10_000

#: Identifiers that are rendered back to the caller are locked to this shape.
#: Alphanumerics and hyphens only - nothing that could read as punctuation,
#: markup or a newline in the rendered assessment.
INERT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{4,38}[A-Za-z0-9]$")

#: Codes the pipeline carries but never renders (policy / claimant references).
_INERT_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$")

#: Field names are caller data too; only a plain name is ever echoed.
_SAFE_FIELD_NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,40}$")


class ClaimValidationError(ValueError):
    """A caller-supplied value failed validation.

    The message names the FIELD and the expected shape. It never carries the
    rejected value: an error string is written to the audit log and, on some
    paths, back to the caller, so echoing the value would re-publish exactly
    the content the screen just refused.
    """


# ---------------------------------------------------------------------------
# Field naming
# ---------------------------------------------------------------------------


def mask_field_name(name: object, position: int = 0) -> str:
    """Return a safe rendering of a caller-supplied field name."""
    text = name if isinstance(name, str) else ""
    if _SAFE_FIELD_NAME_RE.match(text) and not detect_credentials(text):
        return text
    return f"field #{position}"


# ---------------------------------------------------------------------------
# Numbers
# ---------------------------------------------------------------------------


def finite_in_range(
    field: str,
    value: object,
    minimum: float,
    maximum: float,
    *,
    allow_absent: bool = False,
    default: float = 0.0,
) -> float:
    """Return *value* as a finite float inside [minimum, maximum], or raise.

    Rejects, in this order:

    * ``None`` (unless *allow_absent*, which substitutes *default*);
    * ``bool`` - ``isinstance(True, int)`` is True in Python, so a JSON ``true``
      would otherwise be accepted and scored as the amount ``1.0``;
    * anything ``float()`` cannot parse;
    * ``NaN`` and ``+/-Infinity`` - both parse, and every ordering comparison
      against NaN is False, which makes an unchecked NaN look like a claim below
      every threshold;
    * magnitudes outside the declared range.
    """
    if value is None:
        if allow_absent:
            return default
        raise ClaimValidationError(f"'{field}' is required")
    if isinstance(value, bool):
        raise ClaimValidationError(f"'{field}' must be a number, not a boolean")
    if isinstance(value, str):
        value = value.strip()
        if not value:
            if allow_absent:
                return default
            raise ClaimValidationError(f"'{field}' is required")
        if len(value) > 40:
            raise ClaimValidationError(f"'{field}' is not a well-formed number")
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise ClaimValidationError(f"'{field}' is not a well-formed number") from None
    if not math.isfinite(number):
        raise ClaimValidationError(f"'{field}' must be a finite number")
    if number < minimum or number > maximum:
        raise ClaimValidationError(f"'{field}' must be between {minimum:g} and {maximum:g}")
    return number


def finite_int_in_range(
    field: str,
    value: object,
    minimum: int,
    maximum: int,
    *,
    allow_absent: bool = False,
    default: int = 0,
) -> int:
    """Return *value* as an int inside [minimum, maximum], or raise."""
    if value is None and allow_absent:
        return default
    number = finite_in_range(
        field, value, float(minimum), float(maximum), allow_absent=allow_absent, default=float(default)
    )
    if number != int(number):
        raise ClaimValidationError(f"'{field}' must be a whole number")
    return int(number)


# ---------------------------------------------------------------------------
# Strings
# ---------------------------------------------------------------------------


def bounded_text(field: str, value: object, *, max_chars: int = MAX_FIELD_CHARS) -> str:
    """Return *value* as a length-bounded string, or raise."""
    if not isinstance(value, str):
        raise ClaimValidationError(f"'{field}' must be text")
    if len(value) > max_chars:
        raise ClaimValidationError(f"'{field}' exceeds {max_chars} characters")
    return value.strip()


def inert_code(field: str, value: object) -> str:
    """Return *value* as a short inert code, or raise.

    For identifiers the pipeline carries but never renders (policy and claimant
    references). Looser than :func:`inert_identifier` on length — real policy
    numbers are often shorter than six characters — but the same closed
    character set, so nothing that could read as markup or a line break travels
    into a node result that the platform output gate then scans.
    """
    text = bounded_text(field, value, max_chars=64)
    if not _INERT_CODE_RE.match(text):
        raise ClaimValidationError(f"'{field}' must be 1-64 characters of letters, digits, hyphens and underscores")
    return text


def inert_identifier(field: str, value: object) -> str:
    """Return *value* as an identifier safe to render, or raise.

    Every identifier that reaches the assessment text goes through here, so a
    caller cannot introduce a newline, a list marker or markup into a rendering
    that a reader would attribute to the agent.
    """
    text = bounded_text(field, value, max_chars=40)
    if not INERT_ID_RE.match(text):
        raise ClaimValidationError(f"'{field}' must be 6-40 characters of letters, digits and hyphens")
    return text


# ---------------------------------------------------------------------------
# Injection screen
# ---------------------------------------------------------------------------

# Chat-template control tokens, screened as a CLASS rather than as individual
# literals. The platform's own scorer ranks `<<SYS>>` below its blocking
# threshold while blocking `<|im_start|>`, so a phrase-only screen lets the
# quietest form of the same attack through.
_CONTROL_TOKEN_RE = re.compile(
    r"<\|[^|>]{0,64}\|>"  # <|im_start|>, <|endoftext|>, ...
    r"|<</?SYS>>"  # <<SYS>> / <</SYS>>
    r"|\[/?INST\]"  # [INST] / [/INST]
    r"|<\|?(?:im_start|im_end|endoftext|system)\|?>",
    re.IGNORECASE,
)

# Directive phrases. Every pattern pairs a directive VERB with an object that
# means "the instructions you were given" - the pairing is what keeps ordinary
# claim prose ("the adjuster gave the claimant instructions") from matching.
_DIRECTIVE_RES: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}"
        r"\b(?:previous|prior|earlier|above|all|any|your)\b[^.\n]{0,20}"
        r"\b(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:reveal|print|show|repeat|output|disclose)\b[^.\n]{0,30}"
        r"\b(?:system|initial|hidden|original)\b[^.\n]{0,15}"
        r"\b(?:prompt|instruction|instructions|message)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\byou\s+are\s+now\s+(?:a|an|the)\b", re.IGNORECASE),
    re.compile(r"\bact\s+as\s+(?:if\s+you\s+are\s+)?(?:a|an|the)\s+" r"(?:different|new)\b", re.IGNORECASE),
    re.compile(r"\bnew\s+(?:system\s+)?(?:instructions|instruction|prompt)\s*[:\-]", re.IGNORECASE),
)

# Markup stripped before the second pass. A sanitizer that removes tags is not
# a refusal: stripping `<|im_start|>` turns a detectable token attack into
# undetectable plain text, and stripping the tags out of `ig<b>nore all
# previous instructions` re-assembles a directive that the raw pass could not
# see. Screening BOTH forms is what closes each half of that.
_MARKUP_RE = re.compile(r"<[^<>]{0,200}>")
# Zero-width and bidirectional-override characters, spelled as escapes: a literal
# character class here would be invisible in review and in a diff.
_ZERO_WIDTH_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")


def _strip_markup(text: str) -> str:
    """Return *text* with markup and zero-width characters removed."""
    return _MARKUP_RE.sub("", _ZERO_WIDTH_RE.sub("", text))


def _screen_text(text: str) -> str | None:
    """Return the name of the first screen a string trips, or None."""
    normalised = unicodedata.normalize("NFKC", text)
    for candidate in (normalised, _strip_markup(normalised)):
        if _CONTROL_TOKEN_RE.search(candidate):
            return "control_token"
        for pattern in _DIRECTIVE_RES:
            if pattern.search(candidate):
                return "directive_phrase"
    return None


def _walk(value: object, depth: int = 0) -> Iterable[tuple[str, str]]:
    """Yield ``(kind, text)`` for every string in *value*, keys included."""
    if depth > MAX_DEPTH:
        raise ClaimValidationError("claim payload is nested too deeply")
    if isinstance(value, str):
        yield ("value", value)
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                yield ("key", key)
            yield from _walk(item, depth + 1)
    elif isinstance(value, (list, tuple)):
        if len(value) > MAX_LIST_ITEMS:
            raise ClaimValidationError(f"a list field exceeds {MAX_LIST_ITEMS} entries")
        for item in value:
            yield from _walk(item, depth + 1)


def screen_for_injection(payload: object) -> str | None:
    """Return the name of the screen the payload trips, or None if it is clean.

    Walks the PARSED payload depth-first over both keys and values, so a
    ``\\u``-escaped attack that survives a scan of the raw request body is seen
    here in its decoded form, and a hostile field NAME is seen at all.
    """
    for _kind, text in _walk(payload):
        hit = _screen_text(text)
        if hit is not None:
            return hit
    return None


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

# Local additions. These describe credential HABITS rather than credential
# FORMATS, which is the half the platform detector does not carry: its patterns
# are all shapes (sk-..., AKIA..., eyJ...), so `password=hunter2` matches none
# of them. The gate takes the UNION - dropping either set would narrow it.
_LOCAL_CREDENTIAL_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("api_key_prefix", re.compile(r"\b(?:sk|pk|ak|rk)-[A-Za-z0-9]{16,}\b")),
    (
        "credential_assignment",
        re.compile(r"\b(?:password|passwd|secret|api[_-]?key|token|credential)\b\s*[:=]\s*\S+", re.IGNORECASE),
    ),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("email_address", re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}\b")),
)

#: Names of the local patterns, for audit events and tests.
LOCAL_CREDENTIAL_PATTERNS: tuple[str, ...] = tuple(name for name, _ in _LOCAL_CREDENTIAL_RES)


def detect_secrets(text: str) -> str | None:
    """Return the name of the first credential pattern *text* trips, or None.

    The union of the platform detector and the local patterns above. The
    platform half is the FLOOR: a value it catches and this gate missed would
    make the framework raise inside post-process, and the wrapper then discards
    whatever the gate had cleared - a detector gap is a containment bypass. The
    local half is what the platform does not carry.
    """
    if not isinstance(text, str) or not text:
        return None
    framework_findings = detect_credentials(text)
    if framework_findings:
        return str(framework_findings[0]["type"])
    for name, pattern in _LOCAL_CREDENTIAL_RES:
        if pattern.search(text):
            return name
    return None


def detect_secrets_in_value(value: Any, depth: int = 0) -> str | None:
    """Return the first credential pattern found anywhere inside *value*.

    Walks nested mappings and sequences: caller text one level down inside a
    structured field is exactly as visible to a reader as a top-level string,
    and a gate that scans only top-level strings reports zero findings on it.
    """
    if depth > MAX_DEPTH:
        return None
    if isinstance(value, str):
        return detect_secrets(value)
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                hit = detect_secrets(key)
                if hit is not None:
                    return hit
            hit = detect_secrets_in_value(item, depth + 1)
            if hit is not None:
                return hit
        return None
    if isinstance(value, (list, tuple)):
        for item in value:
            hit = detect_secrets_in_value(item, depth + 1)
            if hit is not None:
                return hit
        return None
    return None
