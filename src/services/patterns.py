"""AgentCore Platform v1.0"""

# The fraud pattern rule-set and its validation.
#
# These numbers decide whether a claim is escalated to a special investigation
# unit, so every one of them is bounded and finite-checked before a detector
# reads it. An operator typo that put `critical: NaN` in the deployment config
# would otherwise compare False against every score and quietly stop the agent
# escalating anything.
#
# Operators tune the rule-set in `config/config.yaml` under `fraud_patterns:`.
# The override is merged section by section, so a deployment that only wants to
# move one threshold writes only that threshold.

from __future__ import annotations

import math
from typing import Any, Dict, Mapping, Optional


class PatternConfigError(ValueError):
    """The fraud pattern rule-set is not usable as configured."""


#: The rule-set an untuned deployment runs on.
DEFAULT_FRAUD_PATTERNS: Dict[str, Dict[str, Any]] = {
    "duplicate_detection": {
        "enabled": True,
        "score_contribution": 30.0,
    },
    "inflated_estimate": {
        "enabled": True,
        "high_amount_threshold": 50_000.0,
        "very_high_amount_threshold": 200_000.0,
        "moderate_score_contribution": 20.0,
        "high_score_contribution": 35.0,
    },
    "suspicious_timing": {
        "enabled": True,
        "rapid_submission_hours": 24.0,
        "rapid_submission_score": 15.0,
        "first_claim_score": 5.0,
    },
    # Tier boundaries. The highest score the detectors above can actually
    # produce is 77.75 — an inflated estimate at very-high severity (35.0), a
    # resubmission on a policy with prior claims (30.0) and a rapid report
    # (15.0 x 0.85). A `critical` boundary of 80.0 therefore named a tier that
    # no claim could ever reach, which reads as "we have never seen a critical
    # case" rather than as a misconfiguration. `test_every_tier_is_reachable`
    # pins the property so a future weight change cannot silently restore it.
    "thresholds": {
        "warning": 30.0,
        "high": 60.0,
        "critical": 75.0,
    },
}

#: Every numeric key, with the range it must sit inside. A key absent from this
#: table is not a tunable — an override that names one is refused rather than
#: silently ignored, so a typo in a deployment config fails loudly at startup
#: instead of disabling a detector at runtime.
_NUMERIC_BOUNDS: Dict[str, Dict[str, tuple[float, float]]] = {
    "duplicate_detection": {"score_contribution": (0.0, 100.0)},
    "inflated_estimate": {
        "high_amount_threshold": (0.0, 1e12),
        "very_high_amount_threshold": (0.0, 1e12),
        "moderate_score_contribution": (0.0, 100.0),
        "high_score_contribution": (0.0, 100.0),
    },
    "suspicious_timing": {
        "rapid_submission_hours": (0.0, 8760.0),
        "rapid_submission_score": (0.0, 100.0),
        "first_claim_score": (0.0, 100.0),
    },
    "thresholds": {
        "warning": (0.0, 100.0),
        "high": (0.0, 100.0),
        "critical": (0.0, 100.0),
    },
}

_BOOL_KEYS = frozenset({"enabled"})


def _bounded(section: str, key: str, value: object, low: float, high: float) -> float:
    if isinstance(value, bool):
        raise PatternConfigError(f"fraud_patterns.{section}.{key} must be a number, not a boolean")
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise PatternConfigError(f"fraud_patterns.{section}.{key} is not a number") from None
    if not math.isfinite(number):
        raise PatternConfigError(f"fraud_patterns.{section}.{key} must be a finite number")
    if number < low or number > high:
        raise PatternConfigError(f"fraud_patterns.{section}.{key} must be between {low:g} and {high:g}")
    return number


def resolve_patterns(overrides: Optional[Mapping[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    """Return the effective rule-set, merging *overrides* over the defaults.

    Raises :class:`PatternConfigError` on an unknown section or key, a
    non-finite or out-of-range number, or thresholds that are not strictly
    increasing (a `high` below `warning` would make the `high` tier
    unreachable, which looks like a working configuration and is not).
    """
    patterns: Dict[str, Dict[str, Any]] = {section: dict(values) for section, values in DEFAULT_FRAUD_PATTERNS.items()}

    if overrides:
        if not isinstance(overrides, Mapping):
            raise PatternConfigError("fraud_patterns must be a mapping")
        for section, values in overrides.items():
            if section not in patterns:
                raise PatternConfigError(f"fraud_patterns has no section '{section}'")
            if not isinstance(values, Mapping):
                raise PatternConfigError(f"fraud_patterns.{section} must be a mapping")
            for key, value in values.items():
                if key in _BOOL_KEYS:
                    if not isinstance(value, bool):
                        raise PatternConfigError(f"fraud_patterns.{section}.{key} must be true or false")
                    patterns[section][key] = value
                    continue
                bounds = _NUMERIC_BOUNDS.get(section, {}).get(key)
                if bounds is None:
                    raise PatternConfigError(f"fraud_patterns.{section} has no key '{key}'")
                patterns[section][key] = _bounded(section, key, value, *bounds)

    # Re-validate the merged result, so a bad DEFAULT would be caught too.
    for section, keys in _NUMERIC_BOUNDS.items():
        for key, (low, high) in keys.items():
            patterns[section][key] = _bounded(section, key, patterns[section][key], low, high)

    thresholds = patterns["thresholds"]
    if not (thresholds["warning"] <= thresholds["high"] <= thresholds["critical"]):
        raise PatternConfigError("fraud_patterns.thresholds must satisfy warning <= high <= critical")
    inflated = patterns["inflated_estimate"]
    if inflated["high_amount_threshold"] > inflated["very_high_amount_threshold"]:
        raise PatternConfigError(
            "fraud_patterns.inflated_estimate.high_amount_threshold must not exceed " "very_high_amount_threshold"
        )
    return patterns
