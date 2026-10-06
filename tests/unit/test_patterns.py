"""INS-C2-054 — the detection rule-set and its validation.

These numbers decide whether a claim is escalated. A misconfigured threshold
does not look like a failure at runtime: it looks like an agent that found
nothing. So the rule-set is validated when the graph is built, and everything
below is about what that validation refuses.
"""

import pytest

from src.services.patterns import DEFAULT_FRAUD_PATTERNS, PatternConfigError, resolve_patterns


class TestDefaults:
    def test_the_defaults_resolve(self):
        patterns = resolve_patterns()
        assert patterns["thresholds"] == DEFAULT_FRAUD_PATTERNS["thresholds"]

    def test_the_resolved_set_is_a_copy(self):
        resolve_patterns()["thresholds"]["warning"] = 999.0
        assert DEFAULT_FRAUD_PATTERNS["thresholds"]["warning"] == 30.0

    def test_every_tier_is_reachable_with_the_shipped_weights(self):
        """A tier boundary above the highest score the detectors can produce
        names an outcome that never fires — and reads in a report as an
        outcome that has never occurred. The arithmetic is pinned here so a
        weight change cannot restore that quietly."""
        patterns = resolve_patterns()
        weights = {"high": 1.00, "medium": 0.85, "low": 0.60}
        inflated = patterns["inflated_estimate"]["high_score_contribution"] * weights["high"]
        duplicate = patterns["duplicate_detection"]["score_contribution"] * weights["high"]
        rapid = patterns["suspicious_timing"]["rapid_submission_score"] * weights["medium"]
        best_case = min(inflated + duplicate + rapid, 100.0)
        assert best_case >= patterns["thresholds"]["critical"], (
            f"the highest achievable score is {best_case}, below the critical "
            f"boundary of {patterns['thresholds']['critical']}"
        )


class TestOverrides:
    def test_a_single_key_can_be_moved(self):
        patterns = resolve_patterns({"thresholds": {"critical": 95.0}})
        assert patterns["thresholds"]["critical"] == 95.0
        assert patterns["thresholds"]["high"] == 60.0

    def test_a_detector_can_be_switched_off(self):
        assert resolve_patterns({"duplicate_detection": {"enabled": False}})["duplicate_detection"]["enabled"] is False

    @pytest.mark.parametrize(
        "override",
        [
            {"typo_section": {"x": 1}},
            {"thresholds": {"criticall": 80.0}},
            {"thresholds": "not-a-mapping"},
        ],
    )
    def test_an_unrecognised_section_or_key_is_refused(self, override):
        """Refused rather than ignored: a typo that is quietly dropped disables
        a detector while the configuration file still reads as authoritative."""
        with pytest.raises(PatternConfigError):
            resolve_patterns(override)

    @pytest.mark.parametrize(
        "value", [float("nan"), float("inf"), float("-inf"), "NaN", "Infinity", -1.0, 101.0, True, "abc"]
    )
    def test_a_non_finite_or_out_of_range_threshold_is_refused(self, value):
        with pytest.raises(PatternConfigError):
            resolve_patterns({"thresholds": {"critical": value}})

    def test_a_non_boolean_enable_flag_is_refused(self):
        with pytest.raises(PatternConfigError):
            resolve_patterns({"duplicate_detection": {"enabled": "yes"}})

    def test_thresholds_out_of_order_are_refused(self):
        """A `high` below `warning` makes the high tier unreachable — which
        looks exactly like a working configuration."""
        with pytest.raises(PatternConfigError):
            resolve_patterns({"thresholds": {"warning": 90.0, "high": 10.0}})

    def test_inverted_amount_bands_are_refused(self):
        with pytest.raises(PatternConfigError):
            resolve_patterns(
                {"inflated_estimate": {"high_amount_threshold": 500.0, "very_high_amount_threshold": 100.0}}
            )

    def test_the_error_names_the_key(self):
        with pytest.raises(PatternConfigError) as exc:
            resolve_patterns({"suspicious_timing": {"rapid_submission_score": 900.0}})
        assert "suspicious_timing" in str(exc.value)
        assert "rapid_submission_score" in str(exc.value)
