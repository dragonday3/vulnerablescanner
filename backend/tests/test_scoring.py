"""Unit tests for the pure VRPS scoring functions (Phase 7, PLAN_7.md §6).

Zero DB/network/Redis dependency: Finding and Misconfiguration instances are
constructed directly in memory (no session, never added/flushed), which is
all these functions read.
"""

from __future__ import annotations

import random

import pytest

from app.models.finding import Finding, FindingValidationState
from app.models.misconfiguration import Misconfiguration
from app.modules.risk.scoring import (
    aggregate_risk,
    score_finding_contribution,
    score_misconfiguration_contribution,
    tier_for_score,
)


def _finding(
    *,
    cvss_score: float | None,
    severity: str,
    confidence_score: float,
    validation_state: FindingValidationState = FindingValidationState.UNVALIDATED,
) -> Finding:
    return Finding(
        cve_id="CVE-2021-41773",
        matched_cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        severity=severity,
        cvss_score=cvss_score,
        evidence={},
        confidence_score=confidence_score,
        validation_state=validation_state,
    )


def _misconfig(severity: str) -> Misconfiguration:
    return Misconfiguration(
        check_id="missing-hsts",
        title="Missing HSTS",
        severity=severity,
        description="",
        evidence={},
    )


# --- score_finding_contribution -------------------------------------------


def test_finding_cvss_present_uses_cvss_not_severity_fallback() -> None:
    # cvss 7.5 * 10 = 75.0 at full confidence. The severity string is
    # deliberately CRITICAL (fallback weight 90.0) to prove the CVSS branch
    # wins whenever cvss_score is present.
    finding = _finding(cvss_score=7.5, severity="CRITICAL", confidence_score=100.0)
    assert score_finding_contribution(finding) == pytest.approx(75.0)


def test_finding_cvss_absent_falls_back_to_severity_weight() -> None:
    # No cvss_score: HIGH -> SEVERITY_FALLBACK_WEIGHT["HIGH"] == 70.0.
    finding = _finding(cvss_score=None, severity="HIGH", confidence_score=100.0)
    assert score_finding_contribution(finding) == pytest.approx(70.0)


def test_finding_unknown_severity_with_no_cvss_contributes_zero() -> None:
    finding = _finding(cvss_score=None, severity="BOGUS", confidence_score=100.0)
    assert score_finding_contribution(finding) == 0.0


def test_finding_cvss_contribution_clamped_to_100() -> None:
    # cvss_score is 0-10 by NVD contract, but the function's documented
    # 0-100 range must hold even for an out-of-contract value.
    finding = _finding(cvss_score=12.0, severity="CRITICAL", confidence_score=100.0)
    assert score_finding_contribution(finding) == pytest.approx(100.0)


def test_finding_confidence_discount_applied() -> None:
    # cvss 8.0 -> base 80.0; confidence 50 halves it to 40.0.
    finding = _finding(cvss_score=8.0, severity="HIGH", confidence_score=50.0)
    assert score_finding_contribution(finding) == pytest.approx(40.0)


@pytest.mark.parametrize(
    ("cvss_score", "severity", "confidence_score"),
    [
        (9.8, "CRITICAL", 100.0),
        (9.8, "CRITICAL", 0.0),
        (None, "CRITICAL", 100.0),
        (None, "HIGH", 50.0),
        (5.0, "LOW", 75.0),
    ],
)
def test_false_positive_contributes_exactly_zero(
    cvss_score: float | None, severity: str, confidence_score: float
) -> None:
    finding = _finding(
        cvss_score=cvss_score,
        severity=severity,
        confidence_score=confidence_score,
        validation_state=FindingValidationState.FALSE_POSITIVE,
    )
    assert score_finding_contribution(finding) == 0.0


def test_unvalidated_and_confirmed_contribute_identically() -> None:
    # Same finding, only validation_state differs: CONFIRMED gets no boost
    # beyond the FALSE_POSITIVE exclusion rule, so both must match exactly.
    unvalidated = _finding(
        cvss_score=6.4,
        severity="MEDIUM",
        confidence_score=80.0,
        validation_state=FindingValidationState.UNVALIDATED,
    )
    confirmed = _finding(
        cvss_score=6.4,
        severity="MEDIUM",
        confidence_score=80.0,
        validation_state=FindingValidationState.CONFIRMED,
    )
    assert score_finding_contribution(unvalidated) == score_finding_contribution(confirmed)
    assert score_finding_contribution(confirmed) == pytest.approx(64.0 * 0.8)


# --- score_misconfiguration_contribution ----------------------------------


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        # SEVERITY_FALLBACK_WEIGHT * MISCONFIG_RELATIVE_WEIGHT (0.6)
        ("CRITICAL", 90.0 * 0.6),
        ("HIGH", 70.0 * 0.6),
        ("MEDIUM", 40.0 * 0.6),
        ("LOW", 15.0 * 0.6),
    ],
)
def test_misconfiguration_contribution_per_severity(severity: str, expected: float) -> None:
    assert score_misconfiguration_contribution(_misconfig(severity)) == pytest.approx(expected)


def test_misconfiguration_relative_weight_is_applied() -> None:
    # Strictly below the same-severity Finding fallback (70.0 for HIGH), which
    # is the whole point of the relative weight.
    assert score_misconfiguration_contribution(_misconfig("HIGH")) < 70.0


# --- aggregate_risk -------------------------------------------------------


def test_aggregate_risk_empty_is_zero() -> None:
    assert aggregate_risk([]) == 0.0


def test_aggregate_risk_single_contribution_rounds_to_two_decimals() -> None:
    # For n=1, noisy-OR is the identity on the value itself (1 - (1 - p) = p);
    # the discriminating math is covered by the multi-input cases below. This
    # case pins the single-input output shape: scaled back to 0-100 and
    # rounded to 2 decimal places.
    assert aggregate_risk([33.333]) == 33.33


def test_aggregate_risk_noisy_or_not_plain_sum() -> None:
    # Noisy-OR: 1 - (1 - 0.5)(1 - 0.5) = 0.75 -> 75.0.
    # A plain sum would give 100.0; a max would give 50.0.
    assert aggregate_risk([50.0, 50.0]) == pytest.approx(75.0)


def test_aggregate_risk_noisy_or_three_inputs() -> None:
    # 1 - (1 - 0.5)(1 - 0.25)(1 - 0.2) = 1 - 0.5 * 0.75 * 0.8 = 0.7 -> 70.0.
    assert aggregate_risk([50.0, 25.0, 20.0]) == pytest.approx(70.0)


def test_aggregate_risk_hundred_saturates_with_small_others() -> None:
    assert aggregate_risk([100.0, 10.0, 5.0]) == pytest.approx(100.0)


def test_aggregate_risk_many_small_contributions_never_exceed_100() -> None:
    # 1 - 0.95^100 ~= 99.41 -- climbs toward 100, never reaches or passes it.
    result = aggregate_risk([5.0] * 100)
    assert result < 100.0
    assert result == pytest.approx(99.41, abs=0.01)


def test_aggregate_risk_is_order_independent() -> None:
    contributions = [12.5, 40.0, 3.0, 67.25, 0.5, 22.0]
    expected = aggregate_risk(contributions)
    rng = random.Random(7)
    for _ in range(20):
        shuffled = list(contributions)
        rng.shuffle(shuffled)
        assert aggregate_risk(shuffled) == expected


# --- tier_for_score -------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, "NONE"),
        (0.005, "NONE"),
        (0.01, "LOW"),
        (24.99, "LOW"),
        (25.0, "MEDIUM"),
        (49.99, "MEDIUM"),
        (50.0, "HIGH"),
        (74.99, "HIGH"),
        (75.0, "CRITICAL"),
        (100.0, "CRITICAL"),
    ],
)
def test_tier_for_score_band_edges(score: float, expected: str) -> None:
    assert tier_for_score(score) == expected
