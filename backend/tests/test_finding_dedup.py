"""Unit tests for the pure CVE-dedup helper shared by risk scoring and
reporting (see finding_dedup.py's own docstring for the artifact it fixes).
"""

from __future__ import annotations

from app.models.finding import Finding, FindingValidationState
from app.modules.vulnerability.finding_dedup import dedupe_findings_by_cve


def _finding(
    cve_id: str,
    matched_cpe: str,
    *,
    confidence_score: float = 100.0,
    validation_state: FindingValidationState = FindingValidationState.UNVALIDATED,
) -> Finding:
    return Finding(
        cve_id=cve_id,
        matched_cpe=matched_cpe,
        severity="HIGH",
        cvss_score=7.5,
        evidence={},
        confidence_score=confidence_score,
        validation_state=validation_state,
    )


def test_empty_list_returns_empty_list() -> None:
    assert dedupe_findings_by_cve([]) == []


def test_no_duplicates_returns_all_unchanged() -> None:
    a = _finding("CVE-1", "cpe:a")
    b = _finding("CVE-2", "cpe:b")
    assert dedupe_findings_by_cve([a, b]) == [a, b]


def test_two_cpes_same_cve_collapses_to_one() -> None:
    a = _finding("CVE-1", "cpe:a")
    b = _finding("CVE-1", "cpe:b")
    result = dedupe_findings_by_cve([a, b])
    assert len(result) == 1


def test_prefers_non_false_positive_regardless_of_order() -> None:
    fp = _finding("CVE-1", "cpe:a", validation_state=FindingValidationState.FALSE_POSITIVE)
    real = _finding("CVE-1", "cpe:b", validation_state=FindingValidationState.UNVALIDATED)

    assert dedupe_findings_by_cve([fp, real]) == [real]
    assert dedupe_findings_by_cve([real, fp]) == [real]


def test_both_false_positive_falls_back_to_higher_confidence() -> None:
    low = _finding(
        "CVE-1",
        "cpe:a",
        confidence_score=40.0,
        validation_state=FindingValidationState.FALSE_POSITIVE,
    )
    high = _finding(
        "CVE-1",
        "cpe:b",
        confidence_score=90.0,
        validation_state=FindingValidationState.FALSE_POSITIVE,
    )
    assert dedupe_findings_by_cve([low, high]) == [high]
    assert dedupe_findings_by_cve([high, low]) == [high]


def test_both_non_false_positive_falls_back_to_higher_confidence() -> None:
    low = _finding("CVE-1", "cpe:a", confidence_score=40.0)
    high = _finding("CVE-1", "cpe:b", confidence_score=90.0)
    assert dedupe_findings_by_cve([low, high]) == [high]
    assert dedupe_findings_by_cve([high, low]) == [high]


def test_three_cpes_same_cve_collapses_to_one_best() -> None:
    a = _finding("CVE-1", "cpe:a", confidence_score=10.0)
    b = _finding("CVE-1", "cpe:b", confidence_score=90.0)
    c = _finding("CVE-1", "cpe:c", confidence_score=50.0)
    assert dedupe_findings_by_cve([a, b, c]) == [b]


def test_different_cves_on_otherwise_identical_findings_are_not_merged() -> None:
    a = _finding("CVE-1", "cpe:a")
    b = _finding("CVE-2", "cpe:a")
    result = dedupe_findings_by_cve([a, b])
    assert len(result) == 2
