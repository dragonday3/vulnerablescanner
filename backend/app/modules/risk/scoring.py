"""Pure VRPS risk-scoring functions (Phase 7, PLAN_7.md §2).

No DB session, no network, no Redis -- plain functions over already-built
Finding/Misconfiguration instances and plain floats. Every branch returns a
concrete float or str; nothing here raises on a well-typed input.
"""

from app.models.finding import Finding, FindingValidationState
from app.models.misconfiguration import Misconfiguration
from app.modules.risk.scoring_config import (
    CVSS_TO_100_SCALE,
    MISCONFIG_RELATIVE_WEIGHT,
    RISK_TIER_BANDS,
    RISK_TIER_FLOOR,
    SEVERITY_FALLBACK_WEIGHT,
)


def score_finding_contribution(finding: Finding) -> float:
    """0-100. FALSE_POSITIVE findings contribute exactly zero -- per
    PLAN_5.md's own stated expectation for this phase. UNVALIDATED and
    CONFIRMED both contribute at full confidence-discounted weight;
    CONFIRMED gets no additional boost -- confidence_score is already
    the "how sure are we" signal, and double-counting validation on top
    of it would conflate two mechanisms CLAUDE.md is explicit about
    keeping independent.
    """
    if finding.validation_state == FindingValidationState.FALSE_POSITIVE:
        return 0.0
    base = (
        finding.cvss_score * CVSS_TO_100_SCALE
        if finding.cvss_score is not None
        else SEVERITY_FALLBACK_WEIGHT.get(finding.severity, 0.0)
    )
    base = min(base, 100.0)
    return base * (finding.confidence_score / 100.0)


def score_misconfiguration_contribution(misconfig: Misconfiguration) -> float:
    """0-100. No confidence/validation signal exists for Misconfiguration
    (Phase 6 deliberately scoped that out) -- flat severity weight,
    relatively discounted against a matched-CVE Finding's own weight.
    """
    return SEVERITY_FALLBACK_WEIGHT.get(misconfig.severity, 0.0) * MISCONFIG_RELATIVE_WEIGHT


def aggregate_risk(contributions: list[float]) -> float:
    """Noisy-OR aggregation: treats each 0-100 contribution as a
    0.0-1.0 'probability this thing alone makes the asset/scan risky',
    combines them as independent probabilities (1 - product(1 - p_i)),
    scales back to 0-100. A single near-100 contribution dominates the
    result; many small contributions add up without a plain sum blowing
    past 100. Empty input -> 0.0 (no evidence of risk), never raises.
    Used identically at both the per-Asset level (over that asset's
    Finding/Misconfiguration contributions) and the per-Scan level (over
    its assets' own already-aggregated risk_score values) -- see
    risk_scorer.py.
    """
    if not contributions:
        return 0.0
    survival = 1.0
    for contribution in contributions:
        clamped = max(0.0, min(contribution, 100.0)) / 100.0
        survival *= 1.0 - clamped
    return round((1.0 - survival) * 100.0, 2)


def tier_for_score(score: float) -> str:
    """Never raises -- RISK_TIER_FLOOR is always the fallback for any
    score below every band's threshold, including 0.0.
    """
    for threshold, tier in RISK_TIER_BANDS:
        if score >= threshold:
            return tier
    return RISK_TIER_FLOOR
