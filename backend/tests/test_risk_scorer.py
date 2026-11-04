"""Unit-level tests for `score_assets` (Phase 7, PLAN_7.md section 3/6).

Mirrors `test_correlator.py`/`test_analyzer.py`'s own style: a thin
`_make_asset` helper builds a persisted Asset (with its required
Target/Scan/Project ancestry) plus Service/Finding/Misconfiguration rows,
and the per-asset isolation claim is PROVEN by making one asset's own
contribution-gathering actually raise, not just asserted against an
already-defensively-handled input shape.
"""

from __future__ import annotations

from unittest.mock import patch

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import Finding, FindingValidationState
from app.models.misconfiguration import Misconfiguration
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.service import Service
from app.models.target import Target, TargetType
from app.modules.risk import risk_scorer
from app.modules.risk.risk_scorer import score_assets


def _make_scan(db: Session) -> Scan:
    project = Project(name="Risk Scorer Test Project")
    db.add(project)
    db.flush()

    target = Target(
        project_id=project.id,
        value="127.0.0.1",
        target_type=TargetType.IP,
        authorization_confirmed=True,
    )
    db.add(target)
    db.flush()

    scan = Scan(project_id=project.id, target_id=target.id, status=ScanStatus.RISK_ANALYSIS)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def _make_asset(db: Session, scan: Scan, host: str = "127.0.0.1") -> Asset:
    asset = Asset(project_id=scan.project_id, target_id=scan.target_id, scan_id=scan.id, host=host)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def _add_service(db: Session, asset: Asset, port: int = 80) -> Service:
    service = Service(asset_id=asset.id, port=port, protocol="tcp", state="open")
    db.add(service)
    db.commit()
    db.refresh(service)
    return service


def _add_finding(
    db: Session,
    service: Service,
    *,
    cvss_score: float | None = 9.0,
    severity: str = "CRITICAL",
    confidence_score: float = 100.0,
    validation_state: FindingValidationState = FindingValidationState.UNVALIDATED,
    cve_id: str = "CVE-2021-41773",
    matched_cpe: str = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
) -> Finding:
    finding = Finding(
        service_id=service.id,
        cve_id=cve_id,
        matched_cpe=matched_cpe,
        severity=severity,
        cvss_score=cvss_score,
        evidence={},
        confidence_score=confidence_score,
        validation_state=validation_state,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def _add_misconfig(db: Session, service: Service, severity: str = "HIGH") -> Misconfiguration:
    misconfig = Misconfiguration(
        service_id=service.id,
        check_id="missing-hsts",
        title="Missing HSTS",
        severity=severity,
        description="",
        evidence={},
    )
    db.add(misconfig)
    db.commit()
    db.refresh(misconfig)
    return misconfig


# ---------------------------------------------------------------------------
# Per-asset isolation: one asset's contribution-gathering raising must not
# abort scoring of the rest of the scan's assets (correlator.py's own
# per-CPE isolation claim / analyzer.py's per-service isolation claim,
# mirrored here per-asset).
# ---------------------------------------------------------------------------


def test_per_asset_isolation_one_failure_does_not_abort_the_rest(db: Session) -> None:
    """Two assets, both with real Finding evidence; `score_finding_contribution`
    is made to raise for ONLY the service belonging to the second asset
    (simulating a scoring call blowing up on some unanticipated input
    shape). The first asset's risk_score/risk_tier must still be correctly
    persisted and committed, and the scan-level aggregate must be computed
    from that one successfully-scored asset only -- proving per-asset
    isolation rather than merely asserting it.
    """
    scan = _make_scan(db)
    asset_a = _make_asset(db, scan, host="10.0.0.1")
    asset_b = _make_asset(db, scan, host="10.0.0.2")

    service_a = _add_service(db, asset_a, port=443)
    _add_finding(db, service_a, cvss_score=9.0, confidence_score=100.0)  # contributes 90.0

    service_b = _add_service(db, asset_b, port=443)
    _add_finding(db, service_b, cvss_score=9.0, confidence_score=100.0)

    real_score_finding_contribution = risk_scorer.score_finding_contribution

    def _raise_for_b(finding: Finding) -> float:
        if finding.service_id == service_b.id:
            raise RuntimeError("boom: simulated scoring failure for asset B's service")
        return real_score_finding_contribution(finding)

    with patch.object(risk_scorer, "score_finding_contribution", side_effect=_raise_for_b):
        score_assets(db, scan, [asset_a, asset_b])

    db.refresh(asset_a)
    db.refresh(asset_b)
    db.refresh(scan)

    # Asset A: successfully scored.
    assert asset_a.risk_score == 90.0
    assert asset_a.risk_tier == "CRITICAL"

    # Asset B: its own scoring raised -- its try/except rolled back and
    # moved on, leaving risk_score/risk_tier unset (None, "never scored"),
    # not silently coerced to 0.0/"NONE".
    assert asset_b.risk_score is None
    assert asset_b.risk_tier is None

    # Scan-level aggregate: computed from asset A's own persisted
    # risk_score only -- asset B's failed scoring contributes nothing.
    assert scan.risk_score == 90.0
    assert scan.risk_tier == "CRITICAL"


def test_all_assets_failing_leaves_scan_risk_score_null_not_zero(db: Session) -> None:
    """One scan, exactly one Asset, and that asset's own scoring raises --
    today's only way for step 1 to end with zero successfully-scored
    assets. `scored_asset_scores` is then empty, but it must NOT be
    passed into `aggregate_risk`/`tier_for_score` and committed onto
    `scan.risk_score`/`risk_tier` as 0.0/"NONE": that would be
    indistinguishable from a genuinely clean scan (CLAUDE.md's Global
    Constraint 6). The scan-level columns must stay exactly as they were
    before this call -- NULL, since this scan was never scored.
    """
    scan = _make_scan(db)
    asset = _make_asset(db, scan)
    service = _add_service(db, asset, port=443)
    _add_finding(db, service, cvss_score=9.0, confidence_score=100.0)

    assert scan.risk_score is None
    assert scan.risk_tier is None

    with patch.object(
        risk_scorer,
        "score_finding_contribution",
        side_effect=RuntimeError("boom: simulated scoring failure for the only asset"),
    ):
        score_assets(db, scan, [asset])

    db.refresh(asset)
    db.refresh(scan)

    # The one asset's scoring raised -- left exactly as it was (never
    # scored), not coerced to 0.0/"NONE".
    assert asset.risk_score is None
    assert asset.risk_tier is None

    # The scan-level aggregate must likewise be left untouched -- NOT
    # computed as aggregate_risk([]) == 0.0 / tier_for_score(0.0) ==
    # "NONE", which would look identical to a genuinely clean scan.
    assert scan.risk_score is None
    assert scan.risk_tier is None


# ---------------------------------------------------------------------------
# Scan-level aggregate is computed from assets' own persisted risk_score
# values, not recomputed from raw findings/misconfigs.
# ---------------------------------------------------------------------------


def test_scan_aggregate_uses_assets_persisted_risk_scores(db: Session) -> None:
    scan = _make_scan(db)
    asset_a = _make_asset(db, scan, host="10.0.0.1")
    asset_b = _make_asset(db, scan, host="10.0.0.2")

    service_a = _add_service(db, asset_a, port=443)
    _add_finding(db, service_a, cvss_score=5.0, confidence_score=100.0)  # 50.0

    service_b = _add_service(db, asset_b, port=443)
    _add_finding(db, service_b, cvss_score=2.5, confidence_score=100.0)  # 25.0

    score_assets(db, scan, [asset_a, asset_b])

    db.refresh(asset_a)
    db.refresh(asset_b)
    db.refresh(scan)

    assert asset_a.risk_score == 50.0
    assert asset_b.risk_score == 25.0

    # Noisy-OR over the assets' own persisted scores:
    # 1 - (1 - 0.5)(1 - 0.25) = 0.625 -> 62.5.
    assert scan.risk_score == 62.5
    assert scan.risk_tier == "HIGH"


def test_scan_aggregate_is_built_from_asset_risk_score_values(db: Session) -> None:
    """Directly inspects the arguments `score_assets` passes into
    `aggregate_risk` on its second (scan-level) call: they must be the
    assets' own persisted `risk_score` floats, not a recomputed list of
    raw Finding/Misconfiguration contributions (which would be a longer
    list with different values -- two findings on one asset collapse into
    ONE `risk_score` float per asset by the time step 2 runs).
    """
    scan = _make_scan(db)
    asset = _make_asset(db, scan)
    service = _add_service(db, asset, port=443)
    # Two findings on the same asset -> two raw contributions, but exactly
    # ONE asset.risk_score once step 1 aggregates them.
    _add_finding(
        db, service, cvss_score=9.0, confidence_score=100.0, severity="CRITICAL", cve_id="CVE-A"
    )
    _add_finding(
        db, service, cvss_score=5.0, confidence_score=100.0, severity="MEDIUM", cve_id="CVE-B"
    )

    real_aggregate_risk = risk_scorer.aggregate_risk
    calls: list[list[float]] = []

    def _recording_aggregate_risk(contributions: list[float]) -> float:
        calls.append(list(contributions))
        return real_aggregate_risk(contributions)

    with patch.object(risk_scorer, "aggregate_risk", side_effect=_recording_aggregate_risk):
        score_assets(db, scan, [asset])

    db.refresh(asset)
    db.refresh(scan)

    # First call: step 1's raw per-finding contributions (two of them).
    assert len(calls[0]) == 2
    # Second call: step 2's scan-level call, exactly one float -- the
    # asset's own already-persisted risk_score -- not the two raw
    # contributions recomputed.
    assert calls[1] == [asset.risk_score]
    assert scan.risk_score == asset.risk_score


# ---------------------------------------------------------------------------
# An asset with zero findings/misconfigs lands on risk_score=0.0/
# risk_tier="NONE", never NULL -- distinguishing "scored, nothing found"
# from "never scored".
# ---------------------------------------------------------------------------


def test_asset_with_no_findings_or_misconfigs_scores_zero_not_null(db: Session) -> None:
    scan = _make_scan(db)
    asset = _make_asset(db, scan)
    _add_service(db, asset, port=22)  # open service, no findings/misconfigs at all

    score_assets(db, scan, [asset])

    db.refresh(asset)
    db.refresh(scan)

    assert asset.risk_score == 0.0
    assert asset.risk_tier == "NONE"
    assert scan.risk_score == 0.0
    assert scan.risk_tier == "NONE"


def test_asset_with_no_services_scores_zero_not_null(db: Session) -> None:
    scan = _make_scan(db)
    asset = _make_asset(db, scan)  # no services at all

    score_assets(db, scan, [asset])

    db.refresh(asset)
    assert asset.risk_score == 0.0
    assert asset.risk_tier == "NONE"


# ---------------------------------------------------------------------------
# scan.status is never touched by this module -- the one deliberate
# exception to the inherited "never touch scan" discipline is writing
# scan.risk_score/risk_tier only.
# ---------------------------------------------------------------------------


def test_score_assets_never_mutates_scan_status(db: Session) -> None:
    scan = _make_scan(db)
    asset = _make_asset(db, scan)
    service = _add_service(db, asset, port=443)
    _add_finding(db, service, cvss_score=9.0, confidence_score=100.0)

    score_assets(db, scan, [asset])

    db.refresh(scan)
    assert scan.status == ScanStatus.RISK_ANALYSIS


def test_false_positive_finding_contributes_nothing_to_asset_score(db: Session) -> None:
    scan = _make_scan(db)
    asset = _make_asset(db, scan)
    service = _add_service(db, asset, port=443)
    _add_finding(
        db,
        service,
        cvss_score=9.8,
        confidence_score=100.0,
        validation_state=FindingValidationState.FALSE_POSITIVE,
    )

    score_assets(db, scan, [asset])

    db.refresh(asset)
    assert asset.risk_score == 0.0
    assert asset.risk_tier == "NONE"


# ---------------------------------------------------------------------------
# CVE double-counting: the same CVE matched via two different CPEs on the
# SAME service is a correlation artifact and must contribute exactly one
# noisy-OR term, not two (finding_dedup.py). The same CVE on two different
# services is a real, separate vulnerable surface and must still contribute
# twice -- dedup is scoped per-service, not per-asset.
# ---------------------------------------------------------------------------


def test_same_cve_two_cpes_one_service_contributes_once(db: Session) -> None:
    scan = _make_scan(db)
    asset = _make_asset(db, scan)
    service = _add_service(db, asset, port=443)
    _add_finding(
        db,
        service,
        cve_id="CVE-2021-41773",
        matched_cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        cvss_score=9.0,
        confidence_score=100.0,
    )
    _add_finding(
        db,
        service,
        cve_id="CVE-2021-41773",
        matched_cpe="cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*",
        cvss_score=9.0,
        confidence_score=100.0,
    )

    score_assets(db, scan, [asset])

    db.refresh(asset)
    # If this double-counted, noisy-OR over [90.0, 90.0] would be
    # 1 - (1-0.9)(1-0.9) = 99.0, not 90.0.
    assert asset.risk_score == 90.0
    assert asset.risk_tier == "CRITICAL"


def test_same_cve_two_different_services_still_contributes_twice(db: Session) -> None:
    scan = _make_scan(db)
    asset = _make_asset(db, scan)
    service_a = _add_service(db, asset, port=443)
    service_b = _add_service(db, asset, port=8443)
    _add_finding(db, service_a, cve_id="CVE-2021-41773", cvss_score=9.0, confidence_score=100.0)
    _add_finding(db, service_b, cve_id="CVE-2021-41773", cvss_score=9.0, confidence_score=100.0)

    score_assets(db, scan, [asset])

    db.refresh(asset)
    # Two distinct services genuinely both vulnerable -> noisy-OR over
    # [90.0, 90.0] = 99.0, deliberately NOT deduped across services.
    assert asset.risk_score == 99.0
    assert asset.risk_tier == "CRITICAL"


def test_dedup_prefers_non_false_positive_over_false_positive(db: Session) -> None:
    """One CPE's match was reviewed and dismissed; the other CPE's match
    on the exact same CVE/service was not. The real (non-FP) match must
    still contribute -- reviewing out one CPE's evidence is not evidence
    the CVE is absent via the other CPE too.
    """
    scan = _make_scan(db)
    asset = _make_asset(db, scan)
    service = _add_service(db, asset, port=443)
    _add_finding(
        db,
        service,
        cve_id="CVE-2021-41773",
        matched_cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        cvss_score=9.0,
        confidence_score=100.0,
        validation_state=FindingValidationState.FALSE_POSITIVE,
    )
    _add_finding(
        db,
        service,
        cve_id="CVE-2021-41773",
        matched_cpe="cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*",
        cvss_score=9.0,
        confidence_score=100.0,
        validation_state=FindingValidationState.UNVALIDATED,
    )

    score_assets(db, scan, [asset])

    db.refresh(asset)
    assert asset.risk_score == 90.0


def test_asset_score_combines_findings_and_misconfigs_across_services(db: Session) -> None:
    scan = _make_scan(db)
    asset = _make_asset(db, scan)
    service_a = _add_service(db, asset, port=443)
    _add_finding(db, service_a, cvss_score=5.0, confidence_score=100.0)  # 50.0
    service_b = _add_service(db, asset, port=8080)
    _add_misconfig(db, service_b, severity="HIGH")  # 70.0 * 0.6 = 42.0

    score_assets(db, scan, [asset])

    db.refresh(asset)
    # Noisy-OR: 1 - (1 - 0.5)(1 - 0.42) = 1 - 0.5 * 0.58 = 0.71 -> 71.0.
    assert asset.risk_score == 71.0
    assert asset.risk_tier == "HIGH"
