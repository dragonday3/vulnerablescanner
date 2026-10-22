"""Unit-level tests for `correlate_services` (Task 5, PLAN_4.md section 5).

`nvd_client.fetch_cves_for_cpe` is mocked directly via
`patch.object(nvd_client, "fetch_cves_for_cpe", ...)` -- `correlator.py`
calls it through the `nvd_client` module reference (not a bound local
import), so this patch takes effect regardless of which module object
calls it. No real Redis or HTTP is touched anywhere in this file: the
`redis_client` fixture's connection is passed through to
`correlate_services` purely because the function signature requires one,
but since `fetch_cves_for_cpe` itself is replaced by the mock, that
connection is never actually used to talk to Redis.
"""

from __future__ import annotations

from unittest.mock import patch

import redis
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.service import Service
from app.models.target import Target, TargetType
from app.modules.vulnerability import cache, nvd_client
from app.modules.vulnerability.correlator import MAX_DISTINCT_CPES_PER_SCAN, correlate_services


def _make_service(db: Session, evidence: dict | None, port: int = 80) -> Service:
    """Build and persist one Service row (with its required Asset/Target/
    Scan/Project ancestry) carrying the given `evidence` dict, mirroring
    the shape `run_scan_task` itself produces for an nmap-adapter scan.
    """
    project = Project(name="Correlator Test Project")
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

    scan = Scan(project_id=project.id, target_id=target.id, status=ScanStatus.CORRELATING)
    db.add(scan)
    db.flush()

    asset = Asset(project_id=project.id, target_id=target.id, scan_id=scan.id, host="127.0.0.1")
    db.add(asset)
    db.flush()

    service = Service(
        asset_id=asset.id,
        port=port,
        protocol="tcp",
        state="open",
        fingerprint_source="nmap-sv",
        evidence=evidence,
    )
    db.add(service)
    db.commit()
    db.refresh(service)
    return service


def _cves(*cve_ids: str) -> list[nvd_client.NormalizedCve]:
    return [
        nvd_client.NormalizedCve(
            cve_id=cve_id,
            description=f"Description for {cve_id}",
            severity="HIGH",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            references=["https://example.com/advisory"],
            raw={"id": cve_id, "nested": {"a": 1}},
        )
        for cve_id in cve_ids
    ]


CPE22 = "cpe:/a:nginx:nginx:1.24.0"
CPE23 = "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"


def test_service_with_no_cpe_evidence_is_skipped(db: Session, redis_client: redis.Redis) -> None:
    """A Service with no `evidence` at all, or evidence lacking a truthy
    `"cpe"` key, must never trigger a lookup.
    """
    service_no_evidence = _make_service(db, evidence=None, port=22)
    service_empty_evidence = _make_service(db, evidence={}, port=23)
    service_empty_cpe_list = _make_service(db, evidence={"cpe": []}, port=24)

    with patch.object(nvd_client, "fetch_cves_for_cpe") as mock_fetch:
        correlate_services(
            db,
            redis_client,
            [service_no_evidence, service_empty_evidence, service_empty_cpe_list],
        )

    mock_fetch.assert_not_called()
    assert db.execute(select(Finding)).first() is None


def test_dedup_looks_up_shared_cpe_once_and_persists_findings_for_both_services(
    db: Session, redis_client: redis.Redis
) -> None:
    """Two Service rows sharing the same CPE string must trigger exactly
    one NVD lookup (the dedup step), but Finding rows must be persisted
    for BOTH services independently -- one full set each, never merged
    into one.
    """
    service_a = _make_service(db, evidence={"cpe": [CPE22]}, port=80)
    service_b = _make_service(db, evidence={"cpe": [CPE22]}, port=443)

    with patch.object(
        nvd_client, "fetch_cves_for_cpe", return_value=_cves("CVE-2021-41773")
    ) as mock_fetch:
        correlate_services(db, redis_client, [service_a, service_b])

    mock_fetch.assert_called_once_with(CPE23, redis_client)

    findings_a = (
        db.execute(select(Finding).where(Finding.service_id == service_a.id)).scalars().all()
    )
    findings_b = (
        db.execute(select(Finding).where(Finding.service_id == service_b.id)).scalars().all()
    )
    assert len(findings_a) == 1
    assert len(findings_b) == 1
    assert findings_a[0].cve_id == "CVE-2021-41773"
    assert findings_b[0].cve_id == "CVE-2021-41773"
    assert findings_a[0].matched_cpe == CPE23
    assert findings_b[0].matched_cpe == CPE23


def test_per_scan_cap_only_processes_first_max_distinct_cpes(
    db: Session, redis_client: redis.Redis
) -> None:
    """More distinct CPEs than MAX_DISTINCT_CPES_PER_SCAN must result in
    only the capped number being looked up; the remainder are skipped
    (not retried, not an error).
    """
    total_cpes = MAX_DISTINCT_CPES_PER_SCAN + 5
    services = [
        _make_service(
            db,
            evidence={"cpe": [f"cpe:/a:vendor{i}:product{i}:1.0"]},
            port=1000 + i,
        )
        for i in range(total_cpes)
    ]

    with patch.object(
        nvd_client, "fetch_cves_for_cpe", return_value=_cves("CVE-0000-0001")
    ) as mock_fetch:
        correlate_services(db, redis_client, services)

    assert mock_fetch.call_count == MAX_DISTINCT_CPES_PER_SCAN

    all_findings = db.execute(select(Finding)).scalars().all()
    # Exactly one Finding per processed CPE (one service each, one CVE each).
    assert len(all_findings) == MAX_DISTINCT_CPES_PER_SCAN


def test_lookup_failure_persists_no_findings_and_no_cache_row(
    db: Session, redis_client: redis.Redis
) -> None:
    """A mocked `None` return (an NVD lookup failure) must produce zero
    Finding rows, raise no exception, and write no CveCache row for that
    CPE -- a transient failure must never get permanently cached as
    "zero known vulnerabilities."
    """
    service = _make_service(db, evidence={"cpe": [CPE22]}, port=80)

    with patch.object(nvd_client, "fetch_cves_for_cpe", return_value=None) as mock_fetch:
        correlate_services(db, redis_client, [service])

    mock_fetch.assert_called_once()
    assert db.execute(select(Finding).where(Finding.service_id == service.id)).first() is None
    assert cache.get_cached(db, CPE23) is None


def test_cache_hit_skips_nvd_call_entirely(db: Session, redis_client: redis.Redis) -> None:
    """A fresh (non-stale) CveCache row for a CPE must short-circuit the
    whole NVD lookup -- the mock must never be called for that CPE at
    all, and Finding rows must still be built from the cached data.
    """
    cache.store(db, CPE23, _cves("CVE-2021-41773", "CVE-2021-42013"), total_results=2)

    service = _make_service(db, evidence={"cpe": [CPE22]}, port=80)

    with patch.object(nvd_client, "fetch_cves_for_cpe") as mock_fetch:
        correlate_services(db, redis_client, [service])

    mock_fetch.assert_not_called()

    findings = db.execute(select(Finding).where(Finding.service_id == service.id)).scalars().all()
    cve_ids = {f.cve_id for f in findings}
    assert cve_ids == {"CVE-2021-41773", "CVE-2021-42013"}


def test_incremental_commit_survives_rollback_from_later_cpe_failure(
    db: Session, redis_client: redis.Redis
) -> None:
    """The commit-cadence contract: with three distinct CPEs to process,
    and `fetch_cves_for_cpe` raising on the SECOND call only, the FIRST
    CPE's Finding rows must still be committed and queryable afterward
    (surviving the outer except's db.rollback()), even though the
    function as a whole caught the exception, logged it, and returned
    without ever processing the third CPE.
    """
    service_1 = _make_service(db, evidence={"cpe": ["cpe:/a:vendor1:product1:1.0"]}, port=81)
    service_2 = _make_service(db, evidence={"cpe": ["cpe:/a:vendor2:product2:1.0"]}, port=82)
    service_3 = _make_service(db, evidence={"cpe": ["cpe:/a:vendor3:product3:1.0"]}, port=83)

    with patch.object(
        nvd_client,
        "fetch_cves_for_cpe",
        side_effect=[_cves("CVE-0001-0001"), RuntimeError("boom: second CPE blew up")],
    ) as mock_fetch:
        # Must not raise past correlate_services -- the outer try/except
        # is the structural safety net for exactly this kind of
        # unexpected failure.
        correlate_services(db, redis_client, [service_1, service_2, service_3])

    assert mock_fetch.call_count == 2  # third CPE never attempted

    findings_1 = (
        db.execute(select(Finding).where(Finding.service_id == service_1.id)).scalars().all()
    )
    findings_2 = (
        db.execute(select(Finding).where(Finding.service_id == service_2.id)).scalars().all()
    )
    findings_3 = (
        db.execute(select(Finding).where(Finding.service_id == service_3.id)).scalars().all()
    )

    # First CPE's work survived the rollback triggered by the second CPE's
    # failure.
    assert len(findings_1) == 1
    assert findings_1[0].cve_id == "CVE-0001-0001"
    # Second CPE's (nonexistent, since it raised before any Finding was
    # built) and third CPE's (never attempted) work are both absent.
    assert findings_2 == []
    assert findings_3 == []
