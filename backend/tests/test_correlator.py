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
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.service import Service
from app.models.target import Target, TargetType
from app.modules.vulnerability import cache, nvd_client
from app.modules.vulnerability.correlator import MAX_DISTINCT_CPES_PER_SCAN, correlate_services
from app.modules.vulnerability.nvd_client import NvdFetchResult


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


def _fetch_result(*cve_ids: str, total_results: int | None = None) -> NvdFetchResult:
    """`nvd_client.fetch_cves_for_cpe` returns `NvdFetchResult | None`,
    not a bare list -- every mocked `return_value`/`side_effect` below
    must match that real return shape.
    """
    cves = _cves(*cve_ids)
    resolved_total = total_results if total_results is not None else len(cves)
    return NvdFetchResult(cves=cves, total_results=resolved_total)


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


def test_versionless_cpe_is_skipped_without_attempting_lookup(
    db: Session, redis_client: redis.Redis
) -> None:
    """A CPE with a wildcarded (`*`) or NA (`-`) version component can
    never succeed against NVD's cpeName lookup (NVD 404s on it every
    time) -- it must be skipped during CPE selection, never even passed
    to `fetch_cves_for_cpe`, so it doesn't burn a rate-limit slot or a
    MAX_DISTINCT_CPES_PER_SCAN slot on a query that can't succeed. A
    properly-versioned CPE in the same batch must still be looked up
    normally.
    """
    # nmap emits this shape when it identifies vendor/product but not a
    # specific version -- `cpe:/o:linux:linux_kernel` with no version
    # segment at all converts to a trailing-wildcard CPE 2.3 string.
    service_wildcard = _make_service(db, evidence={"cpe": ["cpe:/o:linux:linux_kernel"]}, port=1)
    # An explicit CPE 2.2 NA ("-") version segment.
    service_na = _make_service(db, evidence={"cpe": ["cpe:/o:linux:linux_kernel:-"]}, port=2)
    service_versioned = _make_service(db, evidence={"cpe": [CPE22]}, port=3)

    with patch.object(
        nvd_client, "fetch_cves_for_cpe", return_value=_fetch_result("CVE-2021-41773")
    ) as mock_fetch:
        correlate_services(db, redis_client, [service_wildcard, service_na, service_versioned])

    # Only the properly-versioned CPE was ever looked up.
    mock_fetch.assert_called_once_with(CPE23, redis_client)

    wildcard_findings = db.execute(
        select(Finding).where(Finding.service_id == service_wildcard.id)
    ).first()
    na_findings = db.execute(select(Finding).where(Finding.service_id == service_na.id)).first()
    assert wildcard_findings is None
    assert na_findings is None
    findings_versioned = (
        db.execute(select(Finding).where(Finding.service_id == service_versioned.id))
        .scalars()
        .all()
    )
    assert len(findings_versioned) == 1


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
        nvd_client, "fetch_cves_for_cpe", return_value=_fetch_result("CVE-2021-41773")
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
        nvd_client, "fetch_cves_for_cpe", return_value=_fetch_result("CVE-0000-0001")
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


def test_per_cpe_failure_skips_only_that_cpe_not_every_cpe_after_it(
    db: Session, redis_client: redis.Redis
) -> None:
    """Final-review fix-wave behavioral change (finding 3): with three
    distinct CPEs to process, and `fetch_cves_for_cpe` raising on the
    SECOND call only, the FIRST CPE's Finding rows must still be
    committed and queryable afterward, AND -- this is the key change
    from the pre-fix behavior -- the THIRD CPE must still be attempted
    and get its own Finding rows. Before the fix, the second CPE's
    exception propagated up to the single outer try/except, which
    rolled back and returned without ever touching the third CPE; now
    each CPE has its own try/except, so a failure processing one CPE
    only skips that CPE.
    """
    service_1 = _make_service(db, evidence={"cpe": ["cpe:/a:vendor1:product1:1.0"]}, port=81)
    service_2 = _make_service(db, evidence={"cpe": ["cpe:/a:vendor2:product2:1.0"]}, port=82)
    service_3 = _make_service(db, evidence={"cpe": ["cpe:/a:vendor3:product3:1.0"]}, port=83)

    with patch.object(
        nvd_client,
        "fetch_cves_for_cpe",
        side_effect=[
            _fetch_result("CVE-0001-0001"),
            RuntimeError("boom: second CPE blew up"),
            _fetch_result("CVE-0003-0001"),
        ],
    ) as mock_fetch:
        # Must not raise past correlate_services -- the outer try/except
        # is still the structural safety net for anything the per-CPE
        # isolation didn't anticipate, but this particular failure is
        # now caught by the per-CPE try/except instead.
        correlate_services(db, redis_client, [service_1, service_2, service_3])

    # All three CPEs attempted -- the second one's failure did not abort
    # the third.
    assert mock_fetch.call_count == 3

    findings_1 = (
        db.execute(select(Finding).where(Finding.service_id == service_1.id)).scalars().all()
    )
    findings_2 = (
        db.execute(select(Finding).where(Finding.service_id == service_2.id)).scalars().all()
    )
    findings_3 = (
        db.execute(select(Finding).where(Finding.service_id == service_3.id)).scalars().all()
    )

    assert len(findings_1) == 1
    assert findings_1[0].cve_id == "CVE-0001-0001"
    # Second CPE's lookup raised before any Finding was built for it.
    assert findings_2 == []
    # Third CPE was still processed normally, despite the second CPE's
    # failure -- this is the behavior that would FAIL against the
    # pre-fix code (which aborted everything after CPE #2).
    assert len(findings_3) == 1
    assert findings_3[0].cve_id == "CVE-0003-0001"


def test_per_cpe_cache_store_integrity_error_skips_only_that_cpe(
    db: Session, redis_client: redis.Redis
) -> None:
    """Same behavioral guarantee as the test above, but triggered via
    `cache.store` raising (simulating the concurrent-insert race: two
    scans miss the cache for the same CPE at once, both fetch from NVD,
    and a second `store()` call raced ahead -- see finding 3's report
    section for the full race description) rather than
    `fetch_cves_for_cpe` raising directly. Three distinct CPEs; the
    SECOND one's `cache.store` call raises `IntegrityError`. The FIRST
    CPE's findings must still be committed, and the THIRD CPE must still
    be looked up and get its own Finding rows -- not skipped just
    because the second one blew up.
    """
    service_1 = _make_service(db, evidence={"cpe": ["cpe:/a:vendor1:product1:1.0"]}, port=81)
    service_2 = _make_service(db, evidence={"cpe": ["cpe:/a:vendor2:product2:1.0"]}, port=82)
    service_3 = _make_service(db, evidence={"cpe": ["cpe:/a:vendor3:product3:1.0"]}, port=83)

    # The real `cache.store` is used for calls 1 and 3 (so the Finding
    # rows built from `cves` behave exactly as in real operation); only
    # the SECOND call is swapped out to raise, simulating the concurrent-
    # insert race landing as an IntegrityError on that one CPE's upsert.
    real_store = cache.store
    call_count = 0

    def _store_second_call_raises(*args: object, **kwargs: object) -> object:
        nonlocal call_count
        call_count += 1
        if call_count == 2:
            raise IntegrityError("duplicate key value violates unique constraint", None, None)
        return real_store(*args, **kwargs)  # type: ignore[arg-type]

    with (
        patch.object(
            nvd_client,
            "fetch_cves_for_cpe",
            side_effect=[
                _fetch_result("CVE-0001-0001"),
                _fetch_result("CVE-0002-0001"),
                _fetch_result("CVE-0003-0001"),
            ],
        ) as mock_fetch,
        patch.object(cache, "store", side_effect=_store_second_call_raises),
    ):
        correlate_services(db, redis_client, [service_1, service_2, service_3])

    assert mock_fetch.call_count == 3  # all three CPEs attempted

    findings_1 = (
        db.execute(select(Finding).where(Finding.service_id == service_1.id)).scalars().all()
    )
    findings_2 = (
        db.execute(select(Finding).where(Finding.service_id == service_2.id)).scalars().all()
    )
    findings_3 = (
        db.execute(select(Finding).where(Finding.service_id == service_3.id)).scalars().all()
    )

    assert len(findings_1) == 1
    assert findings_1[0].cve_id == "CVE-0001-0001"
    # Second CPE's cache.store raised -- no Finding rows for it (the
    # whole per-CPE block, including the Finding build, is rolled back).
    assert findings_2 == []
    # Third CPE still processed normally.
    assert len(findings_3) == 1
    assert findings_3[0].cve_id == "CVE-0003-0001"
