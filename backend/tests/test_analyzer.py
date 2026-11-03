"""Unit-level tests for `analyze_services` (Task 4, PLAN_6.md section 4).

Mirrors `test_correlator.py`'s own style: a thin `_make_service` helper
builds a persisted Service (with its required Asset/Target/Scan/Project
ancestry), and per-unit isolation claims are PROVEN by making one
service's check call actually raise, not just asserted against a
malformed-but-already-defensively-handled input shape.

`tls_inspector.inspect_tls`/`check_tls_result` are exercised through
`analyzer.inspect_tls` (the name `analyzer.py` imports into its own
module namespace), so patches target `analyzer.inspect_tls`/
`analyzer.check_tls_result` etc. -- the same "patch where it's used"
convention `test_correlator.py` already follows for
`nvd_client.fetch_cves_for_cpe`.
"""

from __future__ import annotations

from unittest.mock import patch

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.misconfiguration import Misconfiguration
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.service import Service
from app.models.target import Target, TargetType
from app.modules.misconfiguration import analyzer
from app.modules.misconfiguration.checks import MisconfigCandidate


def _make_service(
    db: Session,
    evidence: dict | None = None,
    port: int = 80,
    service_name: str | None = None,
) -> Service:
    """Build and persist one Service row (with its required Asset/Target/
    Scan/Project ancestry) mirroring the shape `run_scan_task` itself
    produces.
    """
    project = Project(name="Analyzer Test Project")
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

    scan = Scan(project_id=project.id, target_id=target.id, status=ScanStatus.ANALYZING)
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
        service_name=service_name,
        evidence=evidence,
    )
    db.add(service)
    db.commit()
    db.refresh(service)
    return service


def _misconfigs_for(db: Session, service: Service) -> list[Misconfiguration]:
    return (
        db.execute(select(Misconfiguration).where(Misconfiguration.service_id == service.id))
        .scalars()
        .all()
    )


# ---------------------------------------------------------------------------
# Per-service isolation: one service's check call raising must not abort
# analysis of the rest of the scan's services (correlator.py's own
# per-CPE isolation claim, mirrored here per-service).
# ---------------------------------------------------------------------------


def test_per_service_isolation_one_failure_does_not_abort_the_rest(db: Session) -> None:
    """Two services both eligible for header checks; `check_headers` is
    made to raise for ONLY the second service (simulating a check
    blowing up on some unanticipated input shape). The first service's
    misconfigurations must still be persisted and committed, proving
    per-service isolation rather than merely asserting it.
    """
    service_a = _make_service(db, evidence={"headers": {}, "scheme": "http"}, port=8080)
    service_b = _make_service(db, evidence={"headers": {}, "scheme": "http"}, port=8081)

    real_check_headers = analyzer.check_headers

    def _raise_for_b(service: Service) -> list[MisconfigCandidate]:
        if service.id == service_b.id:
            raise RuntimeError("boom: malformed evidence for service B")
        return real_check_headers(service)

    # inspect_tls mocked to {} here: neither service's port is a TLS
    # candidate, and this test is about header-check isolation, not TLS --
    # mocking keeps it from depending on a real (if fast) socket round
    # trip against 443/4443/8443 on every run.
    with (
        patch.object(analyzer, "check_headers", side_effect=_raise_for_b),
        patch.object(analyzer, "inspect_tls", return_value={}),
    ):
        analyzer.analyze_services(db, [service_a, service_b], target_host="127.0.0.1")

    rows_a = _misconfigs_for(db, service_a)
    rows_b = _misconfigs_for(db, service_b)

    # Service A's candidates (missing-csp, missing-x-frame-options, etc.)
    # were committed normally.
    assert len(rows_a) > 0
    # Service B's check raised -- its own try/except rolled back and moved
    # on; no rows for it, but the failure never propagated past
    # analyze_services (no exception raised out of this test either).
    assert rows_b == []


def test_per_service_isolation_db_commit_failure_skips_only_that_service(
    db: Session,
) -> None:
    """Same isolation guarantee, triggered via a DB-level failure (the
    per-service commit itself raising) rather than a check function
    raising -- mirrors `test_correlator.py`'s
    `test_per_cpe_cache_store_integrity_error_skips_only_that_cpe`.
    """
    service_a = _make_service(db, port=21)  # FTP -> exposed-sensitive-service
    service_b = _make_service(db, port=23)  # Telnet -> exposed-sensitive-service

    real_commit = db.commit
    call_count = 0

    def _commit_second_call_raises() -> None:
        nonlocal call_count
        call_count += 1
        if call_count == 2:
            raise RuntimeError("boom: simulated commit failure")
        real_commit()

    with (
        patch.object(db, "commit", side_effect=_commit_second_call_raises),
        patch.object(analyzer, "inspect_tls", return_value={}),
    ):
        analyzer.analyze_services(db, [service_a, service_b], target_host="127.0.0.1")

    rows_a = _misconfigs_for(db, service_a)
    rows_b = _misconfigs_for(db, service_b)

    assert len(rows_a) == 1
    assert rows_a[0].check_id == "exposed-sensitive-service"
    # Service B's commit raised; rolled back, no row persisted for it.
    assert rows_b == []


# ---------------------------------------------------------------------------
# uq_misconfig_service_check: the analyzer must never attempt a duplicate
# check_id for one service, even across check families in one run.
# ---------------------------------------------------------------------------


def test_duplicate_check_id_across_families_is_deduped_not_double_persisted(
    db: Session,
) -> None:
    """Simulates a hypothetical bug where a second check family (header
    checks, here) emits the SAME check_id as `check_exposed_service`
    already produced for this service. The analyzer must persist exactly
    ONE Misconfiguration row for that check_id -- never attempt a second
    insert that would violate `uq_misconfig_service_check` -- and must
    not let that collision abort the rest of this service's candidates.
    """
    service = _make_service(
        db, evidence={"headers": {}, "scheme": "http"}, port=6379
    )  # Redis -> exposed-sensitive-service

    colliding_candidate = MisconfigCandidate(
        check_id="exposed-sensitive-service",
        title="Colliding candidate from a different check family",
        severity="LOW",
        description="Simulated collision to prove dedup, not a real header check result.",
        evidence={"simulated": True},
    )

    real_check_headers = analyzer.check_headers

    def _inject_collision(service: Service) -> list[MisconfigCandidate]:
        return [colliding_candidate, *real_check_headers(service)]

    with (
        patch.object(analyzer, "check_headers", side_effect=_inject_collision),
        patch.object(analyzer, "inspect_tls", return_value={}),
    ):
        analyzer.analyze_services(db, [service], target_host="127.0.0.1")

    rows = _misconfigs_for(db, service)
    exposed_rows = [r for r in rows if r.check_id == "exposed-sensitive-service"]

    # Exactly one row for the colliding check_id -- the real
    # check_exposed_service candidate won (it's processed first), the
    # injected duplicate was skipped, and no IntegrityError aborted the
    # rest of this service's candidates (missing-csp etc. still persist).
    assert len(exposed_rows) == 1
    assert exposed_rows[0].title == "Exposed Redis service"
    assert any(r.check_id == "missing-csp" for r in rows)


def test_no_duplicate_check_ids_ever_persisted_for_one_service(db: Session) -> None:
    """Defensive invariant check across a realistic multi-family run: for
    any service, however many candidates end up persisted, `check_id`
    values are always unique for that service (matching
    `uq_misconfig_service_check`).
    """
    service = _make_service(
        db, evidence={"headers": {}, "scheme": "https"}, port=21
    )  # FTP -> exposed-sensitive-service, plus header checks (https, no headers)

    with patch.object(analyzer, "inspect_tls", return_value={}):
        analyzer.analyze_services(db, [service], target_host="127.0.0.1")

    rows = _misconfigs_for(db, service)
    check_ids = [r.check_id for r in rows]
    assert len(check_ids) == len(set(check_ids))
    assert len(rows) > 0


# ---------------------------------------------------------------------------
# Check-family wiring: each family runs under the right condition, and
# TLS inspection happens exactly once per scan, not once per service.
# ---------------------------------------------------------------------------


def test_exposed_service_check_runs_unconditionally(db: Session) -> None:
    service = _make_service(db, evidence=None, port=6379)  # Redis, no evidence at all

    with patch.object(analyzer, "inspect_tls", return_value={}):
        analyzer.analyze_services(db, [service], target_host="127.0.0.1")

    rows = _misconfigs_for(db, service)
    assert len(rows) == 1
    assert rows[0].check_id == "exposed-sensitive-service"


def test_header_check_skipped_when_evidence_has_no_headers_key(db: Session) -> None:
    """A port not in SENSITIVE_PORTS, with evidence lacking a "headers"
    key (e.g. an nmap `-sV` CPE-only evidence shape) -- zero candidates,
    zero rows, no error.
    """
    service = _make_service(db, evidence={"cpe": ["cpe:/a:nginx:nginx:1.24.0"]}, port=9999)

    with patch.object(analyzer, "inspect_tls", return_value={}):
        analyzer.analyze_services(db, [service], target_host="127.0.0.1")

    assert _misconfigs_for(db, service) == []


def test_tls_check_runs_once_per_scan_not_once_per_service(db: Session) -> None:
    """Two services both on TLS candidate ports (one via
    TLS_CANDIDATE_PORTS directly, one via the service_name heuristic on a
    non-standard port) must still result in exactly ONE `inspect_tls`
    call for the whole scan.
    """
    service_443 = _make_service(db, evidence=None, port=443)
    service_ssl_named = _make_service(db, evidence=None, port=9443, service_name="ssl/https-alt")

    with patch.object(analyzer, "inspect_tls", return_value={}) as mock_inspect:
        analyzer.analyze_services(db, [service_443, service_ssl_named], target_host="127.0.0.1")

    mock_inspect.assert_called_once()
    called_host, called_ports = mock_inspect.call_args.args
    assert called_host == "127.0.0.1"
    assert set(called_ports) == {443, 4443, 8443, 9443}


def test_tls_check_applied_when_inspect_tls_returns_a_result_for_that_port(
    db: Session,
) -> None:
    from app.modules.misconfiguration.tls_inspector import TlsInspectionResult

    service = _make_service(db, evidence=None, port=443)
    fake_result = TlsInspectionResult(
        port=443,
        protocol_version="TLSv1.3",
        subject="CN=self",
        issuer="CN=self",
        not_valid_before=None,
        not_valid_after=None,
        is_self_signed=True,
    )

    with patch.object(analyzer, "inspect_tls", return_value={443: fake_result}):
        analyzer.analyze_services(db, [service], target_host="127.0.0.1")

    rows = _misconfigs_for(db, service)
    assert any(r.check_id == "self-signed-cert" for r in rows)


def test_candidate_tls_port_with_no_inspection_result_produces_no_tls_candidates(
    db: Session,
) -> None:
    """A candidate TLS port that `inspect_tls` found nothing listening on
    (refused/non-TLS/timeout) contributes zero TLS candidates -- not an
    error, and other check families for that same service are unaffected.
    """
    service = _make_service(db, evidence={"headers": {}, "scheme": "http"}, port=443)

    with patch.object(analyzer, "inspect_tls", return_value={}):
        analyzer.analyze_services(db, [service], target_host="127.0.0.1")

    rows = _misconfigs_for(db, service)
    tls_check_ids = {"self-signed-cert", "expired-cert", "expiring-soon-cert", "weak-tls-protocol"}
    assert not any(r.check_id in tls_check_ids for r in rows)
    # Header checks for this same service still ran normally.
    assert any(r.check_id == "missing-csp" for r in rows)


def test_no_candidates_for_any_service_calls_db_commit_zero_times_for_that_service(
    db: Session,
) -> None:
    """A service that triggers nothing from any check family results in
    no Misconfiguration rows and no wasted commit.
    """
    service = _make_service(db, evidence=None, port=9999)

    with (
        patch.object(db, "commit", wraps=db.commit) as mock_commit,
        patch.object(analyzer, "inspect_tls", return_value={}),
    ):
        analyzer.analyze_services(db, [service], target_host="127.0.0.1")

    mock_commit.assert_not_called()
    assert _misconfigs_for(db, service) == []
