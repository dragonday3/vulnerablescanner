"""Tests for `run_scan_task`, the Celery orchestration task.

Called directly here (the underlying function, never `.delay()`) against a
**mocked** scanner adapter — no real network activity in this file. Tasks 3
and 4 already cover real-scanner correctness against a local listener /
the real `nmap` binary.

`run_scan_task` opens its own `SessionLocal()` per Global Constraint 9
(Celery tasks never share a FastAPI request-scoped session). To keep that
real behavior while still running against the `conftest.py` savepoint-based
test transaction, `use_test_session` below monkeypatches
`app.workers.tasks.SessionLocal` to hand the task the test's own `db`
fixture session, and no-ops that session's `close()` so the task's
`finally: db.close()` doesn't tear down the session the test still needs
for its own assertions afterward — the outer transaction rollback in
`conftest.py`'s `db` fixture still does the real cleanup.
"""

import uuid
from unittest.mock import patch

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.service import Service
from app.models.target import Target, TargetType
from app.modules.discovery.common_ports import PORT_NAMES
from app.modules.discovery.interfaces import PortScanResult
from app.modules.discovery.native_scanner import NativePortScanner
from app.modules.discovery.nmap_scanner import NmapPortScanner
from app.modules.fingerprinting.http_prober import HttpProbeResult
from app.workers import tasks as tasks_module


@pytest.fixture()
def use_test_session(monkeypatch: pytest.MonkeyPatch, db: Session) -> None:
    monkeypatch.setattr(tasks_module, "SessionLocal", lambda: db)
    monkeypatch.setattr(db, "close", lambda: None)


def _make_scan(
    db: Session,
    target_type: TargetType = TargetType.IP,
    value: str = "127.0.0.1",
    config: dict | None = None,
    status: ScanStatus = ScanStatus.CREATED,
) -> Scan:
    project = Project(name="Orchestration Test Project")
    db.add(project)
    db.flush()

    target = Target(
        project_id=project.id,
        value=value,
        target_type=target_type,
        authorization_confirmed=True,
    )
    db.add(target)
    db.flush()

    scan = Scan(
        project_id=project.id,
        target_id=target.id,
        status=status,
        config=config or {},
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def test_happy_path_completes_and_persists_asset_and_service(
    db: Session, use_test_session: None
) -> None:
    scan = _make_scan(db, value="127.0.0.1")
    fake_results = [PortScanResult(port=80, protocol="tcp", state="open")]

    with patch.object(NativePortScanner, "scan", return_value=fake_results) as mock_scan:
        tasks_module.run_scan_task(str(scan.id))

    mock_scan.assert_called_once()

    db.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.started_at is not None
    assert scan.completed_at is not None
    assert scan.error_message is None

    asset = db.execute(select(Asset).where(Asset.scan_id == scan.id)).scalar_one()
    assert asset.project_id == scan.project_id
    assert asset.target_id == scan.target_id
    assert asset.host == "127.0.0.1"

    services = db.execute(select(Service).where(Service.asset_id == asset.id)).scalars().all()
    assert len(services) == 1
    assert services[0].port == 80
    assert services[0].protocol == "tcp"
    assert services[0].state == "open"
    assert services[0].service_name == PORT_NAMES.get(80)


def test_cidr_target_fails_fast_without_attempting_a_scan(
    db: Session, use_test_session: None
) -> None:
    scan = _make_scan(db, target_type=TargetType.CIDR, value="10.0.0.0/24")

    with patch.object(NativePortScanner, "scan") as mock_scan:
        tasks_module.run_scan_task(str(scan.id))

    mock_scan.assert_not_called()

    db.refresh(scan)
    assert scan.status == ScanStatus.FAILED
    assert scan.error_message == "CIDR range scanning is not yet supported"
    assert scan.completed_at is not None

    assert db.execute(select(Asset).where(Asset.scan_id == scan.id)).first() is None


def test_scanner_exception_fails_scan_with_exception_message(
    db: Session, use_test_session: None
) -> None:
    scan = _make_scan(db, value="127.0.0.1")

    with patch.object(
        NativePortScanner, "scan", side_effect=RuntimeError("boom: connection reset")
    ):
        tasks_module.run_scan_task(str(scan.id))

    db.refresh(scan)
    assert scan.status == ScanStatus.FAILED
    assert scan.error_message is not None
    assert "boom: connection reset" in scan.error_message
    assert scan.completed_at is not None

    assert db.execute(select(Asset).where(Asset.scan_id == scan.id)).first() is None


def test_persistence_failure_rolls_back_and_reaches_failed(
    db: Session, use_test_session: None
) -> None:
    """A DB-level failure during the Asset/Service persistence commit must
    still land the scan at FAILED with a populated error_message, not
    propagate as an unhandled error that leaves the scan stuck at
    DISCOVERY forever. Guards against a real bug: the except block's own
    commit previously failed with PendingRollbackError because the prior
    failed flush left the session's transaction invalidated, and nothing
    called db.rollback() first.

    Forces a genuine DB-level failure (not a mocked one) by returning a
    port number that overflows Postgres's 4-byte `integer` column
    (`services.port`), so the failure happens inside SQLAlchemy's real
    flush/commit machinery, exactly where the bug manifested.
    """
    scan = _make_scan(db, value="127.0.0.1")
    # 2**31 is one past the max value a 4-byte Postgres `integer` can hold.
    out_of_range_results = [PortScanResult(port=2**31, protocol="tcp", state="open")]

    with patch.object(NativePortScanner, "scan", return_value=out_of_range_results):
        tasks_module.run_scan_task(str(scan.id))

    db.refresh(scan)
    assert scan.status == ScanStatus.FAILED
    assert scan.error_message  # non-empty; exact driver wording not asserted
    assert scan.completed_at is not None

    assert db.execute(select(Asset).where(Asset.scan_id == scan.id)).first() is None


def test_unknown_scanner_config_fails_scan_without_crashing(
    db: Session, use_test_session: None
) -> None:
    scan = _make_scan(db, value="127.0.0.1", config={"scanner": "masscan"})

    with patch.object(NativePortScanner, "scan") as mock_scan:
        tasks_module.run_scan_task(str(scan.id))

    mock_scan.assert_not_called()

    db.refresh(scan)
    assert scan.status == ScanStatus.FAILED
    assert scan.error_message == "Unknown scanner 'masscan'"
    assert scan.completed_at is not None


def test_already_cancelled_scan_returns_without_further_changes(
    db: Session, use_test_session: None
) -> None:
    scan = _make_scan(db, value="127.0.0.1", status=ScanStatus.CANCELLED)

    with patch.object(NativePortScanner, "scan") as mock_scan:
        tasks_module.run_scan_task(str(scan.id))

    mock_scan.assert_not_called()

    db.refresh(scan)
    assert scan.status == ScanStatus.CANCELLED
    assert scan.started_at is None
    assert scan.completed_at is None
    assert scan.error_message is None


def test_missing_scan_returns_without_error(db: Session, use_test_session: None) -> None:
    # No DB row for this id at all — must not raise.
    tasks_module.run_scan_task(str(uuid.uuid4()))


def test_authorization_revoked_after_queueing_fails_scan_without_scanning(
    db: Session, use_test_session: None
) -> None:
    """Finding 6: `create_scan` only checks `target.authorization_confirmed`
    at scan-creation time. The worker runs later, in its own transaction,
    and is the process that actually emits network traffic - it must
    re-check authorization itself rather than trusting a check that may be
    stale by the time it runs.

    Simulated the same way `test_scans.py`'s
    `test_create_scan_rejected_for_target_with_authorization_revoked` does:
    flip the DB column directly (bypassing the API/validator, which can't
    catch this after the fact) between scan creation and task execution.
    """
    scan = _make_scan(db, value="127.0.0.1")
    scan.target.authorization_confirmed = False
    db.commit()

    with patch.object(NativePortScanner, "scan") as mock_scan:
        tasks_module.run_scan_task(str(scan.id))

    mock_scan.assert_not_called()

    db.refresh(scan)
    assert scan.status == ScanStatus.FAILED
    assert scan.error_message == "Target authorization is not confirmed"
    assert scan.completed_at is not None

    assert db.execute(select(Asset).where(Asset.scan_id == scan.id)).first() is None


# --- Phase 3: FINGERPRINTING transition + evidence persistence + native HTTP enrichment ---


def test_nmap_path_persists_evidence_fields(
    db: Session, use_test_session: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """nmap's own `-sV` evidence (product/version/extrainfo/raw_evidence)
    must land on the persisted Service row with fingerprint_source="nmap-sv",
    and nmap's own service-name guess must win over the PORT_NAMES fallback
    when nmap supplies one (the Phase 3 precedence flip) - while a result
    with no service_name guess still falls back to PORT_NAMES as before.

    Uses port 3389 (RDP) for the precedence-flip case rather than 443:
    nmap's own static-table guess for 3389 is "ms-wbt-server"
    (verified against `PORT_NAMES[3389] == "rdp"` in
    app.modules.discovery.common_ports), a genuine mismatch with this
    project's PORT_NAMES fallback. Port 443's PORT_NAMES entry is also
    "https" - identical to nmap's own guess - so a test built around port
    443 would still pass even if the precedence flip were accidentally
    reversed back to "PORT_NAMES wins"; this makes the assertion meaningful.

    Also asserts (Global Constraint 4: HTTP probing is native-adapter-only)
    that `probe_services` is never called for an nmap-adapter scan. This
    result set deliberately includes port 80 - which IS in WEB_PORTS -
    specifically so `mock_probe.assert_not_called()` below is a genuine
    check of the `scanner_name == "native"` guard: without a WEB_PORTS
    port present, the guard could regress (e.g. lose the `scanner_name ==
    "native"` check entirely) and this assertion would still trivially
    pass, since there'd be no web port for a broken guard to react to.
    """
    assert PORT_NAMES.get(3389) == "rdp"  # sanity-check the chosen mismatch is real

    scan = _make_scan(db, value="127.0.0.1", config={"scanner": "nmap"})
    fake_results = [
        PortScanResult(
            port=3389,
            protocol="tcp",
            state="open",
            service_name="ms-wbt-server",
            product="Microsoft Terminal Services",
            version="1.24.0",
            extrainfo="Ubuntu",
            method="probed",
            cpe=("cpe:/a:nginx:nginx:1.24.0",),
            raw_evidence={"name": "ms-wbt-server", "product": "nginx", "version": "1.24.0"},
        ),
        # No service_name guess from nmap for this one -> falls back to
        # PORT_NAMES, exactly like the pre-Phase-3 behavior.
        PortScanResult(port=22, protocol="tcp", state="open"),
        # In WEB_PORTS - see the docstring above for why this port's
        # presence is what makes assert_not_called() below meaningful.
        PortScanResult(port=80, protocol="tcp", state="open", service_name="http"),
    ]

    with (
        patch.object(NmapPortScanner, "scan", return_value=fake_results) as mock_scan,
        patch.object(tasks_module, "probe_services") as mock_probe,
    ):
        tasks_module.run_scan_task(str(scan.id))

    mock_scan.assert_called_once()
    mock_probe.assert_not_called()

    db.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.error_message is None

    asset = db.execute(select(Asset).where(Asset.scan_id == scan.id)).scalar_one()
    services = {
        s.port: s for s in db.execute(select(Service).where(Service.asset_id == asset.id)).scalars()
    }

    rdp_service = services[3389]
    # This is the precedence-flip assertion: nmap's own guess
    # ("ms-wbt-server") must win over PORT_NAMES[3389] ("rdp").
    assert rdp_service.service_name == "ms-wbt-server"
    assert rdp_service.service_name != PORT_NAMES.get(3389)
    assert rdp_service.product == "Microsoft Terminal Services"
    assert rdp_service.version == "1.24.0"
    assert rdp_service.extrainfo == "Ubuntu"
    assert rdp_service.fingerprint_source == "nmap-sv"
    assert rdp_service.evidence == {
        "name": "ms-wbt-server",
        "product": "nginx",
        "version": "1.24.0",
    }

    ssh_service = services[22]
    assert ssh_service.service_name == PORT_NAMES.get(22)
    assert ssh_service.product is None
    assert ssh_service.fingerprint_source == "nmap-sv"
    assert ssh_service.evidence is None


def test_native_http_enrichment_updates_only_matching_web_port_service(
    db: Session, use_test_session: None
) -> None:
    """Native-adapter scans get a second HTTP enrichment pass; only the
    Service row whose port both (a) is in WEB_PORTS and (b) got a probe
    result back should be updated - other discovered ports must be left
    with fingerprint_source=None.
    """
    scan = _make_scan(db, value="127.0.0.1")
    fake_results = [
        PortScanResult(port=22, protocol="tcp", state="open"),
        PortScanResult(port=80, protocol="tcp", state="open"),
        PortScanResult(port=3306, protocol="tcp", state="open"),
    ]
    probe_result = HttpProbeResult(
        port=80,
        scheme="http",
        status_code=200,
        server_header="nginx/1.24.0",
        product="nginx",
        version="1.24.0",
        extrainfo=None,
        title="Welcome",
        headers={"server": "nginx/1.24.0"},
    )

    with (
        patch.object(NativePortScanner, "scan", return_value=fake_results),
        patch.object(tasks_module, "probe_services", return_value={80: probe_result}) as mock_probe,
    ):
        tasks_module.run_scan_task(str(scan.id))

    mock_probe.assert_called_once_with("127.0.0.1", [80])

    db.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.error_message is None

    asset = db.execute(select(Asset).where(Asset.scan_id == scan.id)).scalar_one()
    services = {
        s.port: s for s in db.execute(select(Service).where(Service.asset_id == asset.id)).scalars()
    }

    assert services[80].fingerprint_source == "http"
    assert services[80].product == "nginx"
    assert services[80].version == "1.24.0"
    assert services[80].evidence == {
        "scheme": "http",
        "status_code": 200,
        "server": "nginx/1.24.0",
        "title": "Welcome",
        "headers": {"server": "nginx/1.24.0"},
    }

    assert services[22].fingerprint_source is None
    assert services[22].product is None
    assert services[3306].fingerprint_source is None
    assert services[3306].product is None


def test_native_http_enrichment_clamps_oversized_server_header_fields(
    db: Session, use_test_session: None
) -> None:
    """Final-review finding #2: an over-length `Server` header (remote,
    attacker-influenced input) must not raise a Postgres
    StringDataRightTruncation error, and must not silently discard the
    entire HTTP enrichment pass for every port (the fingerprinting
    try/except rolls back and swallows ANY exception by design). The
    `tasks._clamp` helper truncates `product`/`version` at the write site
    to comfortably fit `Service.product` (String(255)) and
    `Service.version` (String(100)). Crucially, the FULL, unclamped header
    string must still be preserved verbatim in `evidence` - only the
    structured convenience columns are clamped, per the "raw evidence
    preserved verbatim" constraint.
    """
    scan = _make_scan(db, value="127.0.0.1")
    fake_results = [PortScanResult(port=80, protocol="tcp", state="open")]

    oversized_product = "X" * 1000  # far past Service.product's String(255)
    oversized_version = "9" * 500  # far past Service.version's String(100)
    server_header = f"{oversized_product}/{oversized_version}"
    probe_result = HttpProbeResult(
        port=80,
        scheme="http",
        status_code=200,
        server_header=server_header,
        product=oversized_product,
        version=oversized_version,
        extrainfo=None,
        title=None,
        headers={"server": server_header},
    )

    with (
        patch.object(NativePortScanner, "scan", return_value=fake_results),
        patch.object(tasks_module, "probe_services", return_value={80: probe_result}),
    ):
        tasks_module.run_scan_task(str(scan.id))

    db.refresh(scan)
    # The core contract: an oversized value must not fail the scan nor
    # silently discard the whole enrichment pass - it still completes with
    # fingerprint_source="http" for the affected port.
    assert scan.status == ScanStatus.COMPLETED
    assert scan.error_message is None

    asset = db.execute(select(Asset).where(Asset.scan_id == scan.id)).scalar_one()
    service = db.execute(select(Service).where(Service.asset_id == asset.id)).scalar_one()

    assert service.fingerprint_source == "http"
    assert service.product == oversized_product[: tasks_module.MAX_PRODUCT_LENGTH]
    assert len(service.product) == tasks_module.MAX_PRODUCT_LENGTH
    assert service.version == oversized_version[: tasks_module.MAX_VERSION_LENGTH]
    assert len(service.version) == tasks_module.MAX_VERSION_LENGTH
    # The FULL, unclamped header is preserved verbatim in evidence (JSONB,
    # no length limit) - only product/version above were clamped.
    assert service.evidence is not None
    assert service.evidence["server"] == server_header
    assert len(service.evidence["server"]) == len(server_header)


def test_nmap_path_clamps_oversized_service_fields(db: Session, use_test_session: None) -> None:
    """Final-review finding #2, nmap path: an over-length nmap
    service_name/product/version (nmap's own internal buffers make this
    unlikely in practice, but no explicit guard existed before this fix)
    must be clamped at the write site rather than raising a Postgres
    StringDataRightTruncation error on commit - which would otherwise fail
    the entire scan to FAILED instead of just clamping the offending
    fields.
    """
    scan = _make_scan(db, value="127.0.0.1", config={"scanner": "nmap"})
    oversized_name = "n" * 200  # far past service_name's String(50)
    oversized_product = "p" * 400  # far past product's String(255)
    oversized_version = "v" * 300  # far past version's String(100)
    fake_results = [
        PortScanResult(
            port=8080,
            protocol="tcp",
            state="open",
            service_name=oversized_name,
            product=oversized_product,
            version=oversized_version,
        ),
    ]

    with patch.object(NmapPortScanner, "scan", return_value=fake_results):
        tasks_module.run_scan_task(str(scan.id))

    db.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.error_message is None

    asset = db.execute(select(Asset).where(Asset.scan_id == scan.id)).scalar_one()
    service = db.execute(select(Service).where(Service.asset_id == asset.id)).scalar_one()

    assert service.service_name == oversized_name[: tasks_module.MAX_SERVICE_NAME_LENGTH]
    assert len(service.service_name) == tasks_module.MAX_SERVICE_NAME_LENGTH
    assert service.product == oversized_product[: tasks_module.MAX_PRODUCT_LENGTH]
    assert len(service.product) == tasks_module.MAX_PRODUCT_LENGTH
    assert service.version == oversized_version[: tasks_module.MAX_VERSION_LENGTH]
    assert len(service.version) == tasks_module.MAX_VERSION_LENGTH


def test_native_http_enrichment_failure_does_not_fail_scan(
    db: Session, use_test_session: None
) -> None:
    """The single most important contract in this task: fingerprinting is
    best-effort enrichment and must never be able to fail the scan. A
    `probe_services` exception must be caught, logged, and rolled back -
    the scan still reaches COMPLETED with error_message still None, and
    the affected Service row's fingerprint fields stay unset.
    """
    scan = _make_scan(db, value="127.0.0.1")
    fake_results = [PortScanResult(port=80, protocol="tcp", state="open")]

    with (
        patch.object(NativePortScanner, "scan", return_value=fake_results),
        patch.object(
            tasks_module, "probe_services", side_effect=RuntimeError("probe boom")
        ) as mock_probe,
    ):
        tasks_module.run_scan_task(str(scan.id))

    mock_probe.assert_called_once()

    db.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.completed_at is not None
    assert scan.error_message is None

    asset = db.execute(select(Asset).where(Asset.scan_id == scan.id)).scalar_one()
    service = db.execute(select(Service).where(Service.asset_id == asset.id)).scalar_one()
    assert service.fingerprint_source is None
    assert service.product is None
    assert service.evidence is None


def test_native_http_enrichment_skipped_when_no_discovered_ports_are_web_ports(
    db: Session, use_test_session: None
) -> None:
    """`probe_services` must never be called at all when none of the
    discovered open ports are in WEB_PORTS - no wasted work.
    """
    scan = _make_scan(db, value="127.0.0.1")
    fake_results = [PortScanResult(port=22, protocol="tcp", state="open")]

    with (
        patch.object(NativePortScanner, "scan", return_value=fake_results),
        patch.object(tasks_module, "probe_services") as mock_probe,
    ):
        tasks_module.run_scan_task(str(scan.id))

    mock_probe.assert_not_called()

    db.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED


def test_discovery_failure_does_not_fall_through_to_fingerprinting_or_completed(
    db: Session, use_test_session: None
) -> None:
    """Regression test for the explicit `return` added at the end of the
    discovery `except` block. Once the FINGERPRINTING/enrichment/COMPLETED
    code was added *after* that block instead of inside it, a
    discovery-stage failure's correctly-committed FAILED status would -
    without that `return` - fall straight through into the new code and
    get silently overwritten to FINGERPRINTING and then COMPLETED.

    Verified this is a genuine regression test (not a vacuous one) by
    temporarily deleting the `return` in app/workers/tasks.py and
    re-running this test: it fails with
    `assert <ScanStatus.COMPLETED: 'completed'> == <ScanStatus.FAILED: 'failed'>`
    (mock_probe.assert_not_called() also fails, since the fingerprinting
    block runs and calls probe_services). Restoring the `return` makes it
    pass again.
    """
    scan = _make_scan(db, value="127.0.0.1", config={"scanner": "masscan"})

    with (
        patch.object(NativePortScanner, "scan") as mock_scan,
        patch.object(tasks_module, "probe_services") as mock_probe,
    ):
        tasks_module.run_scan_task(str(scan.id))

    mock_scan.assert_not_called()
    mock_probe.assert_not_called()

    db.refresh(scan)
    assert scan.status == ScanStatus.FAILED
    assert scan.error_message == "Unknown scanner 'masscan'"
    assert scan.completed_at is not None


@pytest.mark.parametrize("scanner_name", ["native", "nmap"])
def test_fingerprinting_is_reached_as_an_intermediate_status(
    db: Session,
    use_test_session: None,
    monkeypatch: pytest.MonkeyPatch,
    scanner_name: str,
) -> None:
    """FINGERPRINTING must actually be set (and committed) as an
    intermediate state for both adapters, not skipped straight to
    COMPLETED - including nmap-adapter scans, whose evidence is already
    complete, since the state machine is deliberately adapter-agnostic.

    Spies on `db.commit` to record `scan.status` at the moment of each
    commit, since `run_scan_task` never returns the intermediate states -
    it only leaves the final one behind for a post-hoc `db.refresh`.
    """
    scan = _make_scan(db, value="127.0.0.1", config={"scanner": scanner_name})
    # Port 22 isn't in WEB_PORTS, so the native path's enrichment block is a
    # no-op here (irrelevant to what this test is checking).
    fake_results = [PortScanResult(port=22, protocol="tcp", state="open")]

    observed_statuses: list[ScanStatus] = []
    original_commit = db.commit

    def spy_commit() -> None:
        observed_statuses.append(scan.status)
        original_commit()

    monkeypatch.setattr(db, "commit", spy_commit)

    adapter_cls = NativePortScanner if scanner_name == "native" else NmapPortScanner
    with patch.object(adapter_cls, "scan", return_value=fake_results):
        tasks_module.run_scan_task(str(scan.id))

    assert ScanStatus.FINGERPRINTING in observed_statuses

    db.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
