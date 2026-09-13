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
