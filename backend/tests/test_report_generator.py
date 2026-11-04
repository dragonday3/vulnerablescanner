"""Unit-level tests for `generate_report` (Phase 8, PLAN_8.md section 3/6).

Mirrors `test_risk_scorer.py`'s own style: a thin `_make_scan`/`_make_asset`
helper builds a persisted Scan (with its required Target/Project ancestry)
plus an Asset, and `generate_report`'s best-effort contract is proven by
forcing a real failure (a monkeypatched `build_report_summary` that raises,
and a genuine `scan_id` unique-index violation from calling it twice) rather
than just asserted against an already-defensively-handled input shape.
"""

from __future__ import annotations

from unittest.mock import patch

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.project import Project
from app.models.report import Report
from app.models.scan import Scan, ScanStatus
from app.models.target import Target, TargetType
from app.modules.reporting import report_generator
from app.modules.reporting.report_generator import generate_report


def _make_scan(db: Session) -> Scan:
    project = Project(name="Report Generator Test Project")
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

    scan = Scan(project_id=project.id, target_id=target.id, status=ScanStatus.REPORT_GENERATION)
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


def test_successful_call_persists_exactly_one_report_row(db: Session) -> None:
    scan = _make_scan(db)
    asset = _make_asset(db, scan)

    generate_report(db, scan, [asset])

    reports = db.execute(select(Report).where(Report.scan_id == scan.id)).scalars().all()
    assert len(reports) == 1
    report = reports[0]
    assert report.scan_id == scan.id
    assert report.summary["target"]["value"] == "127.0.0.1"
    assert report.summary["target"]["target_type"] == "ip"
    assert report.summary["assets"][0]["host"] == "127.0.0.1"


def test_build_failure_persists_no_report_row_and_does_not_raise(db: Session) -> None:
    scan = _make_scan(db)
    asset = _make_asset(db, scan)

    with patch.object(
        report_generator,
        "build_report_summary",
        side_effect=RuntimeError("boom: simulated report-build failure"),
    ) as mock_build:
        generate_report(db, scan, [asset])  # must not raise

    mock_build.assert_called_once()

    reports = db.execute(select(Report).where(Report.scan_id == scan.id)).scalars().all()
    assert reports == []


def test_second_call_for_same_scan_is_swallowed_and_leaves_first_report_untouched(
    db: Session,
) -> None:
    """The `scan_id` unique index is the real guard against a scan somehow
    getting two Report rows -- the second `generate_report` call's commit
    hits it at the DB level (a genuine IntegrityError, not a simulated
    failure), and `generate_report`'s own try/except must roll back and
    swallow it rather than raise, leaving the first Report row exactly as
    it was.
    """
    scan = _make_scan(db)
    asset = _make_asset(db, scan)

    generate_report(db, scan, [asset])
    first_report = db.execute(select(Report).where(Report.scan_id == scan.id)).scalar_one()
    first_generated_at = first_report.generated_at
    first_summary = first_report.summary

    generate_report(db, scan, [asset])  # must not raise

    reports = db.execute(select(Report).where(Report.scan_id == scan.id)).scalars().all()
    assert len(reports) == 1
    assert reports[0].id == first_report.id
    assert reports[0].generated_at == first_generated_at
    assert reports[0].summary == first_summary


def test_generate_report_never_mutates_scan_status(db: Session) -> None:
    scan = _make_scan(db)
    asset = _make_asset(db, scan)

    generate_report(db, scan, [asset])

    db.refresh(scan)
    assert scan.status == ScanStatus.REPORT_GENERATION
