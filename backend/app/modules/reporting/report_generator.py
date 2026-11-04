"""Report-persistence orchestration glue (Phase 8, PLAN_8.md section 3).

Wires the pure `build_report_summary` (report_builder.py, Phase 8 Task 2)
into a single persisted `Report` row per scan. Mirrors the per-unit
isolation discipline every prior best-effort orchestrator in this project
follows (`correlator.py`, `analyzer.py`, `risk_scorer.py`) -- but unlike
`risk_scorer.py`'s per-Asset loop, there is exactly one derived object
here (the report as a whole for the entire scan), so this is one
try/except around the full build+persist, not a loop with one try/except
per unit.

Never touches `scan.status` -- that is `tasks.py`'s job alone, same
inherited rule as `correlator.py`/`analyzer.py`/`risk_scorer.py`. Never
raises past `generate_report`.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.report import Report
from app.models.scan import Scan
from app.modules.reporting.report_builder import build_report_summary

logger = logging.getLogger(__name__)


def generate_report(db: Session, scan: Scan, assets: list[Asset]) -> None:
    """Best-effort: build and persist exactly one Report row for `scan`.

    Builds `build_report_summary(scan, assets)` and commits a single new
    `Report(scan_id=scan.id, summary=summary)`. On any failure -- including
    a `Report` row for this `scan_id` already existing, which violates the
    `scan_id` unique index at commit time -- rolls back and logs; never
    raises past this function, and never mutates `scan.status`.
    """
    try:
        summary = build_report_summary(scan, assets)
        report = Report(scan_id=scan.id, summary=summary)
        db.add(report)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("generate_report: report generation failed for scan %s", scan.id)
