import uuid

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.models.report import Report
from app.services.scan_service import get_scan


def get_report(db: Session, scan_id: uuid.UUID) -> Report:
    get_scan(db, scan_id)  # raises NotFoundError if the scan itself doesn't exist
    report = db.query(Report).filter(Report.scan_id == scan_id).first()
    if report is None:
        raise NotFoundError(f"Report for scan {scan_id} not found")
    return report
