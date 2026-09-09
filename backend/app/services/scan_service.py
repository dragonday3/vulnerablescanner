import uuid

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError, ScanStateError, ValidationConflictError
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.target import Target
from app.schemas.scan import ScanCreate

CANCELLABLE_STATUSES = {ScanStatus.CREATED, ScanStatus.QUEUED}


def create_scan(db: Session, data: ScanCreate) -> Scan:
    project = db.get(Project, data.project_id)
    if project is None:
        raise NotFoundError(f"Project {data.project_id} not found")

    target = db.get(Target, data.target_id)
    if target is None or target.project_id != data.project_id:
        raise NotFoundError(f"Target {data.target_id} not found for project {data.project_id}")

    # Defense-in-depth: re-verify authorization at scan-creation time, even
    # though Target creation already enforces this via its own validator.
    if target.authorization_confirmed is not True:
        raise ValidationConflictError("Target is not confirmed as authorized")

    scan = Scan(
        project_id=data.project_id,
        target_id=data.target_id,
        config=data.config,
        status=ScanStatus.CREATED,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def list_scans(db: Session, project_id: uuid.UUID | None = None) -> list[Scan]:
    query = db.query(Scan)
    if project_id is not None:
        query = query.filter(Scan.project_id == project_id)
    return query.order_by(Scan.created_at).all()


def get_scan(db: Session, scan_id: uuid.UUID) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise NotFoundError(f"Scan {scan_id} not found")
    return scan


def cancel_scan(db: Session, scan_id: uuid.UUID) -> Scan:
    scan = get_scan(db, scan_id)
    if scan.status not in CANCELLABLE_STATUSES:
        raise ScanStateError(f"Scan cannot be cancelled from status '{scan.status.value}'")
    scan.status = ScanStatus.CANCELLED
    db.commit()
    db.refresh(scan)
    return scan
