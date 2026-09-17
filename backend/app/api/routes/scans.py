import uuid

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.asset import Asset
from app.models.scan import Scan
from app.schemas.asset import AssetRead
from app.schemas.scan import ScanCreate, ScanRead, ScanStatusRead
from app.services import scan_service

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
def create_scan(data: ScanCreate, db: Session = Depends(get_db)) -> Scan:
    return scan_service.create_scan(db, data)


@router.get("", response_model=list[ScanRead])
def list_scans(project_id: uuid.UUID | None = None, db: Session = Depends(get_db)) -> list[Scan]:
    return scan_service.list_scans(db, project_id)


@router.get("/{scan_id}", response_model=ScanRead)
def get_scan(scan_id: uuid.UUID, db: Session = Depends(get_db)) -> Scan:
    return scan_service.get_scan(db, scan_id)


@router.get("/{scan_id}/status", response_model=ScanStatusRead)
def get_scan_status(scan_id: uuid.UUID, db: Session = Depends(get_db)) -> Scan:
    return scan_service.get_scan(db, scan_id)


@router.post("/{scan_id}/cancel", response_model=ScanRead)
def cancel_scan(scan_id: uuid.UUID, db: Session = Depends(get_db)) -> Scan:
    return scan_service.cancel_scan(db, scan_id)


@router.get("/{scan_id}/assets", response_model=list[AssetRead])
def get_scan_assets(scan_id: uuid.UUID, db: Session = Depends(get_db)) -> list[Asset]:
    return scan_service.get_scan_assets(db, scan_id)
