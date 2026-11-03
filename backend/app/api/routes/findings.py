import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.finding import Finding
from app.schemas.finding import FindingRead, FindingValidationUpdate
from app.services import finding_service

router = APIRouter(prefix="/findings", tags=["findings"])


@router.patch("/{finding_id}", response_model=FindingRead)
def update_finding_validation(
    finding_id: uuid.UUID, data: FindingValidationUpdate, db: Session = Depends(get_db)
) -> Finding:
    return finding_service.update_validation(db, finding_id, data)
