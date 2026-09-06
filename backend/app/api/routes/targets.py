import uuid

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.target import Target
from app.schemas.target import TargetCreate, TargetRead
from app.services import target_service

router = APIRouter(prefix="/projects/{project_id}/targets", tags=["targets"])


@router.post("", response_model=TargetRead, status_code=status.HTTP_201_CREATED)
def create_target(
    project_id: uuid.UUID, data: TargetCreate, db: Session = Depends(get_db)
) -> Target:
    return target_service.create_target(db, project_id, data)


@router.get("", response_model=list[TargetRead])
def list_targets(project_id: uuid.UUID, db: Session = Depends(get_db)) -> list[Target]:
    return target_service.list_targets(db, project_id)


@router.get("/{target_id}", response_model=TargetRead)
def get_target(
    project_id: uuid.UUID, target_id: uuid.UUID, db: Session = Depends(get_db)
) -> Target:
    return target_service.get_target(db, project_id, target_id)
