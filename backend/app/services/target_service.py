import uuid

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.models.target import Target
from app.schemas.target import TargetCreate
from app.services import project_service


def create_target(db: Session, project_id: uuid.UUID, data: TargetCreate) -> Target:
    project_service.get_project(db, project_id)  # raises NotFoundError if missing
    target = Target(project_id=project_id, **data.model_dump())
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


def list_targets(db: Session, project_id: uuid.UUID) -> list[Target]:
    project_service.get_project(db, project_id)  # raises NotFoundError if missing
    return (
        db.query(Target)
        .filter(Target.project_id == project_id)
        .order_by(Target.created_at)
        .all()
    )


def get_target(db: Session, project_id: uuid.UUID, target_id: uuid.UUID) -> Target:
    target = db.get(Target, target_id)
    if target is None or target.project_id != project_id:
        raise NotFoundError(
            f"Target {target_id} not found for project {project_id}"
        )
    return target
