import uuid

from fastapi import Depends
from sqlalchemy.orm import Session

from app.db.session import get_db  # re-export
from app.models.project import Project
from app.services import project_service


def get_project_or_404(project_id: uuid.UUID, db: Session = Depends(get_db)) -> Project:
    return project_service.get_project(db, project_id)
