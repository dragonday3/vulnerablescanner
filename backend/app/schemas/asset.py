import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.schemas.service import ServiceRead


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    target_id: uuid.UUID
    scan_id: uuid.UUID
    host: str
    created_at: datetime
    services: list[ServiceRead] = []
