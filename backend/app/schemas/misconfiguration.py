import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class MisconfigurationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    service_id: uuid.UUID
    check_id: str
    title: str
    severity: str
    description: str
    evidence: dict
    created_at: datetime
