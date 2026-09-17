import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ServiceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    port: int
    protocol: str
    state: str
    service_name: str | None
    product: str | None
    version: str | None
    extrainfo: str | None
    fingerprint_source: str | None
    evidence: dict | None
    created_at: datetime
