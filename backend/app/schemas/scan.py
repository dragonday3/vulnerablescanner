import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.scan import ScanStatus


class ScanCreate(BaseModel):
    project_id: uuid.UUID
    target_id: uuid.UUID
    config: dict = {}


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    target_id: uuid.UUID
    status: ScanStatus
    config: dict
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    # Phase 7: null until the scan reaches RISK_ANALYSIS; a scored scan with
    # zero findings/misconfigs lands on 0.0/"NONE", never null again.
    risk_score: float | None
    risk_tier: str | None


class ScanStatusRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    status: ScanStatus
    updated_at: datetime
    error_message: str | None
