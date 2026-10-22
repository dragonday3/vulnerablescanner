import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    service_id: uuid.UUID
    cve_id: str
    matched_cpe: str
    severity: str
    cvss_score: float | None
    cvss_vector: str | None
    description: str | None
    evidence: dict
    created_at: datetime
