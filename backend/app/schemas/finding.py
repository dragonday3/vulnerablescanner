import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.finding import FindingValidationState


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
    # --- Phase 5 additions ---
    confidence_score: float
    validation_state: FindingValidationState
    validation_note: str | None
    validated_at: datetime | None


class FindingValidationUpdate(BaseModel):
    """Body for PATCH /findings/{id}. validation_state is required (there
    is no sensible partial-update default for "what should this become");
    validation_note is always optional, per the binding decision, for
    either target state. Unlike ProjectUpdate (a true partial PATCH using
    `exclude_unset=True`), this is a full-replace of both fields on every
    call -- see finding_service.py for why validation_note is never
    merged with whatever note was there before.
    """

    validation_state: FindingValidationState
    validation_note: str | None = Field(default=None, max_length=2000)
