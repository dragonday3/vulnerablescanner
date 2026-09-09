import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.target import TargetType


class TargetBase(BaseModel):
    value: str = Field(min_length=1, max_length=255)
    target_type: TargetType
    authorization_note: str | None = None


class TargetCreate(TargetBase):
    authorization_confirmed: bool

    @field_validator("authorization_confirmed")
    @classmethod
    def must_be_confirmed(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("Target must be confirmed as authorized before it can be added")
        return value


class TargetRead(TargetBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    authorization_confirmed: bool
    created_at: datetime
