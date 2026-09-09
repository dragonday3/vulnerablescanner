import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ProjectBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None


class ProjectCreate(ProjectBase):
    pass


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None

    @field_validator("name")
    @classmethod
    def name_cannot_be_explicitly_null(cls, value: str | None) -> str | None:
        # Pydantic only runs field validators on fields that were actually
        # provided in the input, so this fires for an explicit
        # `{"name": null}` PATCH body but not for an omitted `name` field —
        # `exclude_unset=True` in project_service.update_project only
        # excludes fields never mentioned, not explicit nulls, so without
        # this check a `null` here reaches the DB's NOT NULL constraint and
        # crashes with an unhandled IntegrityError -> 500.
        if value is None:
            raise ValueError("name cannot be null")
        return value


class ProjectRead(ProjectBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    updated_at: datetime
