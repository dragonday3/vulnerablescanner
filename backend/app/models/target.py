import uuid, enum
from datetime import datetime
from sqlalchemy import String, Text, Boolean, ForeignKey, DateTime, func, Enum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base_class import Base

class TargetType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    CIDR = "cidr"

class Target(Base):
    __tablename__ = "targets"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[TargetType] = mapped_column(
        Enum(TargetType, name="target_type", values_callable=lambda enum_cls: [e.value for e in enum_cls]),
        nullable=False,
    )
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    authorization_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    project: Mapped["Project"] = relationship(back_populates="targets")
