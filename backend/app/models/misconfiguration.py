import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base

if TYPE_CHECKING:
    from app.models.service import Service


class Misconfiguration(Base):
    __tablename__ = "misconfigurations"
    __table_args__ = (
        UniqueConstraint("service_id", "check_id", name="uq_misconfig_service_check"),
    )
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    service_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("services.id", ondelete="CASCADE"), index=True, nullable=False
    )
    # Which rule fired, e.g. "missing-hsts", "exposed-sensitive-service",
    # "self-signed-cert" — stable identifiers, never translated/localized
    # here. The uq_misconfig_service_check constraint above is load-bearing:
    # the analyzer must never attempt the same check_id twice for one
    # service (see PLAN_6_TASKS.md Global Constraint 9).
    check_id: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    # Plain string, not a DB enum — mirrors Finding.severity's own
    # existing convention exactly (CRITICAL/HIGH/MEDIUM/LOW; "NONE" is
    # never used here since a row only exists when something was
    # actually flagged).
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    # Raw supporting evidence, verbatim — same convention as
    # Finding.evidence/Service.evidence: always populated meaningfully,
    # never a stand-in for a missing structured field.
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    service: Mapped["Service"] = relationship(back_populates="misconfigurations")
