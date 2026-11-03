import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Float, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base

if TYPE_CHECKING:
    from app.models.service import Service


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # --- Phase 7 additions ---
    # NULL means "not yet risk-scored" (pre-Phase-7 row, or this scan
    # hasn't reached RISK_ANALYSIS yet) -- a real, distinct state from a
    # computed score of 0.0/tier "NONE" ("scored, nothing found"). See
    # PLAN_7.md's architecture-decision #3 for why this is nullable where
    # Finding.confidence_score is not.
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    # CRITICAL/HIGH/MEDIUM/LOW/NONE -- same vocabulary and same
    # plain-string-not-enum convention as Finding.severity/
    # Misconfiguration.severity.
    risk_tier: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # order_by="Service.port": without it, services come back in arbitrary
    # (heap) order, and since the native-enrichment pass UPDATEs rows in
    # place (see app.workers.tasks), fingerprinted ports would visibly
    # reorder in the frontend table after a scan completes.
    services: Mapped[list["Service"]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="Service.port",
    )
