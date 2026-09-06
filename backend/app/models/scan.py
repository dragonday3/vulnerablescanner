import uuid, enum
from datetime import datetime
from sqlalchemy import ForeignKey, DateTime, func, Enum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base

class ScanStatus(str, enum.Enum):
    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    DISCOVERY = "discovery"
    FINGERPRINTING = "fingerprinting"
    ANALYZING = "analyzing"
    CORRELATING = "correlating"
    RISK_ANALYSIS = "risk_analysis"
    REPORT_GENERATION = "report_generation"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status", values_callable=lambda enum_cls: [e.value for e in enum_cls]),
        default=ScanStatus.CREATED,
        nullable=False,
    )
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    project: Mapped["Project"] = relationship(back_populates="scans")
    target: Mapped["Target"] = relationship()
