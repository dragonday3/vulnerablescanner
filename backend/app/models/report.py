import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base_class import Base


class Report(Base):
    """One per Scan, generated once during ScanStatus.REPORT_GENERATION,
    never regenerated. `scan_id` is unique -- enforced at the DB level,
    not just by application discipline (mirrors uq_misconfig_service_check's
    own defensive-dedup posture). `summary` is a passthrough JSONB
    document (see report_builder.build_report_summary) -- same convention
    as Finding.evidence/Service.evidence/Misconfiguration.evidence: the
    JSONB column is the source of truth for a nested document, not a
    lossy scalar projection of one.
    """

    __tablename__ = "reports"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        unique=True,
        index=True,
        nullable=False,
    )
    summary: Mapped[dict] = mapped_column(JSONB, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
