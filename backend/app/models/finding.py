import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Float, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base

if TYPE_CHECKING:
    from app.models.service import Service


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("service_id", "cve_id", "matched_cpe", name="uq_finding_service_cve_cpe"),
    )
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    service_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("services.id", ondelete="CASCADE"), index=True, nullable=False
    )
    cve_id: Mapped[str] = mapped_column(String(20), nullable=False)  # "CVE-2021-41773"
    # The exact CPE 2.3 string that produced this match — joins cleanly back
    # to cve_cache.cpe for audit ("why do we think this service has this
    # CVE" -> look up this exact cpe in cve_cache). A Service can carry
    # multiple CPEs in evidence["cpe"] (nmap sometimes reports more than
    # one, e.g. an OS cpe alongside an app cpe); each contributes its own
    # Finding rows, never silently merged.
    matched_cpe: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    # "NONE" is a real, non-null value here (not Optional) — CVSS itself
    # defines a None/Low/Medium/High/Critical severity banding, so a CVE
    # with no CVSS metrics at all (rare but real, e.g. very old or
    # reserved-but-unscored CVEs) legitimately IS severity "NONE", not an
    # absence of data requiring a nullable column + separate UI branch
    # (contrast with FingerprintBadge's null="never fingerprinted" case,
    # which has no CVSS equivalent here).
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="NONE")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(100), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Raw NVD `cve` object subtree for this CVE, verbatim — mirrors the
    # Service.evidence convention exactly: structured columns above are a
    # convenience projection, this JSONB is the source of truth, never
    # lossy even when the parse above is a reasonable-but-lossy summary.
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    service: Mapped["Service"] = relationship(back_populates="findings")
