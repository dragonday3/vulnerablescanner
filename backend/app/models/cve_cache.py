import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base_class import Base


class CveCache(Base):
    __tablename__ = "cve_cache"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    # The CPE 2.3-formatted string actually sent to NVD as `cpeName` (post
    # cpe_utils conversion) — the canonical cache key. Unique+indexed: this
    # table's whole purpose is O(1) lookup by this column.
    cpe: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    # When this entry was last successfully fetched from NVD. A failed
    # lookup NEVER reaches this table at all (see §4) — every row here
    # represents a real, successful NVD response, even one with zero CVEs.
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # NVD's own `totalResults` for this cpeName+isVulnerable=true query, for
    # audit (lets an operator later notice "NVD said there were 40 but we
    # only cached the first 200" truncation cases per the no-pagination
    # scope limit).
    total_results: Mapped[int] = mapped_column(Integer, nullable=False)
    # Normalized CVE list (see nvd_client.NormalizedCve), JSONB, one entry
    # per CVE: {cve_id, description, severity, cvss_score, cvss_vector,
    # references, raw}. An empty list `[]` is a real, meaningful, cacheable
    # "NVD confirms zero known CVEs for this CPE" result — distinct from
    # this row not existing at all (= never successfully looked up).
    cves: Mapped[list] = mapped_column(JSONB, nullable=False)
