import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, Float, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base

if TYPE_CHECKING:
    from app.models.service import Service


class FindingValidationState(str, enum.Enum):
    """Mirrors ScanStatus's "str, enum.Enum" + values_callable pattern
    (app/models/scan.py) exactly, for the same reason: Postgres gets a
    real native enum type, Pydantic schemas accept/emit the lowercase
    string value directly, no separate int<->label mapping anywhere.

    Deliberately only three states, not four. A NEEDS_REVIEW/FLAGGED
    state was considered and rejected: it would imply a review *workflow*
    (a queue, an assignment, a notification) this project has no
    mechanism for -- no user/auth system exists to assign a review to.
    Every UNVALIDATED Finding is already, implicitly, "not yet reviewed"
    -- confidence_score is the signal an operator uses to decide what's
    worth reviewing first; a separate tri-state flag for "flagged" would
    just be a second way to express a subset of "still UNVALIDATED",
    adding a state-space an operator has to reason about for no new
    information.
    """

    UNVALIDATED = "unvalidated"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"


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

    # --- Phase 5 additions ---
    # 0-100, see modules/vulnerability/confidence.py. NOT NULL: every
    # branch of compute_confidence() produces a concrete float (even the
    # "we genuinely have no evidence" case returns a defensive floor, not
    # None) -- there is no code path that constructs a Finding without
    # being able to compute this, so a nullable column here would only
    # invite an accidental, meaningless NULL rather than model a real
    # "unknown" state (which the 10.0 defensive floor already models).
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    # Default UNVALIDATED for every newly-created Finding -- set
    # implicitly by this column default, never explicitly in
    # correlator.py (keeping correlator.py's Finding construction
    # unaware of validation entirely -- scoring and validation are
    # independent concerns that happen to share a table, see PLAN_5.md
    # Context).
    validation_state: Mapped[FindingValidationState] = mapped_column(
        Enum(
            FindingValidationState,
            name="finding_validation_state",
            values_callable=lambda enum_cls: [e.value for e in enum_cls],
        ),
        default=FindingValidationState.UNVALIDATED,
        server_default=FindingValidationState.UNVALIDATED.value,
        nullable=False,
    )
    # Free-text, always optional, for either CONFIRMED or FALSE_POSITIVE
    # (per the binding decision). "Full replace" semantics, not merge: a
    # PATCH that sets a new validation_state always sets validation_note
    # to exactly what that PATCH call provided (None if omitted) -- see
    # finding_service.py's reasoning for why a stale note from a prior,
    # different validation decision must never silently survive.
    validation_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Set to now() whenever validation_state is set to CONFIRMED or
    # FALSE_POSITIVE (on every such PATCH call, not just the first
    # transition into that state -- re-affirming or editing the note
    # bumps it too, since it answers "when did a human last make this
    # call", not "when did this first stop being UNVALIDATED"). Cleared
    # back to None when validation_state is explicitly set back to
    # UNVALIDATED. A new, purpose-specific timestamp -- Finding has no
    # generic `updated_at` at all (unlike Scan's `onupdate=func.now()`),
    # and this phase doesn't add one; validated_at answers one specific
    # question, not "was this row touched".
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    service: Mapped["Service"] = relationship(back_populates="findings")
