# PLAN_5.md — VulnSight Phase 5 Implementation Plan: Confidence & Validation

## Context

Phase 4 answered "is any of this actually vulnerable" by correlating nmap-sourced CPE evidence against the NVD CVE API and persisting the matches as `Finding` rows — deliberately unweighted and unvalidated, exactly the scope limit PLAN_4.md called out: *"a `Finding` is recorded as 'NVD says this CPE matches this CVE,' full stop, no judgment about how trustworthy that match is."* Phase 5 adds that judgment, in two independent halves that happen to land on the same table:

1. **Confidence scoring** — a continuous 0-100 float, computed automatically at `Finding`-creation time, reflecting how much the evidence that produced this `Finding` should actually be trusted. The only evidence available for this is already sitting on the `Service` row that produced the match: nmap's own `method` (`"probed"` vs `"table"`) and `conf` (0-10) attributes, captured since Phase 3 (`backend/app/modules/discovery/nmap_scanner.py:136-137`) and already present in `Service.evidence["method"]`/`Service.evidence["conf"]` for every nmap-sourced `Service`.
2. **Validation state** — a human-operator judgment call, applied after the fact, independent of scoring: `UNVALIDATED` (default, every `Finding` starts here) → `CONFIRMED` or `FALSE_POSITIVE`, with an optional free-text note, via a new write endpoint.

These two halves are related but not coupled: confidence scoring happens automatically, deterministically, inside Phase 4's existing `CORRELATING` stage (no new Celery stage, no new `ScanStatus` value — confirmed below); validation-state changes are an out-of-band, asynchronous, human-triggered API call that has nothing to do with the scan pipeline at all. A `Finding` can be high-confidence and still get marked `FALSE_POSITIVE` (the operator knows something the formula doesn't — e.g. the service is actually a honeypot, or a false CPE match), and a low-confidence `Finding` can sit `UNVALIDATED` indefinitely. This phase builds the two mechanisms; it does not wire one into the other (no auto-marking low-confidence findings as likely-false-positive — see scope limits).

### Why no new `ScanStatus` value

Confirmed by re-reading `backend/app/models/scan.py`: `ANALYZING`, `RISK_ANALYSIS`, `REPORT_GENERATION` remain unused/reserved. Confidence scoring is computed as a pure function of a `Service` row's already-persisted `evidence` dict, called once per `Service` inside the existing per-CPE loop in `correlator.py` — it adds zero I/O, zero latency, zero new failure modes to that stage; it is exactly the same kind of in-memory, milliseconds-scale computation PLAN_4.md's own scope limits said didn't justify a new status for CPE selection/dedup. Validation-state changes happen entirely outside `run_scan_task` — there is no scan in flight when an operator clicks "mark as false positive" days after a scan completed, so there is no pipeline stage for it to occupy at all. Confirmed: this phase needs no `ScanStatus` change.

### Explicit scope limits for this phase (documented, not accidental)

- **No re-computation of confidence after the fact.** `confidence_score` is set once, at `Finding`-construction time, from whatever `Service.evidence` held at that moment. There is no mechanism to mutate a `Service` row's `evidence` after Phase 3's fingerprinting pass completes (and that pass runs *before* correlation in the same scan), so there is nothing to react to even if this were built. A re-scan produces an entirely new `Asset`/`Service`/`Finding` tree anyway (Phase 2's "no cross-scan dedup" scope limit, still true).
- **No bulk/batch validation-state endpoint.** One `Finding` at a time, via its own id. An operator working through 40 findings makes 40 calls. A bulk endpoint is a plausible future addition if this ever becomes a real workflow bottleneck — not built here.
- **No audit log of who changed a validation state or when, beyond `validated_at`.** This project has no user/auth system at all (confirmed: no `User` model, no auth middleware anywhere in `backend/app`) — there is no "who" to record. `validated_at` alone is already more audit trail than anything else in this schema has (`Finding.created_at` is the only other timestamp on this table, and it's not even updated — note Phase 4's `Finding` has no `updated_at` at all, unlike `Scan`, which does via `onupdate=func.now()`).
- **No automatic false-positive detection heuristics beyond the confidence score itself.** No "auto-mark confidence < 20 as likely-false-positive," no auto-transition of any kind. The score is read-only input to a human's judgment call this phase only supports, never makes.
- **Unrestricted validation-state transitions.** Any state can move to any other state via repeated PATCH calls (including back to `UNVALIDATED`, treated as "undo my judgment"). Justified below in §4.
- **No new `ScanStatus` value, no new Celery stage, no new external dependency** (no NVD, no Redis — see §6, this phase's tests are notably simpler than Phase 4's for exactly that reason).
- **No change to how Phase 7 (Risk Intelligence) will eventually consume `confidence_score`/`validation_state` together with `severity`/`cvss_score`.** That weighting/combination logic is explicitly Phase 7's job; this phase only produces the two raw inputs.
- **No CVSS v4 support, no per-scan correlation-outcome tracking.** Both are pre-existing, already-documented gaps from Phase 4 (see `CLAUDE.md`'s Status section) — unrelated to confidence/validation, not addressed here either.

---

## 1. The Confidence-Scoring Formula

### `backend/app/modules/vulnerability/confidence.py` (new)

Lives in its own module, not inlined into `correlator.py` — same rationale PLAN_4.md gave for splitting `rate_limiter.py` out of `nvd_client.py`: it is a pure, self-contained, deterministic computation with no DB/network/Redis dependency at all, so it earns its own file and its own focused table-driven unit tests (§6), independent of anything `correlator.py` does.

```python
"""Confidence scoring for Finding rows (Phase 5).

Reflects how much to trust a Finding's underlying service-identification
evidence -- NOT how severe the matched CVE is (that's severity/cvss_score,
untouched) and NOT a human judgment call (that's validation_state,
applied separately, see finding_service.py). A continuous 0-100 float,
not a HIGH/MEDIUM/LOW tier, so Phase 7's risk scoring can sort/weight on
it directly rather than re-deriving a number from a bucket.

The only inputs available are nmap's own `method` ("probed" | "table")
and `conf` (0-10 int, as a string) attributes, already captured on
Service.evidence by Phase 3's nmap adapter (nmap_scanner.py). By the time
this runs (inside correlator.py, per already-persisted Service ORM rows),
PortScanResult itself is long gone -- evidence is the only source.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.service import Service

logger = logging.getLogger(__name__)

# --- "probed" band: nmap actually handshook with the service and ran a
# protocol-specific interrogation to confirm it -- this is real evidence,
# not a guess. Floor of 50 reflects baseline trust in the handshake itself
# (even a probed match with conf=0 still beats any table-sourced guess);
# the remaining 50 points scale nmap's own 0-10 self-reported `conf`
# linearly, so a probed, conf=10 match reaches the ceiling of 100.
PROBED_FLOOR = 50.0
PROBED_CONF_SCALE = 5.0  # per point of conf, 0-10 -> +0..+50
# nmap's `-sV` empirically almost always sets `conf` alongside
# method="probed" (conf is emitted by the same version-probe subsystem
# that sets method="probed" in the first place) -- the only time this
# branch is hit is an unexpected nmap-output shape. Default to the
# band's midpoint (conf=5 equivalent) rather than assuming best- or
# worst-case: there's no principled way to guess higher or lower without
# the number nmap itself would have reported.
PROBED_MISSING_CONF_DEFAULT = 75.0

# --- "table" band: a static port->service guess from nmap's internal
# nmap-services port table -- nmap never actually talked to the service.
# Deliberately capped at 45, strictly below the "probed" floor of 50 (not
# touching it) -- so no table-sourced guess, however confidently
# self-reported, can ever tie or outrank an actual confirmed probe. The
# gap between 45 and 50 is intentional, not a rounding accident: it means
# no combination of inputs in either band can produce an equal score,
# which keeps "probed always outranks table" a structural guarantee of
# the band boundaries themselves, not something that happens to hold for
# the specific numbers chosen today.
TABLE_CEILING = 45.0
TABLE_CONF_SCALE = TABLE_CEILING / 10.0  # 4.5 per point of conf, 0-10 -> 0..45
# The overwhelmingly common case: nmap's table-based matches essentially
# never carry a `conf` attribute at all (conf is only emitted by the
# version-probe subsystem, which a table match never invokes). 20 is a
# low, fixed value standing for "a guess, nothing more" -- deliberately
# not 0, since even an unconfirmed port-table guess (e.g. port 22 -> ssh)
# is still evidence of a kind, just far weaker than anything nmap
# actually confirmed.
TABLE_MISSING_CONF_DEFAULT = 20.0

# --- method missing entirely, or an unrecognized value nmap hasn't
# documented (nmap's only two documented values are "table"/"probed" --
# PLAN_3/4's own nmap_scanner.py reading confirms this). Shouldn't
# normally happen for a Finding-producing Service (a CPE had to come
# from somewhere, and nmap only ever emits <cpe> inside the same
# <service> element that carries method), but confidence scoring must
# still produce a number defensively, not raise or return None mid-
# correlation. Fixed below the table band's floor (0), distinguishing
# "we have real evidence, however weak" from "we don't even know what
# kind of evidence this is" -- but still a small positive number, not 0,
# since there IS a Finding here (a CPE existed), just with confidence
# metadata this phase cannot interpret.
METHOD_MISSING_SCORE = 10.0

_MIN_CONF, _MAX_CONF = 0, 10


def _parse_conf(raw: object) -> int | None:
    """Parse nmap's `conf` attribute (a string, e.g. "7") into an int
    clamped to nmap's documented 0-10 range. Returns None for missing,
    non-numeric, or any other unparseable value -- treated identically to
    "nmap didn't tell us" by every caller below, never raised.
    """
    if raw is None:
        return None
    try:
        value = int(str(raw))
    except (TypeError, ValueError):
        logger.warning("confidence: unparseable conf value %r, treating as missing", raw)
        return None
    if value < _MIN_CONF or value > _MAX_CONF:
        logger.warning("confidence: out-of-range conf value %r, clamping to [0, 10]", raw)
    return max(_MIN_CONF, min(_MAX_CONF, value))


def compute_confidence(service: "Service") -> float:
    """Deterministic 0-100 confidence score for every Finding that will be
    built from this Service's CPE evidence this correlation pass. Called
    once per Service (not once per Finding/CVE) by correlator.py, since
    the inputs live entirely on Service.evidence and never vary across the
    multiple CVEs one Service's CPE can match.

    Never raises, never returns None -- every branch below produces a
    concrete float, so Finding.confidence_score is NOT NULL (see §2).
    """
    evidence = service.evidence or {}
    method = evidence.get("method")
    conf = _parse_conf(evidence.get("conf"))

    if method == "probed":
        if conf is None:
            return PROBED_MISSING_CONF_DEFAULT
        return round(PROBED_FLOOR + conf * PROBED_CONF_SCALE, 1)

    if method == "table":
        if conf is None:
            return TABLE_MISSING_CONF_DEFAULT
        return round(conf * TABLE_CONF_SCALE, 1)

    if method is not None:
        logger.warning(
            "confidence: service %s has unrecognized method %r (nmap documents only "
            "'table'/'probed'), treating as method-missing",
            service.id,
            method,
        )
    return METHOD_MISSING_SCORE
```

Worked examples (the test table in §6 is this, formally):

| `method` | `conf` | score | reasoning |
|---|---|---|---|
| `"probed"` | `"10"` | 100.0 | handshake confirmed + nmap's own max self-confidence |
| `"probed"` | `"0"` | 50.0 | handshake confirmed, but nmap's own match was ambiguous |
| `"probed"` | missing | 75.0 | handshake confirmed, nmap gave no number — neutral default |
| `"table"` | missing | 20.0 | pure port-table guess, no probe, no self-reported number (the common case) |
| `"table"` | `"10"` | 45.0 | pure port-table guess, even with (unusually) a self-reported number — still capped below every probed score |
| `"table"` | `"0"` | 0.0 | pure port-table guess, self-reporting zero confidence |
| missing entirely | n/a | 10.0 | defensive floor — shouldn't normally happen |
| `"bogus"` (unrecognized) | n/a | 10.0 | defensive floor, logged — nmap only documents two values |

---

## 2. Model Changes — `backend/app/models/finding.py` (edit)

Four new columns, all additive:

```python
import enum
...
from sqlalchemy import DateTime, Enum, Float, ForeignKey, String, Text, UniqueConstraint, func

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
    # ... existing columns unchanged ...

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
```

### Migration — `backend/migrations/versions/<rev>_add_finding_confidence_and_validation_columns.py` (new)

`alembic revision --autogenerate -m "add finding confidence and validation columns"`. `down_revision` is `45f7e770cdbb` (the current head — Phase 4's `cve_cache`/`findings` migration; confirmed via the migration chain, no migration has landed after it). Expected generated body: four `op.add_column('findings', ...)` calls, plus the `finding_validation_state` Postgres enum type creation. Review and adjust to match `d6b7d6e6b8c8_add_service_fingerprint_columns_product_.py`'s exact `op.add_column` style, the closest precedent: four nullable columns added to an existing, possibly-populated table.

`confidence_score` is the one column here that's NOT NULL on a table that may already have rows (any `Finding` rows created during Phase 4 dev/testing on this environment). Rather than either (a) making it nullable — which contradicts §2's reasoning that it's never meaningfully absent — or (b) backfilling it with a meaningless sentinel like `0.0` that then lingers forever since there's no ongoing recompute mechanism (§ scope limits), this migration does a **one-time, bounded backfill**, in the same `upgrade()` function, immediately after adding the column nullable-with-no-default:

```python
def upgrade() -> None:
    op.add_column("findings", sa.Column("confidence_score", sa.Float(), nullable=True))
    # One-time backfill for any pre-existing rows, computed from each
    # row's already-persisted Service.evidence via the same formula
    # confidence.py uses going forward -- NOT an ongoing recompute
    # mechanism (see PLAN_5.md's "no re-computation" scope limit); this
    # runs exactly once, now, because the column is new, not because
    # Service.evidence ever changed after the fact.
    connection = op.get_bind()
    rows = connection.execute(
        sa.text("SELECT f.id, s.evidence FROM findings f JOIN services s ON s.id = f.service_id")
    ).fetchall()
    for finding_id, evidence in rows:
        score = _compute_confidence_from_evidence(evidence or {})  # inlined copy of confidence.py's
        connection.execute(                                        # pure logic -- migrations must not
            sa.text("UPDATE findings SET confidence_score = :score WHERE id = :id"),  # import app code
            {"score": score, "id": finding_id},
        )
    op.alter_column("findings", "confidence_score", nullable=False)

    finding_validation_state = postgresql.ENUM(
        "unvalidated", "confirmed", "false_positive", name="finding_validation_state"
    )
    finding_validation_state.create(op.get_bind())
    op.add_column(
        "findings",
        sa.Column(
            "validation_state", finding_validation_state,
            nullable=False, server_default="unvalidated",
        ),
    )
    op.add_column("findings", sa.Column("validation_note", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True))
```

(`_compute_confidence_from_evidence` is a small, self-contained inline copy of `confidence.py`'s pure logic within the migration file itself — migrations must never import application code, since app code can change shape after the migration is written and frozen; this is the same reasoning any Alembic data-migration guide gives, and keeps this one-time backfill reproducible forever regardless of future refactors to `confidence.py`.) If this environment genuinely has zero pre-existing `Finding` rows (likely, for a project this early), the backfill loop is simply a no-op over an empty result set — harmless either way, and worth keeping for correctness rather than skipping, since "assume the table is empty" is exactly the kind of assumption that bites later.

`backend/app/db/base.py`: no change needed — `Finding` is already imported there from Phase 4.

---

## 3. Where Confidence Is Computed — `backend/app/modules/vulnerability/correlator.py` (edit)

Minimal, surgical diff. Add the import, compute confidence once per `service` in `mapped_services` (not once per `(service, cve)` pair), and pass it into each `Finding`:

```python
from app.modules.vulnerability import cache, confidence, cpe_utils, nvd_client
```

Inside the per-CPE loop, immediately before building `findings`:

```python
                # Computed once per Service, not once per (service, cve)
                # pair -- method/conf live on Service.evidence, which
                # never varies across the multiple CVEs one CPE can
                # match, so recomputing it inside the comprehension's
                # inner `for cve in cves` loop below would be pure waste
                # (and, worse, would make it easy to accidentally call it
                # with the wrong service if the comprehension were ever
                # restructured).
                confidence_by_service = {
                    service.id: confidence.compute_confidence(service) for service in mapped_services
                }
                findings = [
                    Finding(
                        service_id=service.id,
                        cve_id=cve.cve_id,
                        matched_cpe=cpe23,
                        severity=cve.severity,
                        cvss_score=cve.cvss_score,
                        cvss_vector=cve.cvss_vector,
                        description=cve.description,
                        evidence=cve.raw,
                        confidence_score=confidence_by_service[service.id],
                    )
                    for service in mapped_services
                    for cve in cves
                ]
```

`validation_state`/`validation_note`/`validated_at` are deliberately **not** touched here — they rely entirely on the model's own `default=`/`server_default=`/nullable-with-no-default. This keeps `correlator.py` unaware that validation exists at all, which is the concrete expression of "scoring and validation are independent mechanisms that happen to share a table" from the Context section above.

No change to the cache-hit path (rehydrating `NormalizedCve` from `entry.cves`) — confidence is purely a function of the *Service*, never the cached CVE data, so a cache hit computes confidence exactly the same way a cache miss does.

---

## 4. The Validation-State API

### `backend/app/schemas/finding.py` (edit)

```python
from app.models.finding import FindingValidationState

class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    service_id: uuid.UUID
    cve_id: str
    matched_cpe: str
    severity: str
    cvss_score: float | None
    cvss_vector: str | None
    description: str | None
    evidence: dict
    created_at: datetime
    # --- Phase 5 additions ---
    confidence_score: float
    validation_state: FindingValidationState
    validation_note: str | None
    validated_at: datetime | None


class FindingValidationUpdate(BaseModel):
    """Body for PATCH /findings/{id}. validation_state is required (there
    is no sensible partial-update default for "what should this become");
    validation_note is always optional, per the binding decision, for
    either target state. Unlike ProjectUpdate (a true partial PATCH using
    `exclude_unset=True`), this is a full-replace of both fields on every
    call -- see finding_service.py for why validation_note is never
    merged with whatever note was there before.
    """

    validation_state: FindingValidationState
    validation_note: str | None = None
```

### `backend/app/services/finding_service.py` (new)

A new, minimal service module — this is the first time the project needs to *write* to an individual `Finding`, so it gets its own thin service file, following the exact `project_service.py`/`scan_service.py` precedent (`get_X` raising `NotFoundError`, a single focused update function):

```python
"""Finding-level service functions (Phase 5). Deliberately thin and
single-purpose -- the only write operation this phase introduces is
setting a Finding's validation state. Everything else about a Finding
(creation, scoring) happens in correlator.py/confidence.py, upstream of
this module, during correlation -- this file never constructs a Finding,
only mutates an existing one's validation fields.
"""

from datetime import UTC, datetime
import uuid

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.models.finding import Finding, FindingValidationState
from app.schemas.finding import FindingValidationUpdate


def get_finding(db: Session, finding_id: uuid.UUID) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise NotFoundError(f"Finding {finding_id} not found")
    return finding


def update_validation(db: Session, finding_id: uuid.UUID, data: FindingValidationUpdate) -> Finding:
    """Unrestricted transitions: any validation_state may move to any
    other, including back to UNVALIDATED (treated as "undo my previous
    judgment"). No transition table/state machine is enforced.

    Justification for "unrestricted" over "some transitions disallowed":
    this project has no auth/multi-user system, so there's no scenario
    where a transition needs blocking to protect one operator's judgment
    from another's -- the only actor who can ever call this endpoint is
    whoever is running VulnSight at all, and they are always allowed to
    change their own mind. Restricting transitions "for safety" with no
    actual multi-party conflict to guard against would just be friction
    with no corresponding benefit; simplicity wins here over a defensive
    rule this project's actual usage pattern doesn't need yet.

    validation_note: full-replace, never merged with the prior note. If a
    Finding was CONFIRMED with note "verified via SSH login", then later
    re-flagged FALSE_POSITIVE with no note on that call, the earlier
    "verified..." note must NOT silently persist attached to the new
    FALSE_POSITIVE state -- it would misleadingly look like a note
    justifying a judgment it was never written for. Every PATCH call sets
    validation_note to exactly what it provided (None if omitted).

    validated_at: set to now() whenever the target state is CONFIRMED or
    FALSE_POSITIVE -- on every such call, not only the first transition
    into that state, since it answers "when did a human last make this
    call" (editing the note later is itself a new act of judgment worth
    re-timestamping). Cleared to None when the target state is
    UNVALIDATED, since "when was this validated" has no answer once the
    validation itself has been undone.
    """
    finding = get_finding(db, finding_id)
    finding.validation_state = data.validation_state
    if data.validation_state == FindingValidationState.UNVALIDATED:
        # "Undo" semantics: a note only makes sense attached to an actual
        # judgment call. Clear it too, rather than leaving a stale
        # "confirmed because X" note floating under a now-unvalidated
        # Finding where it no longer means anything.
        finding.validation_note = None
        finding.validated_at = None
    else:
        finding.validation_note = data.validation_note
        finding.validated_at = datetime.now(UTC)
    db.commit()
    db.refresh(finding)
    return finding
```

### `backend/app/api/routes/findings.py` (new)

A new, minimal, standalone router — the direct-by-id resource route the design's own framing favors, and the first time this project needs one (confirmed: no existing `findings.py` route file, `Finding` was exposed read-only, nested, via `scans.py`'s `GET /scans/{scan_id}/assets` only). Matches the existing `scans.py` pattern of a narrow, single-purpose route sitting alongside the resource's natural CRUD shape (`GET /scans/{scan_id}/status` is the closest sibling precedent, and `projects.py`'s `PATCH /projects/{project_id}` is the closest precedent for the verb/shape itself):

```python
import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.finding import Finding
from app.schemas.finding import FindingRead, FindingValidationUpdate
from app.services import finding_service

router = APIRouter(prefix="/findings", tags=["findings"])


@router.patch("/{finding_id}", response_model=FindingRead)
def update_finding_validation(
    finding_id: uuid.UUID, data: FindingValidationUpdate, db: Session = Depends(get_db)
) -> Finding:
    return finding_service.update_validation(db, finding_id, data)
```

No `GET /findings/{id}` or `GET /findings` is added — not needed by anything yet (the frontend's only need is the nested `findings[]` array it already gets from `GET /scans/{scan_id}/assets`, and the PATCH response body itself already returns the full updated `FindingRead`, which is all the frontend's mutation flow needs — see §5). A flat `GET /findings` listing is exactly the kind of cross-scan findings view PLAN_4.md's own §6 already deferred to Phase 8 reporting; nothing in this phase needs it either.

### `backend/app/main.py` (edit — one line)

```python
from app.api.routes.findings import router as findings_router
...
app.include_router(findings_router, prefix=settings.API_V1_PREFIX)
```

No change to `backend/app/api/routes/scans.py` or `scan_service.py` — `GET /scans/{scan_id}/assets` already nests `Finding` rows via `ServiceRead.findings`, and `FindingRead`'s edit above means those four new fields simply appear in that existing response automatically, no eager-load change needed (they're plain columns on the already-loaded `Finding` row, not a new relationship).

---

## 5. Frontend

### `frontend/src/lib/types/finding.ts` (edit)

```typescript
export type ValidationState = "unvalidated" | "confirmed" | "false_positive";

export interface FindingRead {
  id: string;
  service_id: string;
  cve_id: string;
  matched_cpe: string;
  severity: Severity;
  cvss_score: number | null;
  cvss_vector: string | null;
  description: string | null;
  evidence: Record<string, unknown>;
  created_at: string;
  // --- Phase 5 additions ---
  confidence_score: number;
  validation_state: ValidationState;
  validation_note: string | null;
  validated_at: string | null;
}

export interface FindingValidationUpdate {
  validation_state: ValidationState;
  validation_note?: string | null;
}
```

### `frontend/src/lib/api/findings.ts` (new)

Mirrors `scans.ts`'s exact one-function-per-endpoint style:

```typescript
import { request } from "./client";
import type { FindingRead, FindingValidationUpdate } from "@/lib/types/finding";

/** PATCH /findings/{id} — used by FindingValidationControl. */
export function updateFindingValidation(
  findingId: string,
  payload: FindingValidationUpdate,
): Promise<FindingRead> {
  return request<FindingRead>(`/findings/${findingId}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}
```

### `frontend/src/components/ValidationBadge.tsx` (new)

Same exhaustive-`Record` convention as `SeverityBadge.tsx`, but following `FingerprintBadge.tsx`'s `Exclude<...>` shape instead: `"unvalidated"` is the overwhelmingly common default state for every `Finding` Phase 4 ever produced and the vast majority Phase 5 will too, so — same reasoning as `service.findings.length === 0` rendering nothing in PLAN_4.md §7 — it must render **nothing**, not a neutral "Unvalidated" badge that would just be noise on every single finding:

```typescript
import type { ValidationState } from "@/lib/types/finding";

const VALIDATION_STYLES: Record<Exclude<ValidationState, "unvalidated">, string> = {
  confirmed: "bg-emerald-100 text-emerald-700 ring-emerald-300",
  false_positive: "bg-zinc-200 text-zinc-600 ring-zinc-400",
};

const VALIDATION_LABELS: Record<Exclude<ValidationState, "unvalidated">, string> = {
  confirmed: "Confirmed",
  false_positive: "False Positive",
};

export default function ValidationBadge({ state }: { state: ValidationState }) {
  if (state === "unvalidated") return null;
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset ${VALIDATION_STYLES[state]}`}
    >
      {VALIDATION_LABELS[state]}
    </span>
  );
}
```

### `frontend/src/components/FindingValidationControl.tsx` (new, `"use client"`)

Mirrors `ScanCreateButton.tsx`'s exact pattern: local `useState` for the editable fields + `isSubmitting`/`error`, an async submit handler that calls the API function then `router.refresh()` to re-run the server component's fetch, inline error text, no new client-side cache/store. Rendered compactly, inline, per finding (not a modal — nothing else in this app uses one):

```tsx
"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { updateFindingValidation } from "@/lib/api/findings";
import type { FindingRead, ValidationState } from "@/lib/types/finding";

/**
 * Compact inline form for setting one Finding's validation_state (+
 * optional note). Same refresh strategy as ScanCreateButton: call the
 * PATCH, then router.refresh() to re-fetch the server component's
 * getScanAssets() rather than reconciling local state with the server's.
 */
export default function FindingValidationControl({ finding }: { finding: FindingRead }) {
  const router = useRouter();
  const [state, setState] = useState<ValidationState>(finding.validation_state);
  const [note, setNote] = useState(finding.validation_note ?? "");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsSubmitting(true);
    setError(null);
    try {
      await updateFindingValidation(finding.id, {
        validation_state: state,
        validation_note: note.trim() === "" ? null : note.trim(),
      });
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update finding.");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-wrap items-center gap-1.5">
      <select
        value={state}
        onChange={(event) => setState(event.target.value as ValidationState)}
        disabled={isSubmitting}
        className="rounded border border-zinc-300 px-1.5 py-0.5 text-xs text-zinc-700 disabled:opacity-60"
      >
        <option value="unvalidated">Unvalidated</option>
        <option value="confirmed">Confirmed</option>
        <option value="false_positive">False Positive</option>
      </select>
      <input
        type="text"
        value={note}
        onChange={(event) => setNote(event.target.value)}
        disabled={isSubmitting}
        placeholder="Note (optional)"
        className="w-32 rounded border border-zinc-300 px-1.5 py-0.5 text-xs text-zinc-700 disabled:opacity-60"
      />
      <button
        type="submit"
        disabled={isSubmitting}
        className="rounded bg-zinc-900 px-2 py-0.5 text-xs font-medium text-white disabled:opacity-60"
      >
        Save
      </button>
      {error && <span className="text-xs text-red-600">{error}</span>}
    </form>
  );
}
```

### `frontend/src/app/projects/[projectId]/scans/[scanId]/page.tsx` (edit)

Inside the existing per-finding `<div>`, add the confidence display, the `ValidationBadge`, and the control, and apply the false-positive de-emphasis:

```tsx
{service.findings.map((finding) => (
  <div
    key={finding.id}
    className={`flex flex-wrap items-center gap-1.5 ${
      finding.validation_state === "false_positive" ? "opacity-50" : ""
    }`}
  >
    <SeverityBadge severity={finding.severity} />
    <a
      href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
      target="_blank"
      rel="noopener noreferrer"
      className={`font-mono text-xs text-blue-600 hover:underline ${
        finding.validation_state === "false_positive" ? "line-through" : ""
      }`}
    >
      {finding.cve_id}
    </a>
    {finding.cvss_score != null && (
      <span className="text-xs text-zinc-500">(CVSS {finding.cvss_score})</span>
    )}
    <span className="text-xs text-zinc-500">
      Confidence: {Math.round(finding.confidence_score)}/100
    </span>
    <ValidationBadge state={finding.validation_state} />
    <FindingValidationControl finding={finding} />
  </div>
))}
```

**Design decisions, stated explicitly:**
- **Confidence as plain text** (`Confidence: 85/100`), not a bar/meter/chart — matches this project's minimal/text-forward style (every other piece of scan evidence on this page is text: `(CVSS {score})`, `{service.product} {service.version}`, badges that are text-in-a-pill). A numeric bar would be the first chart-like element in the whole frontend and isn't earned by a single number per row.
- **A `FALSE_POSITIVE` finding still renders fully** — reduced opacity (`opacity-50` on the whole row) + a strikethrough on the CVE id specifically, plus the `ValidationBadge` itself, but never hidden and never an empty/placeholder state. Reasoning: hiding it would make the page look like the vulnerability was never found at all, which is its own provenance problem even without a formal audit-trail system — an operator (or a future Phase 8 report) revisiting this scan later needs to see "this was found, and a human already judged it to be a false positive," not "nothing here."
- **`FindingValidationControl` always shows the select pre-filled to the finding's current state** — so re-opening the page after marking something `CONFIRMED` shows "Confirmed" selected already, not a blank/default control implying nothing has been judged yet.

No new empty-state clutter for findings with no validation activity: `ValidationBadge` renders nothing for `"unvalidated"`, so a freshly-correlated `Finding` that's never been touched by an operator looks exactly like it did at the end of Phase 4 (severity badge + CVE link + CVSS + confidence number + the control), with no extra "Unvalidated" noise.

---

## 6. Testing Strategy

This phase's tests are notably simpler than Phase 4's, by design: confidence scoring is a pure function with zero I/O, and the validation-state PATCH is ordinary DB-backed service/route logic — neither touches Redis, NVD, or any real network call, so none of Phase 4's `TEST_REDIS_URL`/mocked-`httpx` machinery is needed anywhere in this phase's tests.

- **`backend/tests/test_confidence.py` (new)**: a table of `(method, conf)` -> expected score, covering every branch in §1's worked-examples table above (`"probed"`/`"10"` -> 100.0, `"probed"`/`"0"` -> 50.0, `"probed"`/missing -> 75.0, `"table"`/missing -> 20.0, `"table"`/`"10"` -> 45.0, `"table"`/`"0"` -> 0.0, `method` missing entirely -> 10.0, an unrecognized `method` value -> 10.0, an out-of-range `conf` like `"15"` or `"-3"` -> clamped to the same result as `conf="10"`/`conf="0"` respectively, a non-numeric `conf` like `"abc"` -> treated as missing). A test object needs only an `evidence` attribute (a plain dataclass/`SimpleNamespace` stand-in is sufficient — no DB row needed, confirming this module has zero DB dependency). One additional invariant test: for every `conf` in 0-10, `compute_confidence` with `method="table"` is strictly less than `compute_confidence` with `method="probed"` for *any* conf value — proving the band-separation guarantee structurally, not just via the two boundary numbers.
- **`backend/tests/test_correlator.py` (extend)**: a new test seeding two `Service` rows that share one CPE — one with `evidence={"cpe": [...], "method": "probed", "conf": "10"}`, one with `evidence={"cpe": [...], "method": "table"}` — and a mocked `fetch_cves_for_cpe` returning 2+ CVEs; assert the resulting `Finding` rows carry `confidence_score == 100.0` for the first service's findings and `confidence_score == 20.0` for the second's, confirming confidence is attached per-service, correctly, even within one shared-CPE correlation pass. A second test patches `confidence.compute_confidence` directly and asserts it's called exactly `len(mapped_services)` times (not once per `Finding`/CVE), locking in the "computed once per service" design from §3 against a future accidental regression into the inner loop.
- **`backend/tests/test_finding_service.py` or `test_findings_route.py` (new)**: via the `db`/`client` fixtures, no Redis/network needed —
  - `PATCH /findings/{id}` with `{"validation_state": "confirmed", "validation_note": "verified manually"}` on a seeded `UNVALIDATED` `Finding` → response has `validation_state="confirmed"`, `validation_note="verified manually"`, `validated_at` non-null; re-fetch from `db` confirms persistence.
  - Same, with `{"validation_state": "false_positive"}` and no note → `validation_note` is `null`, `validated_at` still set.
  - An invalid `validation_state` value (e.g. `"bogus"`) → 422 (Pydantic enum validation rejects it before the route body even runs — confirms `FindingValidationUpdate`'s typed field does the rejection, not hand-rolled route logic).
  - A nonexistent `finding_id` → 404 via `NotFoundError`.
  - Re-PATCHing an already-`CONFIRMED` `Finding` to `"false_positive"` succeeds (the unrestricted-transitions decision) and the new note **replaces** the old one, even when the new call omits `validation_note` (locks in the "full replace, never merge" semantics from §4 — this is the one subtlety most worth a dedicated test, since the natural/wrong implementation is `exclude_unset`-style merging).
  - Setting `validation_state` back to `"unvalidated"` clears both `validation_note` and `validated_at` to `null` (the "undo" semantics).
- **Extend the Phase 3/4 scan-assets route test** (`test_scan_assets_route.py`/`test_scans.py`): a freshly-seeded `Finding` (via the `db` fixture, not through correlation) shows `confidence_score` as whatever was explicitly set, `validation_state="unvalidated"`, `validation_note=null`, `validated_at=null` by default in the `GET /scans/{id}/assets` response — confirming the new `FindingRead` fields round-trip through the existing nested-findings endpoint with no extra wiring needed.

---

## 7. Verification Plan

Reuses Phase 4's exact seeded-`Service`-with-known-CPE verification approach (`cpe:/a:apache:http_server:2.4.49`, CVE-2021-41773) — this time seeding `evidence["method"]`/`evidence["conf"]` explicitly so the expected `confidence_score` is known ahead of time, then exercising the new PATCH endpoint against the real, running backend.

```bash
docker compose up --build
docker compose exec backend alembic upgrade head

# --- 1. Seed a Service with KNOWN method/conf evidence, run real correlation ---
docker compose exec backend python -c "
from app.db.session import SessionLocal
from app.models.project import Project
from app.models.target import Target, TargetType
from app.models.scan import Scan, ScanStatus
from app.models.asset import Asset
from app.models.service import Service
from app.modules.vulnerability.correlator import correlate_services
import redis
from app.core.config import get_settings

db = SessionLocal()
project = Project(name='Phase 5 verification')
db.add(project); db.flush()
target = Target(project_id=project.id, value='127.0.0.1', target_type=TargetType.IP, authorization_confirmed=True)
db.add(target); db.flush()
scan = Scan(project_id=project.id, target_id=target.id, status=ScanStatus.CORRELATING)
db.add(scan); db.flush()
asset = Asset(project_id=project.id, target_id=target.id, scan_id=scan.id, host='127.0.0.1')
db.add(asset); db.flush()
# method='probed', conf='10' -> expected confidence_score == 100.0 per confidence.py
service = Service(asset_id=asset.id, port=80, protocol='tcp', state='open',
                   fingerprint_source='nmap-sv',
                   evidence={'cpe': ['cpe:/a:apache:http_server:2.4.49'], 'method': 'probed', 'conf': '10'})
db.add(service); db.commit()

redis_client = redis.Redis.from_url(get_settings().REDIS_URL)
correlate_services(db, redis_client, [service])
db.commit()
print('scan_id:', scan.id, 'service_id:', service.id)
"
# note the printed scan_id / service_id for the queries below

# --- 2. Confirm confidence_score matches the formula's expected output exactly ---
docker compose exec postgres psql -U vulnsight -d vulnsight -c \
  "SELECT id, cve_id, confidence_score, validation_state, validated_at FROM findings WHERE service_id = '<service_id>';"
# expect confidence_score = 100.0 for every row (method=probed, conf=10 -> PROBED_FLOOR(50) + 10*PROBED_CONF_SCALE(5) = 100)
# expect validation_state = 'unvalidated', validated_at = NULL for every row (defaults, untouched by correlation)

# --- 3. Mark one Finding FALSE_POSITIVE with a note, via the real API ---
curl -s -X PATCH http://localhost:8000/api/v1/findings/<finding_id> \
  -H "Content-Type: application/json" \
  -d '{"validation_state": "false_positive", "validation_note": "internal test host, not a real exposure"}' | python -m json.tool
# expect the response body to include:
#   "validation_state": "false_positive"
#   "validation_note": "internal test host, not a real exposure"
#   "validated_at": "<a real non-null ISO timestamp, close to now>"
#   "confidence_score": 100.0  (unchanged -- validation never touches scoring)

# --- 4. Confirm the change persisted in Postgres, not just in the response body ---
docker compose exec postgres psql -U vulnsight -d vulnsight -c \
  "SELECT validation_state, validation_note, validated_at FROM findings WHERE id = '<finding_id>';"

# --- 5. Confirm an invalid validation_state is rejected with 422, not silently accepted ---
curl -s -o /dev/null -w "%{http_code}\n" -X PATCH http://localhost:8000/api/v1/findings/<finding_id> \
  -H "Content-Type: application/json" -d '{"validation_state": "bogus"}'
# expect 422

# --- 6. Confirm transitioning back to UNVALIDATED clears the note and timestamp ---
curl -s -X PATCH http://localhost:8000/api/v1/findings/<finding_id> \
  -H "Content-Type: application/json" -d '{"validation_state": "unvalidated"}' | python -m json.tool
# expect "validation_note": null, "validated_at": null

# --- 7. Re-confirm it (undoing step 6), for the frontend walkthrough below ---
curl -s -X PATCH http://localhost:8000/api/v1/findings/<finding_id> \
  -H "Content-Type: application/json" \
  -d '{"validation_state": "false_positive", "validation_note": "internal test host, not a real exposure"}'

# --- 8. New results shape via the existing nested-findings endpoint ---
curl -s http://localhost:8000/api/v1/scans/<scan_id>/assets | python -m json.tool
# expect the port-80 service's findings[] entries to include confidence_score,
# validation_state="false_positive" (for the one PATCHed above), validation_note, validated_at

# --- 9. Frontend ---
# open http://localhost:3000/projects/<projectId>/scans/<scanId> -- confirm:
#   - every finding row shows "Confidence: 100/100" next to its CVSS score
#   - the PATCHed finding's CVE id is struck through, the row is dimmed, and a
#     muted "False Positive" badge appears
#   - the FindingValidationControl's <select> on that row already shows
#     "False Positive" selected, with the note pre-filled in its text input
#   - changing the select to "Confirmed" and clicking Save updates the badge/
#     styling in place after the page refresh (no full reload needed, no stale UI)

docker compose exec backend pytest -v
docker compose exec backend ruff check . && black --check . && mypy app
docker compose exec frontend npm run lint && npx tsc --noEmit
```

---

## Roadmap Beyond This Plan (not detailed here)

- **Phase 6 — Misconfiguration Analysis**: TLS/header misconfiguration checks, orthogonal to confidence/validation — unrelated to this phase's `Finding`-table additions.
- **Phase 7 — Risk Intelligence**: the first real consumer of `confidence_score` and `validation_state` together with `severity`/`cvss_score` — e.g. discounting a `Finding`'s contribution to an overall risk score by its confidence, and likely excluding (or heavily discounting) `FALSE_POSITIVE`-marked findings from that score entirely. Explicitly not designed here — this phase only produces the two raw inputs Phase 7 will combine.
- **Phase 8 — Reporting**: likely the first consumer that cares about `validated_at`/`validation_note` as human-readable provenance in a generated report ("this finding was reviewed and confirmed by an operator on <date>, with the note: ...").
- Deferred within this phase's own mechanisms, for a later pass if ever prioritized: a bulk/batch validation-state-setting endpoint (if single-finding-at-a-time ever becomes a real workflow bottleneck); any kind of audit log beyond `validated_at` (would require this project's first user/auth system, out of scope for any phase on the current roadmap); automatic confidence-driven false-positive suggestions (a human-assist heuristic layered on top of the raw score, not the score itself); re-weighting the confidence formula's constants once real-world usage shows the bands need adjusting (the formula in `confidence.py` is a judgment call, explicitly documented as one, not a value this plan claims is provably optimal).
