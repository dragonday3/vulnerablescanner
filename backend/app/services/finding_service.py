"""Finding-level service functions (Phase 5). Deliberately thin and
single-purpose -- the only write operation this phase introduces is
setting a Finding's validation state. Everything else about a Finding
(creation, scoring) happens in correlator.py/confidence.py, upstream of
this module, during correlation -- this file never constructs a Finding,
only mutates an existing one's validation fields.
"""

import uuid
from datetime import UTC, datetime

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
