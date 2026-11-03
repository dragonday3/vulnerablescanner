"""add finding confidence and validation columns

Revision ID: 8f08312a037b
Revises: 45f7e770cdbb
Create Date: 2026-11-03 03:24:15.381053

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '8f08312a037b'
down_revision: Union[str, Sequence[str], None] = '45f7e770cdbb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# --- Inlined, self-contained copy of
# backend/app/modules/vulnerability/confidence.py's compute_confidence()
# logic (that module doesn't exist until Phase 5's Task 2, and even once
# it does, migrations must never import application code -- app code can
# change shape after a migration is written and frozen, which would
# silently change what this historical backfill computes if it were
# imported instead of copied). This copy must keep producing the exact
# same results as confidence.py for the same (method, conf) inputs, but
# is deliberately independent of it.
PROBED_FLOOR = 50.0
PROBED_CONF_SCALE = 5.0
PROBED_MISSING_CONF_DEFAULT = 75.0
TABLE_CEILING = 45.0
TABLE_CONF_SCALE = TABLE_CEILING / 10.0  # 4.5
TABLE_MISSING_CONF_DEFAULT = 20.0
METHOD_MISSING_SCORE = 10.0


def _parse_conf(raw: object) -> int | None:
    if raw is None:
        return None
    try:
        value = int(str(raw))
    except (TypeError, ValueError):
        return None
    return max(0, min(10, value))


def _compute_confidence_from_evidence(evidence: dict) -> float:
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
    return METHOD_MISSING_SCORE


def upgrade() -> None:
    """Upgrade schema."""
    # Add nullable-with-no-default first -- there is no meaningful
    # default for pre-existing rows (see PLAN_5.md #2), so every
    # pre-existing row gets a real, formula-derived value via the
    # one-time backfill below before the column is tightened to NOT
    # NULL.
    op.add_column('findings', sa.Column('confidence_score', sa.Float(), nullable=True))

    # One-time backfill for any pre-existing rows, computed from each
    # row's already-persisted Service.evidence via the same formula
    # confidence.py uses going forward -- NOT an ongoing recompute
    # mechanism (see PLAN_5.md's "no re-computation" scope limit); this
    # runs exactly once, now, because the column is new, not because
    # Service.evidence ever changed after the fact. A no-op over an
    # empty result set is fine and expected on a fresh database.
    connection = op.get_bind()
    rows = connection.execute(
        sa.text("SELECT f.id, s.evidence FROM findings f JOIN services s ON s.id = f.service_id")
    ).fetchall()
    for finding_id, evidence in rows:
        score = _compute_confidence_from_evidence(evidence or {})
        connection.execute(
            sa.text("UPDATE findings SET confidence_score = :score WHERE id = :id"),
            {"score": score, "id": finding_id},
        )
    op.alter_column('findings', 'confidence_score', nullable=False)

    finding_validation_state = postgresql.ENUM(
        'unvalidated', 'confirmed', 'false_positive', name='finding_validation_state'
    )
    finding_validation_state.create(op.get_bind())
    op.add_column(
        'findings',
        sa.Column(
            'validation_state',
            finding_validation_state,
            nullable=False,
            server_default='unvalidated',
        ),
    )
    op.add_column('findings', sa.Column('validation_note', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('validated_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('findings', 'validated_at')
    op.drop_column('findings', 'validation_note')
    op.drop_column('findings', 'validation_state')
    op.drop_column('findings', 'confidence_score')
    sa.Enum(name='finding_validation_state').drop(op.get_bind(), checkfirst=True)
