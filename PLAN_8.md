# PLAN_8.md — VulnSight Phase 8: Reporting

Narrative plan. Binding authority for anything `PLAN_8_TASKS.md` doesn't
fully specify. Companion: `PLAN_8_TASKS.md` (task breakdown used for
execution).

**Architecture decisions below were made directly by the controller**,
not through the usual brainstorming conversation — the user opted out
("lets keep moving", following the same pattern as Phase 6's "i would
rather you pick" and Phase 7's "continue") before the opening question
was answered. Every call below is therefore flagged as a controller
judgment, not a user-confirmed requirement, exactly as Phase 6/7's
equivalent calls were.

## Why this phase, and what it actually produces

The last item on the project's original roadmap (`CLAUDE.md`'s own
"Phase 8+ (reporting) — not started" entry): a self-contained report
that consumes everything built in Phases 1-7 — assets, services,
findings (severity/cvss/confidence/validation), misconfigurations, and
Phase 7's risk score/tier — and presents it as one document, rather than
requiring a reader to piece it together from the live results page.

Runs in `ScanStatus.REPORT_GENERATION`, reserved-but-unused in the enum
since Phase 1, immediately after `RISK_ANALYSIS`
(`backend/app/models/scan.py:26`) — exactly the same "slot already
exists, this phase finally wires it up" precedent as `ANALYZING` was for
Phase 6 and `RISK_ANALYSIS` was for Phase 7. **This is the last reserved
slot in the enum** — once this phase lands, every `ScanStatus` value is
wired to real behavior; there is no more "falls straight through"
stage left for a future phase to inherit.

**Zero new network/Redis surface, zero new runtime dependency.** Like
Phase 7, this phase reads only already-persisted `Asset`/`Service`/
`Finding`/`Misconfiguration`/`Scan` rows and writes one new table — no
outbound call, no new Python package. Notably: **no PDF-generation
library**. "Exportable" is satisfied by (a) the report's own API
response, which is already a complete JSON document, and (b) a
dedicated, print-formatted frontend page a reader exports via their
browser's native print-to-PDF — not a server-rendered file. This mirrors
the project's consistent discipline of not adding a dependency unless
something structurally requires it (contrast Phase 6's `cryptography`,
which genuinely was required for TLS inspection); nothing about a report
page structurally requires a server-side PDF renderer.

## Controller's architecture calls

1. **A report is a new, persisted, standalone resource — one `Report`
   row per `Scan` — not a computed-on-read aggregate and not new columns
   bolted onto `Scan`.** New model `backend/app/models/report.py`:
   `id`, `scan_id` (FK to `scans.id`, `ondelete="CASCADE"`, **unique** —
   enforces one report per scan at the DB level), `summary` (JSONB,
   the full report content), `generated_at`. This follows two existing
   precedents at once: Phase 7's "persisted once during the pipeline,
   not recomputed on every read" choice for `risk_score`, and Phase 6's
   "deliberately a standalone model, not crammed onto an existing one"
   choice for `Misconfiguration`. A report is a richer, nested document
   (per-asset/per-service findings and misconfigs, not a scalar), which
   is exactly the shape JSONB — not a pile of new scalar columns — is
   for; this mirrors `Finding.evidence`/`Service.evidence`/
   `Misconfiguration.evidence`'s own existing convention of "a JSONB
   column is the source of truth for a nested document; don't force it
   into many scalar columns." No `scan.report` ORM relationship is added
   — `Report` is reached by a direct `scan_id` query in the service
   layer, the same restraint `Misconfiguration` shows by not getting an
   `Asset`-level backref (only a `Service`-level one).
2. **Content: a full structured document, not just summary counts.**
   `summary` includes the target, the scan's own risk score/tier,
   aggregate counts (findings by severity and by validation state,
   misconfigurations by severity), and a full per-asset → per-service
   breakdown of every finding (`cve_id`/`severity`/`cvss_score`/
   `confidence_score`/`validation_state`) and misconfiguration
   (`check_id`/`title`/`severity`/`description`). This is a controller
   judgment call: the project's own framing ("Evidence-Based
   Vulnerability Assessment & Risk Prioritization Platform") implies a
   report is a leave-behind document someone can read without the live
   app, not just a dashboard tile — a report that only had counts would
   fail that purpose. **Deliberately excludes raw `evidence` JSONB
   blobs** (nmap XML attributes, HTTP headers, NVD's raw CVE subtree,
   TLS certificate details) — those stay queryable via the existing
   `GET /scans/{id}/assets` endpoint for anyone who wants to dig in; a
   report is a readable summary document, not a second copy of every
   byte of raw evidence.
3. **Generated once, during the pipeline, like `risk_score` — never
   regenerated.** `generate_report` runs exactly once, in
   `REPORT_GENERATION`, and is never re-triggered (no "regenerate"
   endpoint, no re-run on a later `PATCH /findings/{id}`). This is the
   same accepted-staleness limitation Phase 7 already established for
   `risk_score`/`confidence_score`: a report, once generated, is a
   snapshot of the data at that moment, and a later validation-state
   change does not retroactively update it. Not a new kind of gap —
   the same one, extended to a third mechanism.
4. **`GET /scans/{id}/report` returns 404 when no `Report` exists yet,
   not a nullable field on an existing resource.** Unlike Phase 7's
   `risk_score`/`risk_tier` (nullable columns on an always-present row),
   a `Report` is its own resource that may simply not exist yet (the
   scan hasn't reached `REPORT_GENERATION`, or genuinely never will — a
   `CIDR`-rejected or otherwise-`FAILED` scan never gets one). A clean
   404 via the existing `NotFoundError` → HTTP-mapping pattern is the
   right REST-ism here, not a new null-handling convention.
5. **Export is a printable frontend page, not a server-rendered file.**
   A new route, `/projects/[projectId]/scans/[scanId]/report`, formatted
   for both on-screen reading and browser print-to-PDF (Tailwind's
   `print:` variants hiding navigation/buttons in the print view). This
   decision was made without the user's input on the exact "read on
   screen vs. hand to someone else" framing question (the brainstorming
   conversation was opted out of before that question was answered) —
   the controller's call is "both, via the same page," since a
   print-formatted screen page satisfies both without forcing a choice
   or adding a new dependency.

## Scope limits (explicit, not gaps)

- **No PDF-generation dependency.** See above.
- **No report regeneration/versioning.** One `Report` per `Scan`,
  generated once, never updated. A `uq`-style unique constraint on
  `scan_id` enforces this at the DB level, the same defensive-dedup
  posture as `uq_misconfig_service_check`.
- **No report customization (templates, selected sections, branding).**
  One fixed shape this phase.
- **No change to `Asset`/`Scan`'s existing risk-scoring behavior.** This
  phase reads `scan.risk_score`/`risk_tier` and every asset's own
  `risk_score`/`risk_tier` as already persisted by Phase 7 — it does not
  recompute or touch them.
- **No new `ScanStatus` value** — the slot already exists, and this is
  the last one.
- **No changes to `discovery/`, `fingerprinting/`, `vulnerability/`,
  `misconfiguration/`, or `risk/` modules.** This phase only reads their
  already-persisted output.

## §1 Migration: new `reports` table

New model, `backend/app/models/report.py`:

```python
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
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    summary: Mapped[dict] = mapped_column(JSONB, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
```

Migration (`backend/migrations/versions/`, new file): purely additive
`create_table`, mirroring the shape of `60f5828d656a_add_misconfigurations_table.py`:

```python
op.create_table('reports',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('scan_id', sa.Uuid(), nullable=False),
    sa.Column('summary', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('generated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
)
op.create_index(op.f('ix_reports_scan_id'), 'reports', ['scan_id'], unique=True)
```

`down_revision` = current head. Confirmed by directly reading every file
in `backend/migrations/versions/` while writing this plan: `111ce3c92341`
→ `26de1feba77b` → `d6b7d6e6b8c8` → `45f7e770cdbb` → `8f08312a037b` →
`60f5828d656a` → `0bb42fc08c11` (head, Phase 7's migration) — a single
linear chain, no branching. Re-verify this is still the head before
generating the new revision.

## §2 Pure report-building function

`backend/app/modules/reporting/report_builder.py` (new) — a pure
function, no DB session, no network, mirroring `scoring.py`'s "every
branch produces a concrete value, never raises" discipline (the package
already exists as an empty placeholder —
`backend/app/modules/reporting/__init__.py`):

```python
from app.models.asset import Asset
from app.models.scan import Scan


def build_report_summary(scan: Scan, assets: list[Asset]) -> dict:
    """Assemble the full report document for `scan` from its `assets`
    (each already carrying its own services -> findings/misconfigurations
    via the existing ORM relationships, exactly as risk_scorer.py already
    traverses them). Pure: no DB write, no network. Deliberately excludes
    every Service/Finding/Misconfiguration's raw `evidence` JSONB -- a
    report is a readable summary, not a second copy of raw evidence
    (still reachable via GET /scans/{id}/assets for anyone who wants it).
    """
    findings_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
    findings_by_validation_state = {"unvalidated": 0, "confirmed": 0, "false_positive": 0}
    misconfigs_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
    findings_total = 0
    misconfigs_total = 0
    asset_entries = []

    for asset in assets:
        service_entries = []
        for service in asset.services:
            finding_entries = []
            for finding in service.findings:
                findings_total += 1
                findings_by_severity[finding.severity] = findings_by_severity.get(finding.severity, 0) + 1
                findings_by_validation_state[finding.validation_state.value] += 1
                finding_entries.append({
                    "cve_id": finding.cve_id,
                    "severity": finding.severity,
                    "cvss_score": finding.cvss_score,
                    "confidence_score": finding.confidence_score,
                    "validation_state": finding.validation_state.value,
                })

            misconfig_entries = []
            for misconfig in service.misconfigurations:
                misconfigs_total += 1
                misconfigs_by_severity[misconfig.severity] = misconfigs_by_severity.get(misconfig.severity, 0) + 1
                misconfig_entries.append({
                    "check_id": misconfig.check_id,
                    "title": misconfig.title,
                    "severity": misconfig.severity,
                    "description": misconfig.description,
                })

            service_entries.append({
                "port": service.port,
                "protocol": service.protocol,
                "service_name": service.service_name,
                "product": service.product,
                "version": service.version,
                "findings": finding_entries,
                "misconfigurations": misconfig_entries,
            })

        asset_entries.append({
            "host": asset.host,
            "risk_score": asset.risk_score,
            "risk_tier": asset.risk_tier,
            "services": service_entries,
        })

    return {
        "target": {"value": scan.target.value, "target_type": scan.target.target_type.value},
        "risk": {"score": scan.risk_score, "tier": scan.risk_tier},
        "findings_summary": {
            "total": findings_total,
            "by_severity": findings_by_severity,
            "by_validation_state": findings_by_validation_state,
        },
        "misconfigurations_summary": {
            "total": misconfigs_total,
            "by_severity": misconfigs_by_severity,
        },
        "assets": asset_entries,
    }
```

(Implementer: confirm `TargetType`'s exact member access pattern — e.g.
whether `.value` is needed or the enum already serializes as the plain
string elsewhere — by reading `app/models/target.py` directly rather
than trusting this sketch verbatim.)

## §3 `report_generator.py` orchestrator + `REPORT_GENERATION` stage wiring

`backend/app/modules/reporting/report_generator.py` (new):

```python
def generate_report(db: Session, scan: Scan, assets: list[Asset]) -> None:
    """Best-effort: build and persist exactly one Report row for `scan`.

    Unlike risk_scorer.py's per-Asset loop, there is exactly one derived
    object here -- the report as a whole -- so one try/except covers the
    full build+persist, not one per asset. Never touches scan.status
    (same inherited rule as every other best-effort stage in this
    project); never raises past this function.
    """
    try:
        summary = build_report_summary(scan, assets)
        report = Report(scan_id=scan.id, summary=summary)
        db.add(report)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("generate_report: report generation failed for scan %s", scan.id)
```

Edit `backend/app/workers/tasks.py`: insert a new stage between the
existing `RISK_ANALYSIS` block and the existing `COMPLETED` line —
re-verify the real current step numbers/line numbers directly in the
file before editing, do not trust stale references from this plan:

```python
# Step N (Phase 8): REPORT_GENERATION. Same best-effort shape as every
# prior post-discovery stage: report-generation failures must never fail
# the scan, so any exception here is logged and swallowed -- no
# scan.status mutation, no return, always falls through to COMPLETED
# below. This is the last slot the ScanStatus enum reserved -- after
# this stage, every enum value is wired to real behavior.
scan.status = ScanStatus.REPORT_GENERATION
db.commit()
try:
    generate_report(db, scan, [asset])
except Exception:
    db.rollback()
    logger.exception("run_scan_task: scan %s report generation failed", scan_id)
```

`asset` is the same single `Asset` ORM object already in scope from
Steps 5-7, reused exactly as `score_assets(db, scan, [asset])` already
is one stage earlier.

## §4 API additions

New `backend/app/schemas/report.py`:

```python
class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    summary: dict
    generated_at: datetime
```

New `backend/app/services/report_service.py`:

```python
def get_report(db: Session, scan_id: uuid.UUID) -> Report:
    get_scan(db, scan_id)  # raises NotFoundError if the scan itself doesn't exist
    report = db.query(Report).filter(Report.scan_id == scan_id).first()
    if report is None:
        raise NotFoundError(f"Report for scan {scan_id} not found")
    return report
```

New route on the existing scans router (`backend/app/api/routes/scans.py`):

```python
@router.get("/{scan_id}/report", response_model=ReportRead)
def get_scan_report(scan_id: uuid.UUID, db: Session = Depends(get_db)) -> Report:
    return report_service.get_report(db, scan_id)
```

## §5 Frontend additions

New `frontend/src/lib/types/report.ts` — hand-maintained mirror of
`report_builder.py`'s actual output shape (the backend's `summary` field
is a passthrough `dict`, not independently validated by Pydantic — same
convention as `evidence`'s `Record<string, unknown>` typing elsewhere; a
future backend-side shape change must be mirrored here by hand, there is
no schema to regenerate from):

```typescript
import type { Severity, ValidationState } from "./finding";

export interface ReportSummary {
  target: { value: string; target_type: string };
  risk: { score: number | null; tier: Severity | null };
  findings_summary: {
    total: number;
    by_severity: Record<Severity, number>;
    by_validation_state: Record<ValidationState, number>;
  };
  misconfigurations_summary: {
    total: number;
    by_severity: Record<Severity, number>;
  };
  assets: Array<{
    host: string;
    risk_score: number | null;
    risk_tier: Severity | null;
    services: Array<{
      port: number;
      protocol: string;
      service_name: string | null;
      product: string | null;
      version: string | null;
      findings: Array<{
        cve_id: string;
        severity: Severity;
        cvss_score: number | null;
        confidence_score: number;
        validation_state: ValidationState;
      }>;
      misconfigurations: Array<{
        check_id: string;
        title: string;
        severity: Severity;
        description: string;
      }>;
    }>;
  }>;
}

export interface ReportRead {
  id: string;
  scan_id: string;
  summary: ReportSummary;
  generated_at: string;
}
```

New `frontend/src/lib/api/scans.ts` function:

```typescript
/** GET /scans/{id}/report — 404 until the scan reaches REPORT_GENERATION. */
export function getScanReport(scanId: string): Promise<ReportRead> {
  return request<ReportRead>(`/scans/${scanId}/report`);
}
```

New page, `frontend/src/app/projects/[projectId]/scans/[scanId]/report/page.tsx`
— a server component, same `try { ... } catch` 404-vs-network-error
split `page.tsx` already uses for `getScan`. Renders: target + generated
timestamp header; the scan's own risk badge; findings-by-severity and
by-validation-state counts; misconfigurations-by-severity counts; a
per-asset → per-service breakdown of every finding/misconfiguration
reusing the existing `SeverityBadge`/`ValidationBadge` components
unchanged. A small new client component,
`frontend/src/components/PrintButton.tsx` (`"use client"`, a single
`<button onClick={() => window.print()}>`), plus Tailwind `print:hidden`
on navigation/buttons so the printed/exported page is just the report
content.

Edit the existing
`frontend/src/app/projects/[projectId]/scans/[scanId]/page.tsx`: add a
"View report" link next to the existing "Back to project" link, shown
only when `scan.status === "completed"` (the only point at which a
`Report` is guaranteed to exist, since `REPORT_GENERATION` runs
immediately before `COMPLETED`).

## §6 Testing strategy

- `report_builder.py`: construct `Scan`/`Target`/`Asset`/`Service`/
  `Finding`/`Misconfiguration` objects directly in-memory (no DB session
  needed, same pattern as `test_scoring.py`) — a scan with one finding
  of each severity and one of each validation state produces correct
  `by_severity`/`by_validation_state` counts; a `FALSE_POSITIVE` finding
  still appears in the detailed per-service list (never dropped) but is
  correctly counted; one misconfiguration of each severity produces
  correct counts; an asset with zero findings/misconfigs produces an
  entry with empty lists and all-zero counts, not an error; multi-asset/
  multi-service input nests correctly.
- `report_generator.py`
  (`backend/tests/test_report_generator.py`, new): a successful call
  persists exactly one `Report` row with the expected `scan_id`/
  `summary`; a forced failure (monkeypatch `build_report_summary` to
  raise) leaves no `Report` row created and does not raise past
  `generate_report`; calling it twice for the same scan (simulating a
  hypothetical re-run) fails the second commit against the
  `scan_id` unique index and is swallowed by the same try/except,
  leaving the original `Report` row untouched — the unique constraint's
  defensive-dedup role, exercised not just asserted.
- `test_scan_orchestration.py` (extend): a full `run_scan_task` run
  reaches `COMPLETED` with exactly one `Report` row persisted for that
  scan; a monkeypatched-to-raise `generate_report` still reaches
  `COMPLETED`, not `FAILED` — the best-effort contract, exercised.
- `test_reports.py` (new, API-level): `GET /scans/{id}/report` returns
  404 for a scan that hasn't reached `REPORT_GENERATION` yet (e.g. a
  freshly-created scan fixture); 200 with the expected `summary` shape
  after a full scan run.

## §7 Verification plan

Fresh migration against a database with pre-existing `Scan` rows —
confirm no existing row gets a spurious `Report`. A real scan producing
at least one `Finding` of a few different severities/validation states
and at least one `Misconfiguration` — confirm the persisted `Report.summary`
matches a hand-computed expectation from the same raw data. Confirm
`GET /scans/{id}/report` returns 404 before the scan completes and 200
with the correct body after. Confirm the new report page renders
correctly on screen and that its print-formatted view (Tailwind
`print:` classes) hides navigation/buttons as intended. Confirm the
existing results page's new "View report" link appears only once the
scan is `completed`. Full backend+frontend lint/type/test suites green.
