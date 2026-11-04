# PLAN_8_TASKS.md — VulnSight Phase 8 Task-Based Execution Plan

Companion to `PLAN_8.md` (narrative plan, binding authority for anything
a task here doesn't fully specify).

Scope: Phase 8 (Reporting) only — the new `reports` table, the pure
`report_builder.py` function, the `report_generator.py` orchestrator
wired into the already-reserved `ScanStatus.REPORT_GENERATION` stage,
the read-only `GET /scans/{id}/report` endpoint, and the new frontend
report page. No report regeneration, no PDF-generation dependency, no
changes to any earlier phase's scoring/detection logic.

## Global Constraints

1. **Migration-first ordering.** Task 1 (the `reports` table + `Report`
   model) must land before Task 3 (the orchestrator writes into it) and
   Task 4 (the API reads it).
2. **Zero new network/Redis surface, zero new runtime dependency.** This
   phase reads only already-persisted `Scan`/`Target`/`Asset`/`Service`/
   `Finding`/`Misconfiguration` rows and writes to one new table. If any
   file in this phase opens a socket, makes an HTTP/other request,
   touches Redis, or adds a new third-party package (a PDF-generation
   library most of all) — that is a Critical finding, not a style
   nitpick. "Exportable" is satisfied by the JSON API response plus a
   print-formatted frontend page (browser print-to-PDF), never a
   server-rendered file.
3. **No changes to `discovery/`, `fingerprinting/`, `vulnerability/`,
   `misconfiguration/`, or `risk/` modules.** This phase reads their
   persisted output only (`Finding`, `Misconfiguration`,
   `Asset.risk_score`/`risk_tier`, `Scan.risk_score`/`risk_tier` via
   existing relationships/columns) and writes exclusively to the new
   `reports` table.
4. **`report_generator.py`'s `generate_report` never touches
   `scan.status`.** Same inherited rule as `risk_scorer.py`/
   `correlator.py`/`analyzer.py`: this module's job is writing its own
   new row, not the scan's status machine. Any write to `scan.status`
   inside `backend/app/modules/reporting/` is a Critical finding.
5. **Report-generation failures can never flip a scan to `FAILED`.**
   Same best-effort contract as every stage since `FINGERPRINTING` —
   `tasks.py`'s new `REPORT_GENERATION` block catches, logs, rolls back,
   and falls through to `COMPLETED` regardless.
6. **Exactly one `Report` row per `Scan`, enforced by a unique index on
   `scan_id`.** `generate_report` is only ever invoked once per scan's
   lifecycle (the `REPORT_GENERATION` stage, once); the unique
   constraint is a defensive backstop (mirrors
   `uq_misconfig_service_check`'s own role), not a feature to build a
   workflow around. No regenerate/update endpoint.
7. **`GET /scans/{id}/report` returns 404 (via the existing
   `NotFoundError` → HTTP mapping) when no `Report` row exists yet for
   that scan.** This is a different null-handling shape than Phase 7's
   nullable columns, deliberately — `Report` is its own resource, not a
   field on an always-present row. Don't invent a 200-with-null-body
   alternative.
8. **`Report.summary` is a passthrough JSONB `dict`**, same convention
   as `Finding.evidence`/`Service.evidence`/`Misconfiguration.evidence`
   — not a strict nested Pydantic model on the backend. The frontend's
   `ReportSummary` TS interface (`frontend/src/lib/types/report.ts`) is
   a hand-maintained mirror of `report_builder.py`'s actual output
   shape, not independently enforced by either side — if `report_builder.py`'s
   shape changes, that file must be updated by hand in the same task.
9. **The report excludes every raw `evidence` JSONB blob** (nmap/HTTP/
   NVD/TLS raw evidence) — it carries only the structured summary fields
   named in `PLAN_8.md` §2. Don't "helpfully" include raw evidence inline;
   it stays reachable via the existing `GET /scans/{id}/assets` endpoint.
10. **No report regeneration, no re-trigger on a later
    `PATCH /findings/{id}`.** Same accepted-staleness limitation Phase 7
    already established for `risk_score`/`confidence_score` — a
    generated report is a point-in-time snapshot, not a live view.
11. **No new `ScanStatus` value, no bulk/manual regenerate endpoint.**
    The slot already exists and this is the last one — don't add
    anything "for completeness."
12. Follow established Phase 0-7 conventions: thin routes, business
    logic in `services`/`modules`, SQLAlchemy 2.x `Mapped`/
    `mapped_column` style, ruff/black/mypy clean on backend, `next lint`/
    `tsc --noEmit` clean on frontend, migrations never import
    application code (trivial here: pure `CREATE TABLE`, no backfill).

---

## Task 1: `reports` table + `Report` model + migration

Create `backend/app/models/report.py` exactly per `PLAN_8.md` §1. Generate
an additive migration (`down_revision` = current head — re-verify it's
still `0bb42fc08c11` by reading `backend/migrations/versions/` directly
before generating; the plan's own stated value may be stale by the time
this task runs):
`alembic revision --autogenerate -m "add reports table"`. No hand-edit
should be needed beyond possibly correcting the unique-index shape
(`PLAN_8.md` §1's exact DDL) — if the autogenerated migration contains
anything beyond creating the `reports` table, review it carefully before
accepting it as-is.

**Tests**: none standalone beyond a smoke check (covered by Task 3/4's
tests exercising the new table via the ORM/API).

**Acceptance**: migration applies cleanly against a database carrying
pre-existing `Scan` rows, with no row gaining a spurious `Report`
(confirm via `docker compose exec postgres psql -U vulnsight -d
vulnsight -c "\d reports"` showing the table, its unique index on
`scan_id`, and the FK with `ON DELETE CASCADE`); `ruff`/`black`/`mypy`
clean.

---

## Task 2: Pure report-building function

Create `backend/app/modules/reporting/report_builder.py`
(`build_report_summary`), per `PLAN_8.md` §2's exact spec. Pure function
— no DB session, no network, never raises. Not wired into `tasks.py` yet
(Task 3 does that) — it just needs to exist and be independently correct
and tested. Read `app/models/target.py` directly before writing the
`target_type` access, rather than trusting the plan's sketch verbatim.

**Tests** (`backend/tests/test_report_builder.py`, new): construct
`Scan`/`Target`/`Asset`/`Service`/`Finding`/`Misconfiguration` objects
directly in-memory per `PLAN_8.md` §6's first bullet — correct
`by_severity`/`by_validation_state` counts, a `FALSE_POSITIVE` finding
still appearing in the detailed list but correctly counted, correct
misconfiguration counts, an asset with zero findings/misconfigs
producing empty-but-present lists (not an error, not an omitted asset),
and correct nesting for multi-asset/multi-service input.

**Acceptance**: `pytest -v` green; every documented behavior in
`PLAN_8.md` §2/§6 covered by at least one test; `ruff`/`black`/`mypy`
clean; no test touches Redis/network/DB.

---

## Task 3: `report_generator.py` orchestrator + `REPORT_GENERATION` stage wiring

Create `backend/app/modules/reporting/report_generator.py`
(`generate_report`), per `PLAN_8.md` §3's exact spec — importing
`build_report_summary` from Task 2 and the new `Report` model from
Task 1.

Edit `backend/app/workers/tasks.py`: insert the new `REPORT_GENERATION`
stage between the existing `RISK_ANALYSIS` block and the existing
`scan.status = ScanStatus.COMPLETED` line, per `PLAN_8.md` §3's exact
code shape. Re-read the real current file first — step numbers/line
numbers may have shifted since the plan was written; don't blindly
trust stale line-number references.

**Tests** (`backend/tests/test_report_generator.py`, new): per
`PLAN_8.md` §6's second bullet — a successful call persists exactly one
`Report` row with the expected `scan_id`/`summary`; a forced failure
(monkeypatch `build_report_summary` to raise) leaves no `Report` row
created and does not raise past `generate_report`; calling it twice for
the same scan hits the `scan_id` unique index on the second commit and
is swallowed, leaving the first `Report` row untouched. Extend
`backend/tests/test_scan_orchestration.py` per `PLAN_8.md` §6's third
bullet: a full `run_scan_task` run reaches `COMPLETED` with exactly one
`Report` row persisted; a monkeypatched-to-raise `generate_report` still
reaches `COMPLETED`, not `FAILED`.

**Acceptance**: `pytest -v` green; `ruff`/`black`/`mypy` clean; a scan
producing at least one real `Finding` and one real `Misconfiguration`
ends with exactly one `Report` row whose `summary` matches a
hand-computed expectation (verified via `docker compose exec postgres
psql`), and the scan reaches `COMPLETED`.

---

## Task 4: API + frontend

Create `backend/app/schemas/report.py` (`ReportRead`) and
`backend/app/services/report_service.py` (`get_report`), per
`PLAN_8.md` §4's exact spec. Add the new
`GET /scans/{scan_id}/report` route to the existing
`backend/app/api/routes/scans.py` router — thin, delegating to
`report_service.get_report`.

Create `frontend/src/lib/types/report.ts` (`ReportSummary`, `ReportRead`)
per `PLAN_8.md` §5's exact spec. Add `getScanReport` to
`frontend/src/lib/api/scans.ts`. Create the new page
`frontend/src/app/projects/[projectId]/scans/[scanId]/report/page.tsx`
and the small client component `frontend/src/components/PrintButton.tsx`,
per `PLAN_8.md` §5 — reuse `SeverityBadge`/`ValidationBadge` unchanged,
do not invent parallel badge components. Edit the existing
`frontend/src/app/projects/[projectId]/scans/[scanId]/page.tsx` to add
the "View report" link, shown only when `scan.status === "completed"`.
Touch nothing else on that existing page.

**Tests**: backend — new `backend/tests/test_reports.py` per
`PLAN_8.md` §6's fourth bullet: 404 before `REPORT_GENERATION`, 200 with
correct body after a full run. Frontend — no automated page-test infra
exists this project (consistent with every prior phase); `npm run lint`
/ `npx tsc --noEmit` plus a manual walkthrough, including the print view.

**Acceptance**: `pytest -v` green; `ruff`/`black`/`mypy` clean; `npm run
lint` and `npx tsc --noEmit` clean; manual `curl` of
`GET /scans/{id}/report` against a completed scan shows the expected
summary shape and a 404 against a freshly-created scan; manual
walkthrough of the new report page renders correctly on screen, the
"View report" link appears only once a scan is `completed`, and the
browser print preview (Tailwind `print:` classes) hides navigation/
buttons as intended.

---

## Task 5: Full-stack verification pass

Fresh `docker compose down -v && docker compose up --build`. Apply the
migration. Run `PLAN_8.md` §7's full Verification Plan end-to-end: a
real scan producing findings across a few different severities/
validation states (including at least one `FALSE_POSITIVE`, set via the
existing Phase 5 `PATCH /findings/{id}` endpoint before the scan — report
generation isn't re-triggered on a later `PATCH`, so the false-positive
case must exist before the `REPORT_GENERATION` stage runs, same
constraint Phase 7's Task 5 worked around for its own false-positive
case) and at least one `Misconfiguration` — confirm the persisted
`Report.summary` matches a hand-computed expectation derived
independently from the same raw DB rows. Confirm no pre-existing
(pre-Phase-8) `Scan` row gained a spurious `Report`. Confirm
`GET /scans/{id}/report` returns 404 before the scan reaches
`REPORT_GENERATION` and 200 with the correct body after. Confirm the
frontend report page renders correctly, including the print view, and
that the results page's "View report" link appears at the right time.
Run the full backend suite and lint/type-check on both sides.

This is not a feature-writing task — fix only narrow integration issues
found (same scope discipline as every prior phase's final task). If
something reveals an architectural gap rather than an integration
correction, report BLOCKED/NEEDS_CONTEXT instead of improvising a
redesign.

**Acceptance**: every step in `PLAN_8.md` §7 passes as described;
`pytest -v`, `ruff check .`, `black --check .`, `mypy app`, `npm run
lint`, `npx tsc --noEmit` all green; report the full transcript/evidence
for the generated report, including the actual persisted `summary` and
the hand-computed expectation it's checked against, so a reviewer can
independently verify correctness.

---

### Critical Files for Implementation

- `backend/app/modules/reporting/report_builder.py` (new — the pure
  function that decides the report's actual content/shape)
- `backend/app/modules/reporting/report_generator.py` (new — the one
  module in this phase allowed to write a `Report` row, never
  `scan.status`)
- `backend/app/models/report.py` (new — the unique `scan_id` index is
  load-bearing, see Global Constraint 6)
- `backend/app/workers/tasks.py` (exact insertion point for the new
  `REPORT_GENERATION` stage between the existing `RISK_ANALYSIS` block
  and `COMPLETED`; must not disturb the FAILED/best-effort invariants
  already there; this is the last reserved `ScanStatus` slot)
- `backend/app/services/report_service.py` (new — the 404-vs-200
  resource-existence check, distinct from Phase 7's nullable-column
  pattern)
- `frontend/src/app/projects/[projectId]/scans/[scanId]/report/page.tsx`
  (new — the only consumer of `ReportSummary`'s hand-maintained shape)
- `frontend/src/app/projects/[projectId]/scans/[scanId]/page.tsx`
  (existing page this phase extends with one new link, nothing else)
