# PLAN_5_TASKS.md — VulnSight Phase 5 Task-Based Execution Plan

Companion to `PLAN_5.md` (narrative plan, binding authority for anything a task here doesn't fully specify).

Scope: Phase 5 (Confidence & Validation) only — `Finding` model additions (`confidence_score`, `validation_state`, `validation_note`, `validated_at`) + migration with one-time backfill, the `compute_confidence` formula + its wiring into `correlator.py`, the validation-state PATCH API (`finding_service.py`, `routes/findings.py`), and the frontend confidence display + validation control. No Phase 6/7 work.

## Global Constraints

1. **Migration-first ordering.** Task 1 (model columns + migration) must land before Task 2 (correlator wiring writes `confidence_score`) and Task 3 (the PATCH route writes `validation_state`/`validation_note`/`validated_at`) — same discipline as every prior phase's Task 1.
2. **Confidence scoring and validation state are independent mechanisms that happen to share a table.** `correlator.py` sets `confidence_score` only, never touches `validation_state`/`validation_note`/`validated_at` (those rely purely on the model's own defaults). `finding_service.update_validation` never touches `confidence_score`. Don't couple the two "while you're in there."
3. **`compute_confidence` is a pure function: no DB session, no Redis, no network, never raises.** Every branch (missing `method`, missing `conf`, unrecognized `method`, out-of-range/non-numeric `conf`) returns a concrete float — there is no path that returns `None` or propagates an exception. A violation here is a correctness bug, not an edge case to "handle later."
4. **Confidence is computed once per `Service`, not once per `Finding`/CVE.** `correlator.py`'s per-CPE `Finding`-construction loop must call `compute_confidence` exactly `len(mapped_services)` times per distinct CPE, reusing the result across that service's multiple `Finding` rows in the inner CVE loop — a regression back into calling it inside the full `(service, cve)` comprehension is wasteful, not just stylistically off.
5. **Validation-state transitions are unrestricted.** Any `FindingValidationState` may move to any other via repeated PATCH calls, including back to `UNVALIDATED`. Don't build a transition-validation state machine "for safety" — PLAN_5.md §4 documents why that's not needed given this project's no-auth, single-operator usage pattern.
6. **`validation_note` is full-replace, never merged.** Every successful PATCH sets `validation_note` to exactly what that call provided (`None` if omitted) — never preserves a prior call's note when the new call doesn't repeat it.
7. **No new `ScanStatus` value, no new Celery stage.** Confidence scoring happens inside Phase 4's existing `CORRELATING` stage; validation-state changes happen entirely outside the scan pipeline, via a standalone API call. Don't touch `backend/app/workers/tasks.py` or `backend/app/models/scan.py` at all this phase.
8. **No bulk/batch validation endpoint, no audit log beyond `validated_at`, no automatic false-positive heuristics.** All per PLAN_5.md's explicit scope-limits section. Don't add any of these "for completeness."
9. **No new runtime dependency, no Redis/NVD/network touched by anything in this phase.** `compute_confidence`, `finding_service.py`, and the PATCH route are all pure-Python/DB-only — if a test for this phase's code needs `TEST_REDIS_URL` or a mocked `httpx` call, something has gone wrong in how it's scoped.
10. **Migrations never import application code.** The one-time `confidence_score` backfill in Task 1's migration file must inline its own copy of the scoring logic, not `from app.modules.vulnerability.confidence import ...` — migrations must stay runnable regardless of later refactors to application modules.
11. **Frontend changes follow existing conventions exactly**: `"use client"` component mirroring `ScanCreateButton.tsx`'s exact state/submit/`router.refresh()` shape; exhaustive-`Record`-with-`Exclude` mapping (`FingerprintBadge.tsx`'s pattern) for `ValidationBadge`; no new chart/meter UI for the confidence number — plain text, matching every other piece of evidence on this page.
12. Follow established Phase 0-4 conventions: thin routes, business logic in `services`/`modules`, `NotFoundError` exception pattern (this phase's only new raise site: `finding_service.get_finding` on an unknown id), SQLAlchemy 2.x `Mapped`/`mapped_column` style, ruff/black/mypy clean on backend, `next lint`/`tsc --noEmit` clean on frontend.

---

## Task 1: `Finding` model columns + migration

Edit `backend/app/models/finding.py`: add `FindingValidationState(str, enum.Enum)` (`UNVALIDATED`/`CONFIRMED`/`FALSE_POSITIVE`) and the four new columns (`confidence_score: float`, NOT NULL; `validation_state`, NOT NULL default `UNVALIDATED`; `validation_note`, nullable; `validated_at`, nullable), per PLAN_5.md §2.

Generate an additive migration (`down_revision` = current head `45f7e770cdbb`): `alembic revision --autogenerate -m "add finding confidence and validation columns"`. Hand-edit the generated file to add the one-time `confidence_score` backfill for any pre-existing `Finding` rows (join to `services.evidence`, apply an inlined copy of the scoring formula, then `alter_column` to NOT NULL) before it's reviewed/applied — per PLAN_5.md §2's exact migration-body sketch. Review the generated enum-type creation for `validation_state` against `d6b7d6e6b8c8`'s `add_column` style.

**Tests**: none standalone beyond a smoke check (covered by Task 2/3's tests exercising the new columns via the ORM/API).

**Acceptance**: migration applies cleanly against a database carrying pre-existing `Finding` rows (seed one manually before running it, to actually exercise the backfill) with no data loss to existing tables/rows; `docker compose exec postgres psql -U vulnsight -d vulnsight -c "\d findings"` shows all four new columns with the documented types/nullability/defaults; every pre-existing row has a non-null, formula-consistent `confidence_score` and `validation_state = 'unvalidated'` after the migration; `ruff`/`black`/`mypy` clean.

---

## Task 2: Confidence-scoring formula + correlator wiring

Create `backend/app/modules/vulnerability/confidence.py` (`compute_confidence`, the `PROBED_*`/`TABLE_*`/`METHOD_MISSING_SCORE` constants, `_parse_conf`), per PLAN_5.md §1.

Edit `backend/app/modules/vulnerability/correlator.py`: import `confidence`, add the per-service `confidence_by_service` dict immediately before the `findings = [...]` comprehension, pass `confidence_score=confidence_by_service[service.id]` into each `Finding(...)` construction, per PLAN_5.md §3. No other change to `correlator.py`'s control flow (commit cadence, per-CPE try/except, outer safety net all untouched).

**Tests** (`backend/tests/test_confidence.py`, new; `backend/tests/test_correlator.py`, extend): per PLAN_5.md §6 — the full `(method, conf)` -> score table including every missing/malformed/out-of-range case, plus the "table band never reaches the probed band" invariant test; a correlator-level test with two services sharing one CPE but different `method`/`conf` evidence asserting each one's `Finding` rows get the correct, service-specific `confidence_score`; a mock-call-count test asserting `compute_confidence` is called exactly once per service regardless of how many CVEs that CPE matches.

**Acceptance**: `pytest -v` green; every branch of `compute_confidence` covered by at least one test; `ruff`/`black`/`mypy` clean; no test in this task's files touches Redis/network (this module has no such dependency to begin with).

---

## Task 3: Validation-state API

Create `backend/app/services/finding_service.py` (`get_finding`, `update_validation`) and `backend/app/api/routes/findings.py` (`PATCH /findings/{id}`), per PLAN_5.md §4. Edit `backend/app/schemas/finding.py`: add `confidence_score`/`validation_state`/`validation_note`/`validated_at` to `FindingRead`, add `FindingValidationUpdate`. Edit `backend/app/main.py`: register the new `findings_router`.

**Tests** (`backend/tests/test_finding_service.py` or `test_findings_route.py`, new; extend the Phase 3/4 scan-assets route test): per PLAN_5.md §6 — valid transitions with/without a note, `validated_at` set/cleared correctly, invalid `validation_state` rejected with 422, unknown `finding_id` -> 404, re-transitioning an already-validated finding (proving unrestricted transitions + full-replace note semantics, not a merge), the back-to-`UNVALIDATED` clearing behavior; the existing scan-assets route test extended to assert the four new `FindingRead` fields appear with their defaults on a freshly-seeded, never-validated `Finding`.

**Acceptance**: `pytest -v` green; `ruff`/`black`/`mypy` clean; manual `curl -X PATCH http://localhost:8000/api/v1/findings/<id>` against a seeded finding shows the full `FindingRead` body with all four new fields in the response.

---

## Task 4: Frontend confidence display + validation control

Edit `frontend/src/lib/types/finding.ts`: add `ValidationState`, the four new `FindingRead` fields, `FindingValidationUpdate`. Create `frontend/src/lib/api/findings.ts` (`updateFindingValidation`). Create `frontend/src/components/ValidationBadge.tsx` (renders nothing for `"unvalidated"`, a styled badge for `"confirmed"`/`"false_positive"`) and `frontend/src/components/FindingValidationControl.tsx` (`"use client"`, mirroring `ScanCreateButton.tsx`'s state/submit/`router.refresh()` pattern). Edit `frontend/src/app/projects/[projectId]/scans/[scanId]/page.tsx`: add the confidence-score text, `ValidationBadge`, and `FindingValidationControl` to each finding's render block; apply `opacity-50` + strikethrough CVE-id styling when `validation_state === "false_positive"`.

**Tests**: no automated page-test infra exists this project (consistent with every prior phase's minimal frontend-testing scope); `npm run lint` / `npx tsc --noEmit` plus the manual walkthrough in PLAN_5.md §7.

**Acceptance**: `npm run lint` and `npx tsc --noEmit` clean; manual walkthrough against a scan with a seeded finding shows the confidence text, lets an operator change validation state + note via the control, and reflects a `false_positive` state with the documented de-emphasis styling (still visible, never hidden) after `router.refresh()`.

---

## Task 5: Full-stack verification pass

Fresh `docker compose down -v && docker compose up --build`. Apply the migration. Run PLAN_5.md §7's full Verification Plan end-to-end: the seeded-evidence correlation run producing a `Finding` with a `confidence_score` matching the formula's exact expected output for that service's `method`/`conf`; the real `PATCH /api/v1/findings/<id>` call marking it `FALSE_POSITIVE` with a note, confirmed persisted in Postgres (not just the response body); the 422 rejection of an invalid `validation_state`; the back-to-`UNVALIDATED` clearing behavior; the nested `findings[]` shape via `GET /scans/{id}/assets` showing all four new fields; the frontend results page rendering the confidence text, the de-emphasized false-positive row, and a working validation control. Run the full backend suite and lint/type-check on both sides.

This is not a feature-writing task — fix only narrow integration issues found (same scope discipline as every prior phase's final task). If something reveals an architectural gap rather than an integration correction (e.g. the confidence formula's bands turn out to need real-world retuning), report BLOCKED/NEEDS_CONTEXT instead of improvising a redesign.

**Acceptance**: every step in PLAN_5.md §7 passes as described; `pytest -v`, `ruff check .`, `black --check .`, `mypy app`, `npm run lint`, `npx tsc --noEmit` all green; report the full transcript/evidence, including the actual `confidence_score` value computed for the seeded service (so a reviewer can independently verify it against `confidence.py`'s formula).

---

### Critical Files for Implementation

- `backend/app/modules/vulnerability/confidence.py` (new — the scoring formula itself, the phase's core judgment call)
- `backend/app/modules/vulnerability/correlator.py` (exact per-service wiring point for `confidence_score`; must not regress into per-CVE recomputation)
- `backend/app/models/finding.py` (new `FindingValidationState` enum + the four new columns everything else hangs off of)
- `backend/app/services/finding_service.py` (new — the one place transition/note/timestamp semantics are enforced)
- `backend/app/api/routes/findings.py` (new — the first standalone, by-id, write-capable `Finding` route)
- `frontend/src/app/projects/[projectId]/scans/[scanId]/page.tsx` (where confidence + validation UI gets rendered; existing structure this phase extends rather than replaces)
