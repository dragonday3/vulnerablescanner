# PLAN_4_TASKS.md — VulnSight Phase 4 Task-Based Execution Plan

Companion to `PLAN_4.md` (narrative plan, binding authority for anything a task here doesn't fully specify).

Scope: Phase 4 (Vulnerability Correlation) only — `Finding`/`cve_cache` models + migration, CPE 2.2→2.3 conversion, the NVD CVE API 2.0 client, a Redis-based cross-process rate limiter, the cache-check-then-fetch flow, `CORRELATING` orchestration wiring, API exposure, and a minimal frontend findings render. No Phase 5 (confidence/validation) work.

## Global Constraints

1. **Migration-first ordering.** Task 1 (`Finding`/`CveCache` models + migration) must land before any task that writes to the new tables (Tasks 5 and 6) — same discipline as every prior phase's Task 1.
2. **Only nmap-sourced `Service` rows ever get `Finding` rows.** `correlate_services` selects purely on "does `evidence` have a non-empty `cpe` key" — never on `scanner_name`/`fingerprint_source` directly — but the practical effect, since only the nmap adapter ever writes that key, is that native-adapter scans produce zero findings, always, this phase. Don't build any CPE-construction path for HTTP-prober evidence "while you're in there" — explicitly out of scope (PLAN_4.md scope limits).
3. **The rate limiter is global and atomic, not per-process.** A plain Python `time.sleep` anywhere in this phase's code is a bug, not an optimization — every NVD-call-gating decision must go through the Redis Lua-script-based `NvdRateLimiter`, no exceptions, no second ad hoc throttling mechanism invented alongside it.
4. **A failed NVD lookup is never cached.** `cache.store()` must never be reachable from a `None` return value of `fetch_cves_for_cpe` — this is the single most important invariant this phase introduces; a violation silently manufactures a permanent false "no known vulnerabilities" for real services.
5. **Vulnerability correlation failures must never fail the scan.** Any exception during the correlation pass is caught, logged, and swallowed — `scan.status` may only become `FAILED` from the pre-existing discovery-stage `try/except` (Phase 2's block), never from correlation code added this phase. No `return` is added to this phase's new `except` block (unlike Phase 3's discovery-failure `return`) — see PLAN_4.md §5 for why that asymmetry is intentional, not an inconsistency.
6. **Correlation commits incrementally, once per distinct CPE — never once at the end of the whole per-scan loop.** This is load-bearing for constraint 5: a late-loop failure must only roll back the one CPE that was mid-flight, never CPEs already successfully processed earlier in the same scan's correlation pass.
7. **No multi-page NVD pagination, no CPE-construction from HTTP-prober strings, no full CPE-2.3-spec-compliant converter library, no proactive cache-refresh job, no API-key usage this phase** — all per PLAN_4.md's explicit scope-limits section. Don't add any of these "for completeness."
8. **No new runtime dependency.** `httpx~=0.28` and `redis~=8.1` are both already pinned in `backend/requirements.txt` — the NVD client and rate limiter are built entirely on top of what's already there.
9. **`ScanStatus.ANALYZING`/`RISK_ANALYSIS`/`REPORT_GENERATION` are untouched.** Only `CORRELATING` is set this phase.
10. **Celery tasks still open their own `SessionLocal()`; every status transition still commits immediately** — unchanged, carried forward.
11. **`GET /scans/{scan_id}/assets` is reused, not duplicated.** `findings` nests onto the existing `ServiceRead` via that endpoint — no new `GET /scans/{scan_id}/findings` endpoint this phase.
12. **Frontend changes follow existing conventions exactly**: server components + `force-dynamic` + per-fetch `try/catch` → inline error banner, no new client-side cache/store, an exhaustive `Record`-style mapping (`StatusBadge.tsx`/`FingerprintBadge.tsx`'s pattern) for `Severity`, existing card/table Tailwind styling reused.
13. Follow established Phase 0–3 conventions: thin routes, business logic in modules/services layers, `NotFoundError`/`ValidationConflictError`/`ScanStateError` exception pattern (none of which this phase's code needs to raise — correlation has no API-facing validation surface), SQLAlchemy 2.x `Mapped`/`mapped_column` style, ruff/black/mypy clean on backend, `next lint`/`tsc --noEmit` clean on frontend.

---

## Task 1: `Finding` + `CveCache` models and migration

Create `backend/app/models/cve_cache.py` (`CveCache`) and `backend/app/models/finding.py` (`Finding`), per PLAN_4.md §1. Edit `backend/app/models/service.py` to add the `findings` relationship (cascade/passive_deletes, matching `Asset.services`' exact pattern). Edit `backend/app/db/base.py` to import both new model classes.

Generate an additive migration: `alembic revision --autogenerate -m "add cve_cache and findings tables"`. Review the generated file (two `op.create_table` calls, FK + unique constraint + indexes as specified), apply it.

**Tests**: none needed standalone (covered by Task 5/6's tests exercising the tables via the ORM) beyond a smoke check that the tables exist.

**Acceptance**: migration applies cleanly with no data loss to existing tables; `docker compose exec postgres psql -U vulnsight -d vulnsight -c "\d cve_cache"` and `"\d findings"` show the documented columns/constraints; `ruff`/`black`/`mypy` clean.

---

## Task 2: CPE 2.2→2.3 conversion + NVD client

Create `backend/app/modules/vulnerability/cpe_utils.py` (`to_cpe23`) and `backend/app/modules/vulnerability/nvd_client.py` (`NormalizedCve`, `fetch_cves_for_cpe`), per PLAN_4.md §2. Edit `backend/app/core/config.py` to add `NVD_API_KEY: str | None = None`.

**Tests** (`backend/tests/test_cpe_utils.py`, `backend/tests/test_nvd_client.py`, both new): per PLAN_4.md §8 — conversion table incl. a malformed-input case; NVD client tests using in-test-constructed `httpx.Response` objects (never real network), covering the full success/zero-results/403/429/timeout/malformed-JSON/rate-limiter-timeout matrix, plus the conditional `apiKey` header test.

**Acceptance**: `docker compose exec backend pytest -v` green; `ruff`/`black`/`mypy` clean; no test in this task's files makes a real network call (verify by running with network access disabled/offline if convenient, or by code review confirming every `httpx` call site is patched).

---

## Task 3: Redis-based rate limiter + test Redis fixture

Create `backend/app/modules/vulnerability/rate_limiter.py` (`NvdRateLimiter`, `RateLimiterTimeoutError`, the Lua-script-based atomic `try_acquire`/`acquire`), per PLAN_4.md §3.

Edit `backend/tests/conftest.py`: add the new `TEST_REDIS_URL`-based Redis fixture (session-scoped connection, per-test `flushdb()`), following the exact precedent PLAN_4.md §8 describes for the existing Postgres test-database pattern.

**Tests** (`backend/tests/test_rate_limiter.py`, new): against the real ephemeral test Redis — immediate-success-then-rejection at the configured limit; a timeout case (`acquire()` raising `RateLimiterTimeoutError` when `max_wait_seconds` is shorter than the window); the `ThreadPoolExecutor` concurrency test proving no more than `max_requests` grants happen within one window under simultaneous contention (the test that actually validates cross-process-safe atomicity, not just single-threaded correctness).

**Acceptance**: `pytest -v` green including the new Redis-backed tests (confirm they fail loudly, not silently skip, if `TEST_REDIS_URL`/`REDIS_URL` is unreachable); `ruff`/`black`/`mypy` clean.

---

## Task 4: Cache layer (`cve_cache` check/store/staleness)

Create `backend/app/modules/vulnerability/cache.py` (`get_cached`, `is_stale`, `store`, `CVE_CACHE_TTL_DAYS = 7`), per PLAN_4.md §4.

**Tests** (`backend/tests/test_cve_cache.py`, new): cache miss; round-trip store→get; staleness true/false at the TTL boundary; re-`store()` on an existing `cpe` updates in place rather than duplicating.

**Acceptance**: `pytest -v` green; `ruff`/`black`/`mypy` clean; explicit test (or code-review-confirmed invariant) that no code path in this file can be reached with a `None` CVE-list argument from a failed lookup.

---

## Task 5: Correlator + orchestration wiring (`CORRELATING`)

Create `backend/app/modules/vulnerability/correlator.py` (`correlate_services`, `MAX_DISTINCT_CPES_PER_SCAN = 25`), per PLAN_4.md §5: CPE-evidence filtering, 2.2→2.3 conversion + drop-unconvertible, dedup into `cpe_to_services`, per-scan cap with first-encountered-order truncation + logging, per-distinct-CPE cache-then-fetch-then-persist with a commit after each CPE (not batched at the end), and an outer `try/except` safety net.

Edit `backend/app/workers/tasks.py`: insert the `CORRELATING` transition + `correlate_services` call exactly at the point PLAN_4.md §5 shows (between the existing Step 9 fingerprinting block and the final `COMPLETED` transition), constructing `redis.Redis.from_url(get_settings().REDIS_URL)` once per task invocation. No `return` added to the new `except` block.

**Tests** (`backend/tests/test_correlator.py`, new; `backend/tests/test_scan_orchestration.py`, extend): per PLAN_4.md §8 — correlator-level dedup/cap/cache-hit/failure/incremental-commit tests with `nvd_client.fetch_cves_for_cpe` mocked directly; orchestration-level tests with `correlator.correlate_services` itself mocked, asserting the `CORRELATING` status transition for both adapters and the never-fail-the-scan contract (a raising mock still reaches `COMPLETED` with `error_message` still `None`).

**Acceptance**: `pytest -v` green, every branch above exercised by at least one test; `ruff`/`black`/`mypy` clean.

---

## Task 6: Backend schema + API exposure

Create `backend/app/schemas/finding.py` (`FindingRead`). Edit `backend/app/schemas/service.py` to nest `findings: list[FindingRead] = []`. Edit `backend/app/services/scan_service.py`'s `get_scan_assets` to chain `.selectinload(Service.findings)` onto the existing `selectinload(Asset.services)`.

**Tests** (extend the Phase 3 scan-assets route test): seed `Finding` rows via the `db` fixture directly on a seeded `Service`; `GET /scans/{id}/assets` response includes the expected nested `findings` array with every `FindingRead` field; a `Service` with none returns `"findings": []`.

**Acceptance**: `pytest -v` green; `ruff`/`black`/`mypy` clean; manual `curl http://localhost:8000/api/v1/scans/<id>/assets` shows the `findings` array nested under a real correlated service (can reuse Task 5's test data or Task 8's seeded verification data).

---

## Task 7: Frontend findings render

Create `frontend/src/lib/types/finding.ts` (`Severity`, `FindingRead`). Edit `frontend/src/lib/types/service.ts` to add `findings: FindingRead[]`. Create `frontend/src/components/SeverityBadge.tsx` (plain, non-nullable `Record<Severity, string>` mapping). Edit `frontend/src/app/projects/[projectId]/scans/[scanId]/page.tsx` to render a severity badge + NVD-linked CVE id (+ CVSS score) per finding under each service row; services with zero findings render nothing extra.

**Tests**: no automated page-test infra exists this project (consistent with Phase 0/3's minimal frontend-testing scope); `npm run lint` / `npx tsc --noEmit` plus the manual walkthrough in PLAN_4.md §9.

**Acceptance**: `npm run lint` and `npx tsc --noEmit` clean; manual walkthrough against a scan with seeded/real findings renders severity badges and working NVD links; a scan with no CPE-evidenced services renders the page exactly as it did before this phase (no new empty-state clutter).

---

## Task 8: Full-stack verification pass

Fresh `docker compose down -v && docker compose up --build`. Apply the migration. Run PLAN_4.md §9's full Verification Plan end-to-end: the best-effort real-nmap-CPE attempt (documented either way); the seeded-CPE correlation run producing real `Finding` rows against a real, live NVD lookup for a well-known CVE (e.g. CVE-2021-41773 via `cpe:/a:apache:http_server:2.4.49`); confirmation the `cve_cache` row is populated and a second identical-CPE lookup doesn't re-hit NVD (log-based or mocked-call-count evidence); confirmation the rate limiter actually caps concurrent grants (the `ThreadPoolExecutor` script showing exactly `max_requests` immediate grants out of more simultaneous attempts); the new nested `findings` shape via `GET /scans/{id}/assets`; the frontend results page rendering severity badges and NVD links from a real browser session. Run the full backend suite and lint/type-check on both sides.

This is not a feature-writing task — fix only narrow integration issues found (same scope discipline as Phase 2/3's final tasks). If something reveals an architectural gap rather than an integration correction (e.g. the rate limiter design turns out not to hold up against the real worker pool's actual concurrency), report BLOCKED/NEEDS_CONTEXT instead of improvising a redesign.

**Acceptance**: every step in PLAN_4.md §9 passes as described; `pytest -v`, `ruff check .`, `black --check .`, `mypy app`, `npm run lint`, `npx tsc --noEmit` all green; report the full transcript/evidence, including the actual CVE ids/severities returned by the live NVD call (so a reviewer can independently verify them against nvd.nist.gov).

---

### Critical Files for Implementation

- `backend/app/workers/tasks.py` (exact insertion point for `CORRELATING` + `correlate_services`; never-fail-the-scan contract lives here)
- `backend/app/modules/vulnerability/correlator.py` (new — orchestration glue: dedup, per-scan cap, incremental commits)
- `backend/app/modules/vulnerability/nvd_client.py` (new — NVD HTTP call + response parsing + error taxonomy)
- `backend/app/modules/vulnerability/rate_limiter.py` (new — cross-process Redis Lua-script rate limiter)
- `backend/app/models/finding.py` and `backend/app/models/cve_cache.py` (new — the two new tables everything else hangs off of)
- `backend/app/modules/discovery/nmap_scanner.py` (confirms the CPE 2.2 form nmap actually emits — the fact the conversion step in `cpe_utils.py` exists to handle)
- `frontend/src/app/projects/[projectId]/scans/[scanId]/page.tsx` (where findings get rendered; existing structure this phase extends rather than replaces)
