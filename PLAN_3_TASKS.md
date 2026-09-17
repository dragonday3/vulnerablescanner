# PLAN_3_TASKS.md — VulnSight Phase 3 Task-Based Execution Plan

Companion to `PLAN_3.md` (narrative plan, binding authority for anything a task here doesn't fully specify).

Scope: Phase 3 (Service Fingerprinting) only — nmap `-sV` evidence capture, native-scanner HTTP-header enrichment, `Service` schema/storage for both, the `FINGERPRINTING` status transition, and a minimal frontend results view. No Phase 4 (vulnerability correlation) work.

## Global Constraints

1. **Migration-first ordering.** Task 1 (Service model + migration) must land before any task that writes to the new columns (Tasks 4 and 5) — same "schema before code that uses it" discipline as Phase 2's Task 1/2 ordering.
2. **Discovery's "is this port open" semantics are unchanged.** Fingerprinting only ever adds data to already-`open` `Service` rows; a closed/filtered port is never fingerprinted, regardless of adapter.
3. **`-sV` is unconditional for the nmap adapter this phase** — no new `scan.config` toggle. Don't add one "for flexibility."
4. **HTTP fingerprinting is native-adapter-only and allowlist-only.** Never probe every open port; never run HTTP probing for nmap-adapter scans (their `-sV` evidence already covers it — running both would waste time and duplicate evidence for no gain).
5. **Fingerprinting failures must never fail the scan.** Any exception during the HTTP enrichment pass is caught, logged, and swallowed — `scan.status` may only become `FAILED` from the pre-existing discovery-stage `try/except` (Phase 2's block), never from fingerprinting code added this phase.
6. **No redirect-following in the HTTP prober, and a bounded response-body read** (`MAX_RESPONSE_BYTES`) — this is a security-relevant control (SSRF/resource-exhaustion hygiene against a target host that may misbehave), not a style preference; don't relax it "to be more thorough."
7. **Subprocess safety rules from Phase 2 are unchanged and un-relaxed.** `-sV` is appended to the existing list-form argv; the single-`<host>`-element assertion, `shell=True` prohibition, and no-string-interpolation rule all carry forward untouched.
8. **`NMAP_SCAN_TIMEOUT_SECONDS` must be re-measured against a live target with `-sV` enabled** before being left at its Phase 2 value or bumped — record the measurement, don't guess.
9. **Raw evidence (`Service.evidence`) is always preserved verbatim** alongside any parsed `product`/`version`/`extrainfo`, even when that parse is only a best-effort heuristic. The structured columns are a convenience projection; `evidence` is the source of truth.
10. **Celery tasks still open their own `SessionLocal()`; every status transition still commits immediately** — Phase 2's Global Constraints 9–10 carry forward unchanged, including for the new `FINGERPRINTING` transition and the enrichment-results commit.
11. **`GET /scans/{scan_id}/assets` is a new, separate endpoint.** `ScanRead`/`GET /scans`/`GET /scans/{id}` are NOT changed to embed nested assets/services — don't fold this in "since you're already touching scan schemas."
12. **Frontend changes follow existing conventions exactly**: server components + `force-dynamic` + per-fetch `try/catch` → inline error banner (never let one failed fetch break the whole page), no new client-side cache/store, an exhaustive `Record`-style mapping (`StatusBadge.tsx`'s pattern) for the new `fingerprint_source` union, existing card/table Tailwind styling reused rather than inventing a new visual pattern.
13. Follow established Phase 0–2 conventions: thin routes, business logic in the service layer, `NotFoundError`/`ValidationConflictError`/`ScanStateError` exception pattern, SQLAlchemy 2.x `Mapped`/`mapped_column` style, ruff/black/mypy all clean on backend, `next lint`/`tsc --noEmit` clean on frontend.

---

## Task 1: `Service` fingerprint columns + migration

Edit `backend/app/models/service.py`: add `product: Mapped[str | None] = mapped_column(String(255), nullable=True)`, `version: Mapped[str | None] = mapped_column(String(100), nullable=True)`, `extrainfo: Mapped[str | None] = mapped_column(Text, nullable=True)`, `fingerprint_source: Mapped[str | None] = mapped_column(String(20), nullable=True)`, `evidence: Mapped[dict | None] = mapped_column(JSONB, nullable=True)`. Add the `Text` (from `sqlalchemy`) and `JSONB` (from `sqlalchemy.dialects.postgresql`) imports.

Generate an **additive** migration: `alembic revision --autogenerate -m "add service fingerprint columns (product, version, extrainfo, fingerprint_source, evidence)"`. Review the generated file (five `op.add_column('services', ...)` calls expected, all nullable, no index/table changes), apply it.

**Acceptance**: migration applies cleanly on top of the current schema with no data loss (create a project/target/scan/asset/service before and after applying, confirm it survives); `docker compose exec postgres psql -U vulnsight -d vulnsight -c "\d services"` shows all five new columns with the documented types/lengths.

---

## Task 2: Discovery interface widening + Nmap `-sV`/service parsing + timeout re-verification

Edit `backend/app/modules/discovery/interfaces.py`: widen `PortScanResult` with the optional evidence fields (`service_name`, `product`, `version`, `extrainfo`, `method`, `cpe: tuple[str, ...] = ()`, `raw_evidence: dict[str, object] | None = None`), all defaulted so `NativePortScanner`/its existing tests need zero changes.

Edit `backend/app/modules/discovery/nmap_scanner.py`: add `-sV` to the command unconditionally; parse each `<port>`'s `<service>` child (name/product/version/extrainfo/method/conf attributes, each optional) and its `<cpe>` children into the new `PortScanResult` fields and a `raw_evidence` dict (only keys actually present in the XML — never inject `None`s). `service_el is None` is a normal, non-error outcome (all new fields stay at their defaults).

Edit `backend/app/workers/tasks.py`: re-measure `NMAP_SCAN_TIMEOUT_SECONDS` against a real in-network target with `-sV` now enabled (see PLAN_3.md §2 for the exact method); update the constant to the measured value plus headroom, and update its neighboring comment to state the measured baseline and date.

**Tests** (`backend/tests/test_nmap_scanner.py`, extend): a deterministic unit test patching `subprocess.run` to return a canned XML fixture with a full `<service>` + `<cpe>` element, asserting exact field extraction; the existing real-nmap-against-local-listener test extended to confirm `-sV` is in the built command and that an unidentifiable service (no useful `<service>` data) doesn't crash the parse.

**Acceptance**: `docker compose exec backend pytest -v` green (including nmap tests, skipped gracefully if `nmap` isn't on `PATH`); `ruff`/`black`/`mypy` clean; the timeout re-measurement's observed number and the chosen constant are documented in the task's report.

---

## Task 3: HTTP fingerprinting module + `httpx` promotion

Create `backend/app/modules/fingerprinting/http_prober.py`: `WEB_PORTS` curated allowlist, `HttpProbeResult` dataclass, `probe_services(host, ports, timeout_seconds=HTTP_PROBE_TIMEOUT_SECONDS, max_concurrency=DEFAULT_MAX_CONCURRENCY) -> dict[int, HttpProbeResult]` (async-internally, sync-externally, semaphore-bounded, `follow_redirects=False`, bounded body read, per-port failure swallowed/omitted rather than raised, one-scheme-per-port heuristic via `_TLS_HEURISTIC_PORTS`), private `_parse_server_header` heuristic.

Edit `backend/requirements.txt`: add `httpx~=0.28`.
Edit `backend/requirements-dev.txt`: remove the now-duplicate `httpx~=0.28` line; update the header comment (httpx is no longer dev-only).

**Tests** (`backend/tests/test_http_prober.py`, new): local `http.server.HTTPServer` (stdlib, background thread, random port on `127.0.0.1`) serving a response with a known `Server` header + `<title>`, asserting correct `HttpProbeResult` parsing; a closed port → absent from the result dict, no exception; an accept-but-never-respond socket → absent, no exception, bounded wait time. No real external host touched.

**Acceptance**: `docker compose exec backend pytest -v` green; `docker compose up --build` succeeds with `httpx` now installed via `requirements.txt`; `ruff`/`black`/`mypy` clean.

---

## Task 4: Orchestration wiring — `FINGERPRINTING` transition + evidence persistence + native HTTP enrichment

Edit `backend/app/workers/tasks.py`:
- `Service` construction (existing discovery step) gains the new field assignments described in PLAN_3.md §4, including the `service_name` precedence flip (nmap's own guess wins over `PORT_NAMES` when present) and `fingerprint_source="nmap-sv" if scanner_name == "nmap" else None`.
- Add an explicit `return` at the end of the existing discovery `except Exception` block (required once code follows it).
- Add `scan.status = ScanStatus.FINGERPRINTING; db.commit()` immediately after the discovery commit, for both adapters uniformly.
- Add a new, separate `try/except Exception` block: for `scanner_name == "native"`, filter the just-created `services` list to `WEB_PORTS`, call `probe_services`, update matching `Service` rows in place (`product`/`version`/`extrainfo`/`fingerprint_source="http"`/`evidence`), one `db.commit()` for the batch. Any exception: `db.rollback()`, `logger.exception(...)`, no `scan.status` mutation, no `return` — always falls through.
- `scan.status = ScanStatus.COMPLETED` unchanged, now reached after the fingerprinting block regardless of its outcome.

**Tests** (`backend/tests/test_scan_orchestration.py`, extend): nmap-path evidence persistence (mocked `NmapPortScanner.scan` returning enriched `PortScanResult`s); native-path HTTP enrichment (mocked `http_prober.probe_services`) updating only the matching `Service` row; a `probe_services`-raises test proving the scan still reaches `COMPLETED` with `error_message` still `None` and affected fields still `None`; a no-web-ports-found test proving `probe_services` is never called; confirmation that `FINGERPRINTING` is set as an intermediate state for both adapters.

**Acceptance**: `pytest -v` green, every new transition/branch above exercised by at least one test; `ruff`/`black`/`mypy` clean.

---

## Task 5: Backend schemas + `GET /scans/{scan_id}/assets`

Create `backend/app/schemas/service.py` (`ServiceRead`) and `backend/app/schemas/asset.py` (`AssetRead`, nesting `list[ServiceRead]`), per PLAN_3.md §5.

Edit `backend/app/services/scan_service.py`: add `get_scan_assets(db, scan_id) -> list[Asset]` (404s via the existing `get_scan` if the scan itself doesn't exist; `selectinload(Asset.services)` to avoid N+1).

Edit `backend/app/api/routes/scans.py`: add `GET /scans/{scan_id}/assets` → `list[AssetRead]`.

**Tests** (extend `backend/tests/test_scans.py` or new `test_scan_assets_route.py`): seed scan+asset+service rows directly via the `db` fixture; `GET /scans/{id}/assets` returns 200 with the expected nested shape including all new fingerprint fields; 404 for a nonexistent scan; `[]` for a real scan with no assets yet.

**Acceptance**: `pytest -v` green; `ruff`/`black`/`mypy` clean; manual `curl http://localhost:8000/api/v1/scans/<id>/assets` returns the expected JSON shape against a real completed scan.

---

## Task 6: Frontend results view + navigation + `error_message` fix

Edit `frontend/src/lib/types/scan.ts`: add `error_message: string | null` to `ScanRead`.

Create `frontend/src/lib/types/asset.ts`, `frontend/src/lib/types/service.ts` (mirrors of the new backend schemas; `fingerprint_source` as a `"nmap-sv" | "http" | "port-guess" | null` union).

Edit `frontend/src/lib/api/scans.ts`: add `getScan(scanId)` and `getScanAssets(scanId)`.

Create `frontend/src/components/FingerprintBadge.tsx` (exhaustive `Record`-mapping component, same pattern as `StatusBadge.tsx`).

Create `frontend/src/app/projects/[projectId]/scans/[scanId]/page.tsx`: server component, `force-dynamic`, three independently-`try/catch`'d fetches (`getScan`, `listTargets` for the target join, `getScanAssets`), header card + per-asset services table with `FingerprintBadge` and an expandable raw-evidence panel, "no results yet" empty state distinct from a fetch-error state.

Edit `frontend/src/app/projects/[projectId]/page.tsx`: scan-id table cell becomes a `<Link>` to the new route.

**Tests**: no backend-style automated test infra exists for pages this phase (consistent with Phase 0/2's minimal frontend-testing scope); manual verification is the `npm run lint` / `tsc --noEmit` pass plus the visual walkthrough in the Verification Plan.

**Acceptance**: `npm run lint` and `npx tsc --noEmit` clean; manual walkthrough (create a scan, let it complete, click through from the project page to the new results page, confirm the fingerprint data renders) matches PLAN_3.md §8's described behavior.

---

## Task 7: Full-stack verification pass

Fresh `docker compose down -v && docker compose up --build` (all 5 services). Apply the migration. Run PLAN_3.md §8's full Verification Plan end-to-end: nmap-adapter scan against an in-network target showing populated `product`/`version`/`evidence` with `fingerprint_source='nmap-sv'`; native-adapter scan against an in-network web-serving target (e.g. the `frontend` container on port 3000) showing `Server`-header evidence with `fingerprint_source='http'` on the matching port and `NULL` on other open, non-web ports found on the same asset; `GET /scans/{id}/assets` returns the expected shape; the new frontend results page renders correctly from a real browser session, and the scan-id link on the project page navigates there. Run the full backend suite and lint/type-check on both sides.

This is not a feature-writing task — fix only narrow integration issues found (same scope discipline as Phase 2's Task 8). If something reveals an architectural gap rather than an integration correction, report BLOCKED/NEEDS_CONTEXT instead of improvising a redesign.

**Acceptance**: every step in PLAN_3.md §8 passes as described; `pytest -v`, `ruff check .`, `black --check .`, `mypy app`, `npm run lint`, `npx tsc --noEmit` all green; report the full transcript/evidence.
