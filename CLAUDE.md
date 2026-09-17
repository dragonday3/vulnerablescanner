# VulnSight

Evidence-Based Vulnerability Assessment & Risk Prioritization Platform.
Authorized-use-only network scanner: projects contain targets (ip/cidr/
domain/hostname), targets require `authorization_confirmed` before any
scan can run against them, scans discover open services and (in later
phases) will fingerprint, check misconfigurations, assess vulnerabilities,
score risk, and report.

**Keep this file updated** as phases land — status, structure, and
conventions below should track reality, not the plan that predates it.

## Status

- **Phase 0** (project foundation) and **Phase 1** (Project/Target/Scan
  CRUD + auth enforcement) — done. See `PLAN_1.md` / `PLAN_1_TASKS.md`.
- **Phase 2** (Scan Orchestration) — done, merged to `main`. Celery worker
  + Redis broker actually execute scans; two interchangeable port-scan
  adapters (native asyncio TCP-connect, and nmap via subprocess with
  strict list-form args); results persist as `Asset`/`Service` rows. See
  `PLAN_2.md` / `PLAN_2_TASKS.md`.
- **Phase 3+** (fingerprinting, misconfiguration, vulnerability,
  risk scoring, reporting) — not started. Placeholder empty packages
  already exist under `backend/app/modules/` for each.
- No CI configured yet. No GitHub remote existed until this was pushed
  manually — verify `git remote -v` / `.github/` before assuming any
  pipeline exists.

## Stack & architecture

- **Backend**: FastAPI (`backend/app`), SQLAlchemy 2.x (`Mapped`/
  `mapped_column` style), Alembic migrations, Postgres, Pydantic v2
  schemas. Thin routes → service layer → models. Exceptions follow a
  `NotFoundError`/`ValidationConflictError`/`ScanStateError` pattern
  mapped to HTTP responses centrally — don't `raise HTTPException`
  directly in services.
- **Async work**: Celery (`backend/app/workers/`), Redis as both broker
  and result backend. `run_scan_task` opens its own `SessionLocal()` —
  never share a FastAPI request-scoped session across the broker
  boundary. Every scan status transition commits immediately, not
  batched, so a crash mid-scan leaves the DB at the last real state.
  The `worker` container does not hot-reload; `docker compose restart
  worker` after editing task code.
- **Discovery adapters** (`backend/app/modules/discovery/`): both
  implement `PortScannerInterface`. `NativePortScanner` is the default;
  `NmapPortScanner` is opt-in via `scan.config.scanner == "nmap"`.
  Target values are validated by `TargetCreate` *before* they can reach
  either adapter (format + shell-metacharacter + IPv6-zone-ID + nmap
  host-range-syntax rejection) — that's the load-bearing invariant the
  nmap adapter's subprocess-argument safety depends on. Never re-loosen
  that validator without re-auditing `nmap_scanner.py`.
- **No CIDR scanning yet** — a scan against a `cidr` target must reach
  `FAILED` with `error_message="CIDR range scanning is not yet
  supported"`, never attempt subnet expansion.
- **Frontend**: Next.js App Router (`frontend/src/app`), typed API client
  in `frontend/src/lib/api/`. No frontend changes landed in Phase 2 —
  scan config (`scanner: native|nmap`) isn't exposed in the UI yet.

## Running it

See `README.md` Quick Start — `docker compose up --build` (5 services:
postgres, redis, backend, worker, frontend), then `docker compose exec
backend alembic upgrade head` (migrations are manual, deliberately not
run on container start). Verification: `pytest -v`, `ruff check .`,
`black --check .`, `mypy app` from `backend/`; `next lint` from
`frontend/`. Windows-specific gotchas (bind-mount hot reload, line
endings, port collisions) are documented in the README, not repeated
here.

## Conventions

- Security-sensitive by design: this scans real hosts, so validation at
  the target-creation boundary is the security control, not the scanner
  adapters. Treat changes to `schemas/target.py`'s validators as
  security-relevant even when they look like a formatting nit.
- Subprocess safety is non-negotiable in the nmap adapter: list-form
  `subprocess.run` args only, never `shell=True`, never string-built
  commands.
- Service identification this phase is a static port→name lookup only —
  no banner grabbing/version detection (that's a later phase; don't
  add it opportunistically while touching this code).
- One `Asset` per non-CIDR scan, no cross-scan dedup yet — don't build
  asset-history logic ahead of the phase that needs it.
- Structured JSON logging (`backend/app/core/logging.py`) hooks
  `scan_id` into log records where available.

## Development process

Implementation plans for each phase live at repo root as `PLAN_N.md`
(narrative, binding authority) + `PLAN_N_TASKS.md` (task breakdown used
for execution). Phase work happens in a git worktree under
`.claude/worktrees/`, task-by-task with review between tasks and a final
whole-branch review before merge — see the merge commit for e.g. Phase 2
for what that review caught (a critical nmap host-range authorization
bypass, a lost-update race, a silent-failure-on-unresolvable-host bug).
Don't assume a merged phase is bug-free by construction, but do trust
that it went through that process.
