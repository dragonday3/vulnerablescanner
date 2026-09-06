# VulnSight — Phase 0 + Phase 1 Implementation Plan

## Context

VulnSight is a new project: an evidence-based vulnerability assessment and risk-prioritization platform (not an Nmap wrapper, not an autonomous exploitation tool). The user provided a comprehensive product/architecture spec covering ~8 build phases, from a foundation skeleton all the way to CVE correlation, risk scoring, and professional reporting. The repository at `D:\Vulnscanner` is currently empty (confirmed via `ls`, not yet a git repo).

The spec explicitly calls for building vertically and not overengineering the MVP: complete one working pipeline before adding complexity. Per the user's decisions:
- This plan covers **Phase 0 (Project Foundation)** and **Phase 1 (Project/Target/Scan data model + CRUD)** in full execution detail. Later phases (actual scanning, fingerprinting, CVE correlation, misconfiguration analysis, risk scoring, reporting) are intentionally left as a roadmap outline — they'll get their own detailed plan once this foundation is built and verified.
- **Docker Compose** is used from day one (Postgres + Redis + backend + frontend), even though nothing consumes Redis until Phase 2, to avoid rework.
- **Auth is deferred entirely** — no users table, no login/register, no JWT. Projects/Targets/Scans are not user-scoped yet.

The core philosophy that must be reflected even at this early stage: scanner tools sit behind interfaces (not hardcoded), targets must be explicitly marked as authorized before they can be scanned (enforced at the schema/service layer, not just a UI checkbox), and the `Scan` model's status enum already contains the full future lifecycle so later phases don't require a schema migration just to add states.

---

## 1. Repository Layout

```
D:\Vulnscanner\
├── .git/
├── .gitignore
├── .gitattributes          # * text=auto eol=lf — avoids CRLF issues in Docker/Alpine on Windows
├── .editorconfig
├── .env.example
├── docker-compose.yml
├── README.md
│
├── backend/
│   ├── Dockerfile
│   ├── .dockerignore
│   ├── pyproject.toml      # ruff + black + mypy + pytest config
│   ├── requirements.txt
│   ├── alembic.ini
│   ├── app/
│   │   ├── main.py                     # FastAPI app factory + router mounting
│   │   ├── core/
│   │   │   ├── config.py               # pydantic-settings Settings
│   │   │   ├── logging.py              # structured logging, scan_id-ready
│   │   │   └── exceptions.py           # domain exceptions + handlers
│   │   ├── db/
│   │   │   ├── base.py                 # Declarative Base, model import hub for Alembic
│   │   │   └── session.py              # engine, SessionLocal, get_db dependency
│   │   ├── models/
│   │   │   ├── project.py
│   │   │   ├── target.py
│   │   │   └── scan.py
│   │   ├── schemas/
│   │   │   ├── project.py
│   │   │   ├── target.py
│   │   │   └── scan.py
│   │   ├── api/
│   │   │   ├── deps.py                 # get_db re-export, get_project_or_404, get_target_or_404
│   │   │   └── routes/
│   │   │       ├── health.py
│   │   │       ├── projects.py
│   │   │       ├── targets.py
│   │   │       └── scans.py
│   │   ├── services/
│   │   │   ├── project_service.py
│   │   │   ├── target_service.py
│   │   │   └── scan_service.py
│   │   ├── modules/                    # package convention only, empty __init__.py files
│   │   │   ├── discovery/__init__.py
│   │   │   ├── fingerprinting/__init__.py
│   │   │   ├── vulnerability/__init__.py
│   │   │   ├── misconfiguration/__init__.py
│   │   │   ├── risk/__init__.py
│   │   │   └── reporting/__init__.py
│   │   └── workers/__init__.py         # placeholder, no Celery app wired yet
│   ├── migrations/
│   │   ├── env.py
│   │   ├── script.py.mako
│   │   └── versions/
│   └── tests/
│       ├── conftest.py
│       ├── test_health.py
│       ├── test_projects.py
│       ├── test_targets.py
│       └── test_scans.py
│
└── frontend/
    ├── Dockerfile
    ├── .dockerignore
    ├── package.json
    ├── tsconfig.json
    ├── next.config.js
    ├── tailwind.config.ts
    ├── src/
    │   ├── app/
    │   │   ├── layout.tsx
    │   │   ├── page.tsx                 # redirects to /projects
    │   │   ├── globals.css
    │   │   └── projects/
    │   │       ├── page.tsx             # list + create project
    │   │       └── [projectId]/page.tsx # targets + scans for a project
    │   ├── lib/
    │   │   ├── api/
    │   │   │   ├── client.ts            # base fetch wrapper
    │   │   │   ├── projects.ts
    │   │   │   ├── targets.ts
    │   │   │   └── scans.ts
    │   │   └── types/
    │   │       ├── project.ts
    │   │       ├── target.ts
    │   │       └── scan.ts
    │   └── components/
    │       ├── StatusBadge.tsx
    │       ├── ProjectForm.tsx
    │       ├── TargetForm.tsx
    │       └── ScanCreateButton.tsx
    └── tests/
        └── example.test.tsx            # optional smoke test, see §7
```

No `models/user.py`, no auth router, no `modules/*` files beyond `__init__.py` (Phase 4+ content like `cpe_mapper.py` is not created now).

---

## 2. Backend Skeleton

- **`app/main.py`**: FastAPI app factory, mounts routers under `/api/v1` prefix (future-proofs versioning before auth exists), CORS middleware allowing `http://localhost:3000`.
- **`core/config.py`**: `pydantic-settings` `Settings` with `DATABASE_URL`, `REDIS_URL` (unused until Phase 2 but defined now), `ENVIRONMENT`, `LOG_LEVEL`, `CORS_ORIGINS`, `API_V1_PREFIX`; singleton via `@lru_cache`.
- **`core/logging.py`**: stdlib `logging` with a JSON formatter that supports a `scan_id` field via contextvars — nothing populates it yet, but it's the hook Phase 2 background jobs bind to. Keep dependency-light (no heavy observability stack yet).
- **`core/exceptions.py`**: `NotFoundError`, `ValidationConflictError` domain exceptions + FastAPI exception handlers returning consistent `{"detail": ..., "code": ...}` bodies.
- **`db/session.py`**: SQLAlchemy engine (`psycopg[binary]` v3 driver) + `SessionLocal` + `get_db` dependency.
- **`db/base.py`**: `DeclarativeBase` subclass; imports all models so Alembic autogenerate sees them.
- **Alembic**: `alembic init migrations`, wire `env.py` to `Settings.DATABASE_URL` and `Base.metadata`. First migration created via `alembic revision --autogenerate` once models exist (creates `projects`, `targets`, `scans` tables + `target_type`/`scan_status` enum types). Apply manually via `docker compose exec backend alembic upgrade head` — not auto-run on container start, so migration failures aren't masked.
- **Health check** (`api/routes/health.py`): `GET /api/v1/health` runs `SELECT 1` against the DB — doubles as DB-connectivity smoke test.
- **`requirements.txt`**: `fastapi`, `uvicorn[standard]`, `sqlalchemy>=2.0`, `alembic`, `psycopg[binary]`, `pydantic`, `pydantic-settings`, `python-dotenv`, `celery`, `redis` (both installed now, unused until Phase 2), `pytest`, `pytest-cov`, `httpx`, `ruff`, `black`, `mypy`.

---

## 3. Data Model (Phase 1)

**`models/project.py`** — `Project`: `id` (UUID pk), `name`, `description` (nullable), `created_at`, `updated_at`; relationships to `targets` and `scans` (cascade delete-orphan).

**`models/target.py`** — `Target`: `id`, `project_id` (FK, cascade), `value` (e.g. `"10.0.0.5"`, `"example.com"`), `target_type` enum (`ip`/`domain`/`hostname`/`cidr`), `authorization_confirmed: bool` (default `False`), `authorization_note` (nullable text, e.g. "pentest agreement #123"), `created_at`.

`authorization_confirmed` is enforced at the schema layer, not just stored: `TargetCreate` Pydantic schema uses a `field_validator` that **rejects `authorization_confirmed=False` outright** (422), directly encoding the "authorized targets only" principle before it ever reaches the DB.

**`models/scan.py`** — `ScanStatus` enum with the **full future lifecycle** (`CREATED, QUEUED, RUNNING, DISCOVERY, FINGERPRINTING, ANALYZING, CORRELATING, RISK_ANALYSIS, REPORT_GENERATION, COMPLETED, FAILED, CANCELLED`) even though only `CREATED`/`QUEUED`/`CANCELLED` are reachable right now — avoids an Alembic migration when Phase 2 starts using the rest. `Scan`: `id`, `project_id` (FK), `target_id` (FK), `status` (default `CREATED`), `config: JSONB` (placeholder for future scan-profile options), `created_at`, `updated_at`, `started_at`/`completed_at` (nullable).

Pydantic schemas follow the standard `*Base`/`*Create`/`*Read` triad per entity (`from_attributes=True`). `ScanCreate` takes `target_id` + optional `config`; the **service layer** re-validates the target's `authorization_confirmed` at creation time (belt-and-suspenders beyond the schema check). `ScanStatusRead` is a slim schema (`id`, `status`, `updated_at`) for the status-polling endpoint.

---

## 4. API Routes (Phase 1)

All under `/api/v1`. Route handlers stay thin — business rules (authorization checks, status-transition legality) live in `services/*_service.py`.

| Method | Path | Behavior |
|---|---|---|
| GET | `/health` | DB connectivity check |
| POST / GET | `/projects` | create / list |
| GET / PATCH / DELETE | `/projects/{id}` | get / update / delete (cascades) |
| POST / GET | `/projects/{id}/targets` | create (rejects unauthorized) / list |
| GET | `/projects/{id}/targets/{target_id}` | get one |
| POST | `/scans` | body: `project_id`, `target_id`, optional `config`; validates target belongs to project and is authorized; inserts with `status=CREATED` |
| GET | `/scans` | list, optional `?project_id=` filter |
| GET | `/scans/{id}` | full detail |
| GET | `/scans/{id}/status` | slim status-only read |
| POST | `/scans/{id}/cancel` | legal only from `CREATED`/`QUEUED` → `CANCELLED`; 409 if already running/terminal |

`api/deps.py` provides `get_db`, `get_project_or_404`, `get_target_or_404` helpers shared across route modules.

---

## 5. Frontend Skeleton

- Next.js App Router + TypeScript strict + Tailwind (`create-next-app --typescript --tailwind --app --src-dir --eslint`).
- `lib/api/client.ts`: minimal typed `fetch` wrapper (`NEXT_PUBLIC_API_URL` base, throws on non-2xx). Per-entity modules (`projects.ts`, `targets.ts`, `scans.ts`) wrap it with typed functions — **no fetch calls inside components/pages directly**.
- Pages:
  - `/projects` — list + create form.
  - `/projects/[projectId]` — target list (with authorization badge) + `TargetForm` (client-side required-checked validation mirroring the backend rejection) + scan list/create with target dropdown.
  - `StatusBadge.tsx` — maps every `ScanStatus` value to a Tailwind color (only `CREATED`/`QUEUED`/`CANCELLED` reachable now, but built for the full enum so Phase 2 needs no changes here).
- Keep it simple: no charts, no auth pages, no dark-mode toggle — explicitly deferred to later phases.

---

## 6. Docker Compose

`docker-compose.yml` defines four services: `postgres` (16-alpine, healthcheck via `pg_isready`), `redis` (7-alpine, no consumer yet), `backend` (dev Dockerfile, `uvicorn --reload`, bind-mounted, depends on postgres healthy), `frontend` (dev Dockerfile, `npm run dev`, bind-mounted **with an anonymous volume on `/app/node_modules`** to avoid Windows bind-mount shadowing native binaries like `@next/swc`).

Windows-specific notes to put in the README:
1. Anonymous `node_modules` volume is required — without it, Windows bind-mounting over the container's Linux `node_modules` breaks native binaries.
2. `.gitattributes` (`* text=auto eol=lf`) prevents CRLF from breaking Alpine images/shell steps.
3. `uvicorn --reload` / Next dev server file-watching can be slow over Windows bind mounts — document `WATCHFILES_FORCE_POLLING` / `WATCHPACK_POLLING` as opt-in env vars if hot reload doesn't fire.
4. Ports 5432/6379 commonly collide with existing local installs — note how to remap.
5. Save `.env`/`.env.example` as UTF-8 without BOM (Notepad defaults to BOM, which breaks pydantic-settings' dotenv parsing).

`.env.example` at repo root covers Postgres creds, `DATABASE_URL`, `REDIS_URL`, `ENVIRONMENT`, `LOG_LEVEL`, `CORS_ORIGINS`, `NEXT_PUBLIC_API_URL`, and commented-out polling fallbacks.

---

## 7. Testing

**Backend (pytest)**: `conftest.py` provides a `TestClient` fixture with `get_db` overridden to a test session (against a separate `vulnsight_test` database; `create_all` once per session, rollback per test for isolation). First concrete tests:
1. Health check returns 200.
2. Create + list a project.
3. Target creation rejects `authorization_confirmed=False` (422); accepts `True` (201).
4. Targets are scoped correctly per project.
5. Scan creation is rejected if the target isn't authorized (service-layer check).
6. Scan is created in `CREATED` status; status endpoint reflects it.
7. Cancel transitions `CREATED → CANCELLED`; cancelling again returns 409.

Version-matching, CVE-correlation, and risk-scoring test suites are explicitly out of scope until their respective later phases.

**Frontend**: optional lightweight Vitest + Testing Library smoke test for `StatusBadge` only — no E2E (Playwright/Cypress) yet.

**Lint/format**: `ruff check .`, `black --check .`, `mypy app` (backend); `next lint` (frontend). No CI workflow file yet, but commands should be copy-paste-ready for when CI is added.

---

## 8. Build Order

1. `git init` + `.gitignore`/`.gitattributes`/`.editorconfig`/`README.md`.
2. Bare FastAPI (`/health` static) and bare Next.js app, run directly on host (no Docker yet) to confirm toolchains.
3. Dockerize both + minimal `docker-compose.yml` (backend + frontend only) — verify hot reload through containers.
4. Add `postgres` service + `db/session.py` + `core/config.py`; make `/health` do `SELECT 1`.
5. Add `redis` service (unused) — verify it starts cleanly.
6. Add SQLAlchemy models + `db/base.py`; init Alembic; generate + apply first migration; verify tables via `psql \dt`.
7. Add `Project` schemas/service/routes; verify via Swagger UI (`/docs`).
8. Add `Target` schemas/service/routes (with authorization validation); verify via `/docs`.
9. Add `Scan` schemas/service/routes (including status + cancel); verify via `/docs`.
10. Write backend pytest suite; get it green; wire ruff/black/mypy and fix violations.
11. Build frontend API client + types against the now-stable contracts.
12. Build `/projects` page against the live backend.
13. Build `/projects/[projectId]` page (targets + scans + `StatusBadge`).
14. Optional frontend smoke test + lint config.
15. Full-stack pass: `docker compose down -v && docker compose up --build`, run the verification plan below end-to-end.

---

## 9. Verification Plan

```powershell
docker compose up --build

curl http://localhost:8000/api/v1/health
# {"status":"ok","environment":"development"}

docker compose exec backend alembic upgrade head
docker compose exec postgres psql -U vulnsight -d vulnsight -c "\dt"
# projects, targets, scans, alembic_version

# create a project, view it at http://localhost:3000/projects
curl -X POST http://localhost:8000/api/v1/projects -H "Content-Type: application/json" `
  -d '{"name":"Acme Corp Pentest","description":"Q4 authorized engagement"}'

# authorized target succeeds; unauthorized target -> 422
curl -X POST http://localhost:8000/api/v1/projects/$PROJECT_ID/targets -H "Content-Type: application/json" `
  -d '{"value":"10.0.0.5","target_type":"ip","authorization_confirmed":true}'

# create a scan -> status "created"; GET .../status reflects it
curl -X POST http://localhost:8000/api/v1/scans -H "Content-Type: application/json" `
  -d '{"project_id":"'$PROJECT_ID'","target_id":"'$TARGET_ID'"}'

# view target (authorized badge) + scan (CREATED badge) at http://localhost:3000/projects/$PROJECT_ID

docker compose exec backend pytest -v
docker compose exec backend ruff check .
docker compose exec backend mypy app
docker compose exec frontend npm run lint
```

Pass criteria: all API calls return expected status/bodies, both frontend pages render created data with no console errors, pytest is green, lint/type-check pass clean.

---

## Roadmap Beyond This Plan (not detailed here)

- **Phase 2 — Scan Orchestration**: Celery app consuming the already-provisioned Redis broker; `PortScannerInterface` with `NmapPortScanner`/`NativePortScanner` adapters under `modules/discovery/`; drives `Scan.status` through the full lifecycle; persists discovered `Asset`/`Service` rows. Likely needs one additive migration (e.g. `celery_task_id` on `Scan`).
- **Phase 3 — Service Fingerprinting**: version/banner/HTTP detection, evidence storage.
- **Phase 4 — Vulnerability Correlation**: product/version normalization, CPE mapping, CVE lookup, version-range matching.
- **Phase 5 — Confidence & Validation**: confidence scoring, validation states, false-positive handling.
- **Phase 6 — Misconfiguration Analysis**: HTTP headers, TLS, exposed services.
- **Phase 7 — Risk Intelligence**: configurable VRPS scoring.
- **Phase 8 — Reporting**: executive summary, findings detail, HTML then PDF.

Each of these should get its own detailed plan once the current foundation is built and verified, per the "build vertically, don't overengineer the MVP" principle in the spec.
