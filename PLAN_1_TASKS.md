# VulnSight — Phase 0 + Phase 1 Task-Based Execution Plan

This is the execution-ready, task-numbered companion to `PLAN_1.md` (the
narrative plan already reviewed and approved by the project owner). There is
no separate formal "spec" document beyond `PLAN_1.md` — treat `PLAN_1.md` as
the binding authority for anything a task below doesn't fully specify, and
treat the Global Constraints section here as the condensed, load-bearing
subset of it. This plan has no external spec file, so any ruling made while
executing it is provisional per normal process.

Scope: Phase 0 (project foundation: runnable full-stack skeleton) and
Phase 1 (Project / Target / Scan data model + CRUD, no scan execution yet).
Nothing past Phase 1 (actual scanning, fingerprinting, CVE correlation,
misconfiguration analysis, risk scoring, reporting) is in scope for these
tasks.

## Global Constraints

Apply these to every task below, not just the ones that mention them:

1. **Stack**: Backend = Python 3.12, FastAPI, SQLAlchemy 2.x (`DeclarativeBase`
   style), Alembic, `psycopg[binary]` (v3 driver), Pydantic v2 +
   `pydantic-settings`, pytest, ruff, black, mypy. Frontend = Next.js (App
   Router) + TypeScript (strict) + Tailwind CSS. DB = PostgreSQL 16. Redis 7
   is provisioned via Docker Compose starting in Task 4 but has **no
   consumer** until a later phase (Celery orchestration) — do not add Celery
   code now.
2. **No authentication.** No `users` table, no login/register routes, no
   JWT, no session concept. Projects/Targets/Scans are not scoped to a user.
   Do not add placeholder auth scaffolding "for later."
3. **API prefix**: every backend route lives under `/api/v1` (mounted via
   `app.include_router(..., prefix="/api/v1")` in `app/main.py`), except the
   health check which is also reachable at `/api/v1/health`.
4. **Thin routes, logic in services.** Route handler functions in
   `app/api/routes/*.py` only: parse/validate via FastAPI+Pydantic, call one
   function in the matching `app/services/*_service.py`, translate
   service-layer exceptions to HTTP responses. All business rules
   (authorization checks, status-transition legality, existence checks)
   live in the service layer, not in route handlers.
5. **Authorization is enforced twice, deliberately:**
   - Schema layer: `TargetCreate` Pydantic schema has a `field_validator`
     that raises `ValueError` if `authorization_confirmed` is not `True`
     (FastAPI turns this into a 422).
   - Service layer: `scan_service.create_scan` re-checks that the target
     referenced by `target_id` has `authorization_confirmed is True` in the
     database before inserting a `Scan` row, and raises a domain exception
     that the route maps to HTTP 400 if not. This is deliberate
     defense-in-depth (a target's authorization flag could theoretically be
     revoked after creation in a later phase) — do not simplify this down to
     a single check.
6. **`Scan.status` enum contains the full future lifecycle** even though only
   a few values are reachable by any code path in this plan:
   `CREATED, QUEUED, RUNNING, DISCOVERY, FINGERPRINTING, ANALYZING,
   CORRELATING, RISK_ANALYSIS, REPORT_GENERATION, COMPLETED, FAILED,
   CANCELLED` (exact spelling/casing: Python enum members are these names
   uppercase, values are the lowercase string, e.g. `CREATED = "created"`).
   Do not trim this enum to only the values used now.
7. **No fetch calls inside frontend page/components directly** — all HTTP
   calls go through `src/lib/api/*.ts` wrapper functions that pages and
   components call.
8. **IDs are UUIDs** (`uuid.uuid4` default) for `Project`, `Target`, `Scan`.
9. **Windows/Docker specifics** (apply wherever relevant): frontend Docker
   volume mounts must use an anonymous volume on `/app/node_modules` to
   avoid Windows bind-mounts shadowing Linux-built native binaries;
   `.env`/`.env.example` files must be saved as UTF-8 without BOM.
10. Do not create files for Phase 2+ functionality (no `celery_app.py`, no
    `nmap_scanner.py`, no `cpe_mapper.py`, etc.) — `app/modules/*` and
    `app/workers/` only get empty `__init__.py` placeholders in this plan.
11. **Every task that adds backend code must leave `docker compose up`
    working** (or, for Tasks 1-2 before Docker exists, leave the bare host
    toolchain working) — don't leave the stack broken between tasks.
12. Commit at the end of each task with a message describing what was added
    (implementer's normal responsibility, not spelled out per-task below).

---

## Task 1: Repository scaffolding for backend and frontend

Create the directory/file skeleton (no business logic yet) so later tasks
have a place to put code:

```
backend/
  .dockerignore
  requirements.txt
  app/
    __init__.py
    core/__init__.py
    db/__init__.py
    models/__init__.py
    schemas/__init__.py
    api/__init__.py
    api/routes/__init__.py
    services/__init__.py
    modules/__init__.py
    modules/discovery/__init__.py
    modules/fingerprinting/__init__.py
    modules/vulnerability/__init__.py
    modules/misconfiguration/__init__.py
    modules/risk/__init__.py
    modules/reporting/__init__.py
    workers/__init__.py
  tests/__init__.py

frontend/
  .dockerignore
```

`backend/requirements.txt` (pin loosely by major version, exact versions are
the implementer's judgment call as long as they're current stable releases
compatible with Python 3.12):
```
fastapi
uvicorn[standard]
sqlalchemy>=2.0
alembic
psycopg[binary]
pydantic>=2.0
pydantic-settings
python-dotenv
celery
redis
pytest
pytest-cov
httpx
ruff
black
mypy
```

`backend/.dockerignore`:
```
__pycache__/
*.pyc
.venv/
.pytest_cache/
.mypy_cache/
.ruff_cache/
tests/
```

`frontend/.dockerignore`:
```
node_modules/
.next/
```

No Dockerfiles yet (Task 3), no `docker-compose.yml` yet (Task 3), no
`main.py` yet (Task 2). This task is purely the directory/package skeleton
plus dependency manifest.

**Acceptance**: directory tree above exists exactly; `pip install -r
backend/requirements.txt` succeeds in a throwaway virtualenv (or report the
command was run and succeeded — a full env isn't required to persist).

---

## Task 2: Bare backend and bare frontend running on host (no Docker)

**Backend**: create `backend/app/main.py` with a FastAPI app exposing
`GET /health` returning a static `{"status": "ok"}` (no DB, no config module
yet — those come in Task 4). Verify with `uvicorn app.main:app --reload`
from `backend/` and `curl http://localhost:8000/health`.

**Frontend**: scaffold with `npx create-next-app@latest frontend
--typescript --tailwind --app --src-dir --eslint --no-import-alias` (or
equivalent flags for the current create-next-app version — use whatever
produces an App Router + TypeScript + Tailwind + `src/` layout project;
adjust flags to the installed CLI version's actual options and note in your
report what flags you used). Verify with `npm run dev` from `frontend/` and
loading `http://localhost:3000` in a way you can confirm renders (curl for
a 200 status is sufficient if a browser isn't available).

Do not add Docker files in this task. Do not add any API-calling code to the
frontend yet — it's the default `create-next-app` starter page at this
point.

**Acceptance**: `uvicorn app.main:app --reload` serves `/health` returning
200 with `{"status":"ok"}`; `npm run dev` serves the Next.js starter page on
port 3000 with a 200 response.

---

## Task 3: Dockerize backend + frontend, minimal Docker Compose (no DB yet)

Create `backend/Dockerfile`:
```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
```

Create `frontend/Dockerfile`:
```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev"]
```

Create `docker-compose.yml` at the repo root with exactly two services for
now:
```yaml
services:
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    volumes:
      - ./backend:/app
    ports:
      - "8000:8000"

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    volumes:
      - ./frontend:/app
      - /app/node_modules
    ports:
      - "3000:3000"
    depends_on:
      - backend
```

(`postgres`/`redis` services, env vars, and `depends_on: condition:
service_healthy` are added in Task 4 — do not add them here.)

Verify: `docker compose up --build`, then `curl http://localhost:8000/health`
returns 200, and `curl -I http://localhost:3000` returns 200. Confirm hot
reload works for at least the backend (edit a trivial string in `/health`'s
response while the stack is running, confirm the change appears without a
rebuild) — note the result in your report; if hot reload doesn't fire,
report it as a concern rather than silently leaving it broken (Windows
bind-mount file-watching can be slow; if it's simply slow rather than
non-functional, that's an acceptable, reportable concern, not a blocker).

**Acceptance**: `docker compose up --build` brings up both containers
cleanly; both health/root endpoints respond as above.

---

## Task 4: PostgreSQL + Redis services, backend DB config/session, DB-backed health check

Add to `docker-compose.yml`: a `postgres` service (`postgres:16-alpine`,
env `POSTGRES_USER=vulnsight`, `POSTGRES_PASSWORD=vulnsight`,
`POSTGRES_DB=vulnsight`, port `5432:5432`, a named volume
`postgres_data:/var/lib/postgresql/data`, and a healthcheck: `test:
["CMD-SHELL", "pg_isready -U vulnsight"]`, `interval: 5s`, `timeout: 5s`,
`retries: 5`); and a `redis` service (`redis:7-alpine`, port `6379:6379`,
no healthcheck needed, no consumer — it's provisioned now for later phases
per Global Constraint 1). Declare the `postgres_data` named volume at the
bottom of the compose file. Add `depends_on: postgres: condition:
service_healthy` to the `backend` service.

Add environment variables to the `backend` service in compose:
`DATABASE_URL=postgresql+psycopg://vulnsight:vulnsight@postgres:5432/vulnsight`,
`REDIS_URL=redis://redis:6379/0`, `ENVIRONMENT=development`,
`LOG_LEVEL=INFO`. Add `NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1` to
the `frontend` service's environment.

Create `.env.example` at the repo root documenting all of the above (plus
commented-out `# WATCHFILES_FORCE_POLLING=true` / `#
WATCHPACK_POLLING=true` for the Windows hot-reload fallback mentioned in
Global Constraint 9). Save it as UTF-8 without BOM.

Backend code — create `backend/app/core/config.py`:
```python
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    DATABASE_URL: str
    REDIS_URL: str = "redis://localhost:6379/0"
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]
    API_V1_PREFIX: str = "/api/v1"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

@lru_cache
def get_settings() -> Settings:
    return Settings()
```

Create `backend/app/db/session.py`:
```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import get_settings

engine = create_engine(get_settings().DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

Create `backend/app/db/base.py`:
```python
from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
    pass
```
(No model imports yet — those are added in Task 5 when models exist.)

Update `app/main.py`: add CORS middleware allowing
`get_settings().CORS_ORIGINS`; move the health check into
`app/api/routes/health.py` as `GET /health` (mounted with the `/api/v1`
prefix per Global Constraint 3 — so it's reachable at
`/api/v1/health`) that now runs `db.execute(text("SELECT 1"))` via the
`get_db` dependency and returns `{"status": "ok", "environment":
settings.ENVIRONMENT}`.

**Acceptance**: `docker compose up --build`; `docker compose ps` shows
`postgres` healthy; `curl http://localhost:8000/api/v1/health` returns 200
with the DB-backed response; `docker compose logs redis` shows Redis
started with no errors; stopping/restarting the stack preserves Postgres
data (named volume works).

---

## Task 5: SQLAlchemy models, Alembic setup, first migration

Create `backend/app/models/project.py`:
```python
import uuid
from datetime import datetime
from sqlalchemy import String, Text, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base

class Project(Base):
    __tablename__ = "projects"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    targets: Mapped[list["Target"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    scans: Mapped[list["Scan"]] = relationship(back_populates="project", cascade="all, delete-orphan")
```

Create `backend/app/models/target.py`:
```python
import uuid, enum
from datetime import datetime
from sqlalchemy import String, Text, Boolean, ForeignKey, DateTime, func, Enum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base

class TargetType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    CIDR = "cidr"

class Target(Base):
    __tablename__ = "targets"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[TargetType] = mapped_column(Enum(TargetType, name="target_type"), nullable=False)
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    authorization_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    project: Mapped["Project"] = relationship(back_populates="targets")
```

Create `backend/app/models/scan.py`:
```python
import uuid, enum
from datetime import datetime
from sqlalchemy import ForeignKey, DateTime, func, Enum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base

class ScanStatus(str, enum.Enum):
    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    DISCOVERY = "discovery"
    FINGERPRINTING = "fingerprinting"
    ANALYZING = "analyzing"
    CORRELATING = "correlating"
    RISK_ANALYSIS = "risk_analysis"
    REPORT_GENERATION = "report_generation"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus, name="scan_status"), default=ScanStatus.CREATED, nullable=False)
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    project: Mapped["Project"] = relationship(back_populates="scans")
    target: Mapped["Target"] = relationship()
```

Update `backend/app/db/base.py` to import all three models below the `Base`
class definition (so Alembic autogenerate sees them via `Base.metadata`):
```python
from app.models.project import Project  # noqa: F401
from app.models.target import Target  # noqa: F401
from app.models.scan import Scan  # noqa: F401
```

Run `alembic init migrations` inside `backend/`. Edit the generated
`migrations/env.py` so `target_metadata = Base.metadata` (import from
`app.db.base`) and the DB URL comes from
`app.core.config.get_settings().DATABASE_URL` (not a hardcoded value in
`alembic.ini` — override `config.set_main_option("sqlalchemy.url", ...)` in
`env.py`). Generate the first migration:
`alembic revision --autogenerate -m "initial schema: projects, targets, scans"`.
Review the generated migration file to confirm it creates all three tables
plus the `target_type` and `scan_status` Postgres enum types, then apply it:
`alembic upgrade head` (run this against the Dockerized Postgres, e.g. via
`docker compose exec backend alembic upgrade head`, or from the host with
`DATABASE_URL` pointed at `localhost:5432` — either is acceptable as long as
you verify the result against the actual running Postgres container).

**Acceptance**: `docker compose exec postgres psql -U vulnsight -d
vulnsight -c "\dt"` lists `projects`, `targets`, `scans`, `alembic_version`;
`\dT` (or `\dT+`) shows `target_type` and `scan_status` enum types with the
expected members.

---

## Task 6: Project CRUD (schemas, service, routes)

Create `backend/app/schemas/project.py` (Pydantic v2, `ConfigDict(from_attributes=True)`):
- `ProjectBase`: `name: str`, `description: str | None = None`
- `ProjectCreate(ProjectBase)`
- `ProjectUpdate`: `name: str | None = None`, `description: str | None = None` (all optional, for PATCH)
- `ProjectRead(ProjectBase)`: adds `id: uuid.UUID`, `created_at: datetime`, `updated_at: datetime`

Create `backend/app/core/exceptions.py`:
```python
class NotFoundError(Exception):
    pass

class ValidationConflictError(Exception):
    pass
```
Register FastAPI exception handlers in `app/main.py` (or a small
`register_exception_handlers(app)` helper called from there) mapping
`NotFoundError` -> HTTP 404 `{"detail": str(exc), "code": "not_found"}` and
`ValidationConflictError` -> HTTP 400 `{"detail": str(exc), "code":
"conflict"}`.

Create `backend/app/services/project_service.py` with functions
`create_project(db, data: ProjectCreate) -> Project`,
`list_projects(db) -> list[Project]`,
`get_project(db, project_id) -> Project` (raises `NotFoundError` if
missing), `update_project(db, project_id, data: ProjectUpdate) -> Project`,
`delete_project(db, project_id) -> None`.

Create `backend/app/api/deps.py`:
```python
from app.db.session import get_db  # re-export

def get_project_or_404(project_id, db):
    ...  # thin wrapper calling project_service.get_project, letting NotFoundError propagate to the handler
```

Create `backend/app/api/routes/projects.py` implementing:
- `POST /projects` (201, body `ProjectCreate`, returns `ProjectRead`)
- `GET /projects` (200, returns `list[ProjectRead]`)
- `GET /projects/{project_id}` (200 or 404)
- `PATCH /projects/{project_id}` (200 or 404, body `ProjectUpdate`)
- `DELETE /projects/{project_id}` (204 or 404)

Mount this router in `app/main.py` under the `/api/v1` prefix.

**Acceptance**: via `/docs` (Swagger UI) or curl — create a project, list
it, get it by id, patch its description, delete it, confirm a subsequent
GET on the deleted id returns 404.

---

## Task 7: Target CRUD with authorization enforcement

Create `backend/app/schemas/target.py`:
- `TargetBase`: `value: str`, `target_type: TargetType`, `authorization_note: str | None = None`
- `TargetCreate(TargetBase)`: adds `authorization_confirmed: bool`, with a
  `field_validator("authorization_confirmed")` that raises `ValueError(
  "Target must be confirmed as authorized before it can be added")` if the
  value is not `True`. (This must produce a 422 from FastAPI — verify it
  does, don't just trust the validator syntax.)
- `TargetRead(TargetBase)`: adds `id`, `project_id`, `authorization_confirmed: bool`, `created_at`

Create `backend/app/services/target_service.py`:
`create_target(db, project_id, data: TargetCreate) -> Target` (raises
`NotFoundError` if `project_id` doesn't exist), `list_targets(db,
project_id) -> list[Target]`, `get_target(db, project_id, target_id) ->
Target` (raises `NotFoundError` if missing or if it belongs to a different
project — targets must be scoped correctly per project).

Create `backend/app/api/routes/targets.py`:
- `POST /projects/{project_id}/targets` (201, or 404 if project missing, or
  422 if unauthorized per the schema validator)
- `GET /projects/{project_id}/targets` (200, list scoped to that project only)
- `GET /projects/{project_id}/targets/{target_id}` (200 or 404)

Mount under `/api/v1`.

**Acceptance**: creating a target with `authorization_confirmed: false`
returns 422; with `true` returns 201; a target created under project A does
not appear when listing project B's targets; getting a target by the wrong
project_id returns 404.

---

## Task 8: Scan CRUD with status and cancel

Create `backend/app/schemas/scan.py`:
- `ScanCreate`: `project_id: uuid.UUID`, `target_id: uuid.UUID`, `config: dict = {}`
- `ScanRead`: `id`, `project_id`, `target_id`, `status: ScanStatus` (serializes
  as the string value), `config: dict`, `created_at`, `updated_at`,
  `started_at: datetime | None`, `completed_at: datetime | None`
- `ScanStatusRead`: `id`, `status`, `updated_at` (slim schema for the status
  endpoint)

Create `backend/app/services/scan_service.py`:
- `create_scan(db, data: ScanCreate) -> Scan`: verify `project_id` exists
  (`NotFoundError` if not), verify `target_id` exists **and belongs to that
  project** (`NotFoundError` if not), verify
  `target.authorization_confirmed is True` (raise
  `ValidationConflictError("Target is not confirmed as authorized")` if not
  — this becomes a 400, per Global Constraint 5's service-layer
  re-check), then insert with `status=ScanStatus.CREATED`.
- `list_scans(db, project_id: uuid.UUID | None = None) -> list[Scan]`
- `get_scan(db, scan_id) -> Scan` (raises `NotFoundError`)
- `cancel_scan(db, scan_id) -> Scan`: raises `NotFoundError` if missing;
  raises `ValidationConflictError("Scan cannot be cancelled from status
  '<status>'")` (-> 409, not 400 — map `ValidationConflictError` to 400
  generically per Task 6, but this specific case needs 409; either add a
  distinct exception type `ScanStateError` mapped to 409, or special-case it
  in the route — your call, document which you chose) unless current status
  is `CREATED` or `QUEUED`; otherwise sets status to `CANCELLED` and
  persists.

Create `backend/app/api/routes/scans.py`:
- `POST /scans` (201, or 404/400 per above)
- `GET /scans` (200, optional `?project_id=` query filter)
- `GET /scans/{scan_id}` (200 or 404)
- `GET /scans/{scan_id}/status` (200 or 404, returns `ScanStatusRead`)
- `POST /scans/{scan_id}/cancel` (200 with updated `ScanRead`, 404, or 409)

Mount under `/api/v1`.

**Acceptance**: creating a scan against an authorized target returns 201
with `status: "created"`; against an unauthorized target returns 400 (test
this by creating a target then manually flipping
`authorization_confirmed` to `False` directly in the DB in your
verification, since the API itself won't let you create one unauthorized —
or verify the check exists in code and exercise it via a unit test in Task
9); `GET /scans/{id}/status` reflects current status; cancelling a
`CREATED` scan returns 200 with `status: "cancelled"`; cancelling it again
returns 409.

---

## Task 9: Backend pytest suite, lint, and type-check config

Create `backend/tests/conftest.py` with:
- A `TEST_DATABASE_URL` (e.g. same Postgres instance/container, database
  name `vulnsight_test` — add a note to `.env.example` and/or
  `docker-compose.yml` if a second database needs to be created; simplest
  approach: connect to the same `postgres` service and `CREATE DATABASE
  vulnsight_test` if it doesn't exist, or use `Base.metadata.create_all`
  against it once per test session).
- A `db` fixture yielding a SQLAlchemy session, wrapping each test in a
  transaction that's rolled back after the test for isolation.
- A `client` fixture: `TestClient(app)` with `app.dependency_overrides[get_db]`
  pointed at the test session.

Write these test files (one file per entity, matching Global Constraint's
acceptance criteria from Tasks 6-8):
- `tests/test_health.py`: `GET /api/v1/health` returns 200.
- `tests/test_projects.py`: create + list a project; get by id; patch;
  delete; get-after-delete is 404.
- `tests/test_targets.py`: authorization_confirmed=False rejected with 422;
  True accepted with 201; targets correctly scoped per project (a target
  under project A is absent from project B's list).
- `tests/test_scans.py`: creating a scan against an authorized target
  succeeds with status "created"; creating a scan against a target whose
  `authorization_confirmed` is `False` (set directly via the DB session in
  the test, bypassing the API, to simulate the service-layer defense) is
  rejected with 400; `GET /scans/{id}/status` reflects status; cancelling a
  `CREATED` scan transitions it to `CANCELLED` (200); cancelling again
  returns 409.

Add `backend/pyproject.toml` with `[tool.pytest.ini_options]
testpaths = ["tests"]`, plus `[tool.ruff]`, `[tool.black]`, and
`[tool.mypy]` sections with reasonable defaults (line length 100 is fine,
your call otherwise). Run `pytest -v`, `ruff check .`, `black --check .`,
`mypy app` and fix every violation until all four commands exit 0 (do not
suppress errors with blanket ignores — fix the underlying code/types,
except where a third-party library genuinely lacks type stubs, in which
case a targeted `# type: ignore[...]` with the specific error code is
acceptable).

**Acceptance**: all four commands (`pytest -v`, `ruff check .`, `black
--check .`, `mypy app`) run from `backend/` and exit 0, with pytest showing
all tests passing (report the exact count).

---

## Task 10: Frontend API client and types

Create `frontend/src/lib/types/project.ts`, `target.ts`, `scan.ts` — TypeScript
interfaces mirroring the backend Pydantic `*Read` schemas exactly (field
names, optionality, and the `ScanStatus` union type listing all twelve
lowercase string values from Task 5's `ScanStatus` enum).

Create `frontend/src/lib/api/client.ts`:
```ts
const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

export async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    throw new Error(`API error ${res.status}: ${await res.text()}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}
```

Create `frontend/src/lib/api/projects.ts`, `targets.ts`, `scans.ts` with
typed functions matching every backend route from Tasks 6-8: e.g.
`listProjects()`, `createProject(payload)`, `getProject(id)`,
`listTargets(projectId)`, `createTarget(projectId, payload)`,
`listScans(projectId?)`, `createScan(payload)`, `getScanStatus(scanId)`,
`cancelScan(scanId)`, etc. — one function per backend endpoint that the
frontend pages (Tasks 11-12) will need. Do not add functions for endpoints
no page will call in this plan (e.g. skip a `deleteProject` wrapper unless
Task 11 actually uses one — check Task 11/12 below before deciding).

Create `frontend/.env.local.example` with
`NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1` (UTF-8, no BOM).

**Acceptance**: TypeScript compiles with no errors (`npx tsc --noEmit` or
equivalent); no page/component exists yet that calls these — that's Tasks
11-12.

---

## Task 11: Frontend `/projects` page (list + create)

Create `frontend/src/components/ProjectForm.tsx` — a client component with
a controlled form (`name`, `description`) that calls `createProject` from
Task 10's API client on submit, then refreshes the list (e.g.
`router.refresh()` in the App Router, or local state re-fetch — your call,
document which).

Create `frontend/src/app/projects/page.tsx` — a server component that calls
`listProjects()` and renders the results (name, description, created date)
as a simple list/table, with `ProjectForm` rendered above or below it. Style
with Tailwind utility classes: clean, minimal, no chart libraries, no
dark-mode toggle (Global Constraint / plan §5).

Update `frontend/src/app/page.tsx` (the default Next.js root page) to
redirect to `/projects` (e.g. `redirect("/projects")` from
`next/navigation` in a server component, or a client-side redirect —
server-side is preferred).

**Acceptance**: running the dev server (host or Docker), visiting `/`
lands on `/projects`; the page lists any existing projects fetched from the
live backend; submitting the form creates a new project via the API and it
appears in the list without a manual page reload.

---

## Task 12: Frontend `/projects/[projectId]` page (targets + scans)

Create `frontend/src/components/StatusBadge.tsx` — takes a `ScanStatus`
value as a prop and renders a small colored badge; map every one of the
twelve enum values to a Tailwind color class (not just the three reachable
ones — e.g. greys for `created`/`queued`/`cancelled`, blues for the
in-progress states, green for `completed`, red for `failed` — exact color
choices are your call, but every enum value must have a mapping so no value
falls through to an "unknown" default).

Create `frontend/src/components/TargetForm.tsx` — client component with
`value`, a `target_type` `<select>` (ip/domain/hostname/cidr), and an
`authorization_confirmed` checkbox that is **required to be checked**
before the form will submit (client-side validation mirroring the backend's
422 rejection — disable the submit button, or show a validation message,
when unchecked). Calls `createTarget(projectId, payload)` on submit.

Create `frontend/src/components/ScanCreateButton.tsx` (or a small inline
form) — a `<select>` of the project's targets and a button that calls
`createScan({ project_id, target_id })`, then refreshes the scan list.

Create `frontend/src/app/projects/[projectId]/page.tsx` — server component
that calls `getProject(projectId)`, `listTargets(projectId)`, and
`listScans(projectId)`; renders: project name/description header, a target
list (value, type, an "Authorized" badge derived from
`authorization_confirmed`) with `TargetForm` below it, and a scan list
(id or a short prefix, target value, `StatusBadge`) with
`ScanCreateButton` below it.

**Acceptance**: visiting `/projects/<id>` for a project created in Task 11
shows its (initially empty) target and scan lists; creating a target
via the form (with the checkbox checked) shows it in the list with an
authorized badge; leaving the checkbox unchecked prevents submission;
creating a scan against that target shows it in the scan list with a grey
"created" status badge.

---

## Task 13: Full-stack verification pass

No new features — this task fixes any drift/integration issues found when
running the whole stack fresh, and produces the final verification
evidence.

1. `docker compose down -v` then `docker compose up --build`.
2. `curl http://localhost:8000/api/v1/health` — expect 200,
   `{"status":"ok","environment":"development"}`.
3. `docker compose exec backend alembic upgrade head` (idempotent if
   already applied) then `docker compose exec postgres psql -U vulnsight -d
   vulnsight -c "\dt"` — expect `projects`, `targets`, `scans`,
   `alembic_version`.
4. Create a project via `curl -X POST
   http://localhost:8000/api/v1/projects ...`; confirm it appears at
   `http://localhost:3000/projects`.
5. Create an authorized target under it via curl; confirm a curl POST with
   `authorization_confirmed: false` returns 422; confirm the authorized one
   appears at `http://localhost:3000/projects/<id>` with an authorized
   badge.
6. Create a scan via curl; confirm `GET /scans/{id}/status` reflects
   `"created"`; confirm it appears in the frontend with a "created" status
   badge; cancel it via curl and confirm the frontend reflects `cancelled`
   after a refresh.
7. Run `docker compose exec backend pytest -v`, `ruff check .`, `mypy app`,
   and (in the frontend container or via `npm run lint` locally)
   `next lint` — all must pass cleanly.
8. Fix anything broken by the above (schema drift between backend and
   frontend types, a missed CORS origin, a Docker Compose ordering issue,
   etc.) and re-run the affected checks until everything in steps 1-7
   passes.

**Acceptance**: every check in steps 1-7 passes as described, on a fresh
`docker compose down -v && up --build`. Report the full command transcript
(or a faithful summary with exact outputs for the checks that matter) in
your task report.
