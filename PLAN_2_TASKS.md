# VulnSight — Phase 2 Task-Based Execution Plan

Companion to `PLAN_2.md` (narrative plan, already written with the decisions
below). `PLAN_2.md` is the binding authority for anything a task here
doesn't fully specify. No separate formal spec file exists beyond
`PLAN_1.md`/`PLAN_2.md` — rulings made while executing this are provisional
per normal process.

Scope: Phase 2 (Scan Orchestration) only — a Celery worker that actually
executes scans, port discovery via two interchangeable adapters, and
persisted Asset/Service results. Backend only; no frontend changes.

## Global Constraints

1. **Stack additions**: Celery (already in `requirements.txt` from Phase 0,
   unused until now), Redis as broker+result-backend (already provisioned).
   `nmap` binary added to `backend/Dockerfile`.
2. **No CIDR scanning.** A scan against a `cidr`-type target must reach
   `status=FAILED` with `error_message="CIDR range scanning is not yet
   supported"` — never attempt subnet expansion, never silently no-op.
3. **No mid-scan cancellation.** Cancel remains legal only from
   `CREATED`/`QUEUED` (unchanged from Phase 1). Cancelling `QUEUED` also
   best-effort revokes the Celery task.
4. **Target values are pre-validated by the time any scanner code runs**
   (Task 1 establishes this). No discovery-module code re-validates
   `target.value`'s shape — trust the invariant, don't defensively
   re-check it.
5. **Subprocess safety is non-negotiable for the Nmap adapter**: list-form
   `subprocess.run` arguments only, never `shell=True`, never string-
   interpolated commands. This is the reason Task 1 (validation) must land
   before Task 4 (Nmap adapter) — don't reorder.
6. **Only open ports are persisted** as `Service` rows this phase — no
   closed/filtered noise.
7. **Service identification is a static port→name lookup only** — no
   banner grabbing, no version detection (that's Phase 3). Don't add
   fingerprinting logic even if it seems easy while you're in this code.
8. **One `Asset` per (non-CIDR) scan**, no cross-scan deduplication yet.
   Don't build asset-history/dedup logic — out of scope.
9. **Celery tasks get their own DB session** (`SessionLocal()`, opened and
   closed within the task) — never share a FastAPI request-scoped session
   across the broker boundary.
10. **Every status transition is committed as it happens**, not batched at
    the end — if a task crashes mid-scan, the DB should reflect the last
    real transition (e.g. `DISCOVERY`), not silently stay at `QUEUED`.
11. **No frontend changes in this phase.** Verification is via API/curl/
    tests only.
12. Follow the established Phase 0/1 conventions: thin routes, business
    logic in services, `NotFoundError`/`ValidationConflictError`/
    `ScanStateError` exception pattern, SQLAlchemy 2.x `Mapped`/
    `mapped_column` style, ruff/black/mypy all clean.

---

## Task 1: Target value format validation

Add a `field_validator` on `TargetCreate.value` in
`backend/app/schemas/target.py`, dispatched on `target_type`:
- `ip` → must parse via `ipaddress.ip_address(value)`.
- `cidr` → must parse via `ipaddress.ip_network(value, strict=False)`.
- `domain`/`hostname` → must match a conservative hostname pattern (labels
  of `[a-zA-Z0-9-]`, no leading/trailing hyphen per label, dot-separated,
  overall length ≤ 253, each label ≤ 63 chars per RFC 1035/1123). Reject
  anything containing whitespace, shell metacharacters (`;`, `|`, `&`,
  `` ` ``, `$`, `<`, `>`, quotes), or control characters outright, even if
  it would otherwise loosely match a permissive regex — this string may
  eventually reach a subprocess argument list (Task 4), so be strict.

On failure: raise `ValueError` with a message naming the expected format —
FastAPI turns this into a 422, consistent with the existing
`authorization_confirmed` validator's pattern in the same file.

**Tests** (`backend/tests/test_targets.py`, extend existing file): valid
IP/CIDR/hostname per type → 201; invalid format per type → 422; a hostname
value containing shell metacharacters (e.g. `"host; rm -rf /"`) → 422
regardless of target_type; an IP-shaped string submitted with
`target_type=hostname` is fine to accept (types aren't mutually exclusive
in that direction — an IP address is a syntactically valid hostname too;
only reject when the value doesn't match ITS OWN declared type's rules).

**Acceptance**: `docker compose exec backend pytest -v` green including
new cases; `ruff`/`black`/`mypy` clean.

---

## Task 2: Asset & Service models, Scan additive columns, migration

Create `backend/app/models/asset.py`:
```python
class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=False)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    services: Mapped[list["Service"]] = relationship(back_populates="asset", cascade="all, delete-orphan", passive_deletes=True)
```

Create `backend/app/models/service.py`:
```python
class Service(Base):
    __tablename__ = "services"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False, default="tcp")
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    service_name: Mapped[str | None] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    asset: Mapped["Asset"] = relationship(back_populates="services")
```

Update `backend/app/models/scan.py`: add
`celery_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)`
and `error_message: Mapped[str | None] = mapped_column(Text, nullable=True)`.

Update `backend/app/db/base.py` to import `Asset`/`Service` alongside the
existing model imports (same registration pattern as Phase 1 — reuse
`app.db.base_class.Base`, don't reintroduce the circular-import shape that
was fixed in Phase 1).

Generate an **additive** migration (do NOT regenerate/drop the existing
one — that bootstrap phase is over):
`alembic revision --autogenerate -m "add assets, services tables; scan celery_task_id, error_message columns"`.
Review the generated migration for correctness (both new tables, both new
`scans` columns, indexes on `assets.project_id`/`assets.target_id`/
`assets.scan_id`/`services.asset_id`), apply it, verify via
`docker compose exec postgres psql -U vulnsight -d vulnsight -c "\dt"` and
`"\d scans"`.

**Acceptance**: migration applies cleanly on top of the existing schema
(no data loss — verify by creating a project/target/scan before and after
the migration and confirming it's still there); `\dt` shows `assets`,
`services`; `\d scans` shows the two new columns.

---

## Task 3: Discovery interfaces, common ports, NativePortScanner

Create `backend/app/modules/discovery/interfaces.py`:
```python
from dataclasses import dataclass
from typing import Protocol

@dataclass(frozen=True)
class PortScanResult:
    port: int
    protocol: str
    state: str

class PortScannerInterface(Protocol):
    def scan(self, host: str, ports: list[int], timeout_seconds: float) -> list[PortScanResult]: ...
```

Create `backend/app/modules/discovery/common_ports.py`: a curated constant
`COMMON_PORTS: list[int]` (roughly 100-150 ports spanning FTP(21)/SSH(22)/
Telnet(23)/SMTP(25)/DNS(53)/HTTP(80)/POP3(110)/IMAP(143)/HTTPS(443)/
SMB(445)/MSSQL(1433)/MySQL(3306)/RDP(3389)/PostgreSQL(5432)/VNC(5900)/
Redis(6379)/Elasticsearch(9200)/common web-app and proxy ports/Docker
(2375-2376)/Kubernetes API(6443), etc.) and a `PORT_NAMES: dict[int, str]`
lookup for the same ports (e.g. `{22: "ssh", 80: "http", 443: "https",
...}`). Document in a module docstring that this is a pragmatic curated
set, not nmap's proprietary frequency-ranked top-1000 — the Nmap adapter
(Task 4) uses nmap's own `--top-ports 1000` instead.

Create `backend/app/modules/discovery/native_scanner.py` —
`NativePortScanner` implementing `PortScannerInterface.scan`: `asyncio`-
based TCP-connect attempt per port (`asyncio.open_connection(host, port)`
wrapped in `asyncio.wait_for(..., timeout=timeout_seconds)`), bounded by
an `asyncio.Semaphore` capping concurrent connection attempts (default
50). A successful connect = open (append a `PortScanResult`); any
exception (timeout, connection refused, unreachable) = not open, not
appended. The synchronous `scan()` method wraps the async work internally
(e.g. `asyncio.run(...)`) so callers (the Celery task) don't need to know
it's async internally.

**Tests** (`backend/tests/test_native_scanner.py`): spin up a local TCP
listener in the test itself (`socketserver.TCPServer` or
`asyncio.start_server` bound to `127.0.0.1` on a random free port —
`port=0` and read back the bound port), scan `127.0.0.1` including that
port plus a couple of definitely-closed ports (e.g. `port+1` unless
already bound), assert the listener's port is detected open and the
others aren't. Never scan a real external host in this test.

**Acceptance**: `docker compose exec backend pytest -v` green; new module
has no import-time side effects (importing it doesn't open sockets).

---

## Task 4: NmapPortScanner adapter + Dockerfile

Update `backend/Dockerfile`: add
`RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*`
(before the `pip install` step or after — either works, just keep the
image layer count sane; document your choice).

Create `backend/app/modules/discovery/nmap_scanner.py` — `NmapPortScanner`
implementing `PortScannerInterface.scan`: builds a **list-form** subprocess
command — `["nmap", "-sT", "--top-ports", "1000", "-oX", "-", host]` when
`ports` is empty/None (using nmap's own top-ports selection), or
`["nmap", "-sT", "-p", ",".join(str(p) for p in ports), "-oX", "-", host]`
when an explicit port list is given — via `subprocess.run(cmd,
capture_output=True, text=True, timeout=<a sane overall timeout, e.g.
120s>, check=False)`. **Never** use `shell=True`, never build the command
via string formatting/concatenation of `host` into a shell string. Parse
the XML from `result.stdout` via `xml.etree.ElementTree` into
`list[PortScanResult]` (look for `<port>` elements with
`<state state="open">`). If `nmap` exits non-zero or the XML doesn't
parse, raise an exception with the captured `stderr`/output included (the
orchestration task in Task 6 will turn this into `status=FAILED` +
`error_message`) — don't silently return an empty list on a real failure
vs. a real "no open ports found" result; distinguish them.

**Tests** (`backend/tests/test_nmap_scanner.py`): same local-listener
approach as Task 3's native scanner test. If `nmap` isn't found on `PATH`
in whatever environment runs the test (`shutil.which("nmap") is None`),
`pytest.skip(...)` rather than fail — the Docker image will always have it
installed, this guard only matters for a hypothetical bare-host test run.

**Acceptance**: `docker compose up --build` succeeds with `nmap` installed
in the image (`docker compose exec backend nmap --version` succeeds);
pytest green (or cleanly skipped if nmap truly isn't available, which
shouldn't happen inside the container).

---

## Task 5: Celery app + Docker Compose worker service

Create `backend/app/workers/celery_app.py`:
```python
from celery import Celery
from app.core.config import get_settings

settings = get_settings()
celery_app = Celery("vulnsight", broker=settings.REDIS_URL, backend=settings.REDIS_URL)
celery_app.autodiscover_tasks(["app.workers"])
```

Create a trivial placeholder task in `backend/app/workers/tasks.py` for
this task only (e.g. `@celery_app.task def ping() -> str: return "pong"`)
— the REAL orchestration task (`run_scan_task`) is Task 6; this task is
purely about proving the Celery+Redis+worker-container wiring works
before building real scan logic on top of it.

Update `docker-compose.yml`: add a `worker` service — `build: ./backend`
(same Dockerfile/image as `backend`), `command: celery -A
app.workers.celery_app worker --loglevel=info`, same `DATABASE_URL`/
`REDIS_URL` env vars as `backend`, `volumes: - ./backend:/app` (same bind
mount as backend, for dev convenience — note in a comment that Celery
doesn't reliably autoreload on code changes, so `docker compose restart
worker` is the expected workflow during development, mirroring the
Windows hot-reload note already in the README), `depends_on: postgres:
condition: service_healthy` and `redis`.

**Verify**: `docker compose up --build` brings up all 5 services now
(postgres, redis, backend, frontend, worker); `docker compose logs
worker` shows Celery's startup banner with no errors and the `ping` task
registered; from a Python shell inside the backend container (or a tiny
throwaway script), call `ping.delay()` and confirm the result (via
`.get(timeout=10)`) is `"pong"`, proving the full broker+worker round
trip.

**Acceptance**: 5-service `docker compose up --build` clean; `ping` task
round-trips successfully.

---

## Task 6: Scan orchestration task

In `backend/app/workers/tasks.py`, replace/add alongside the Task 5
placeholder: `run_scan_task(scan_id: str)`, a `@celery_app.task`-decorated
function. Sequence (open a `SessionLocal()` at the top, `try/finally:
db.close()` around the whole body):

1. `scan = db.get(Scan, uuid.UUID(scan_id))`; if `None` or
   `scan.status == ScanStatus.CANCELLED`, return early (log at info level,
   no exception) — handles the cancel-before-pickup race.
2. `scan.status = ScanStatus.RUNNING`; `scan.started_at = datetime.now(UTC)`; commit.
3. `scan.status = ScanStatus.DISCOVERY`; commit.
4. Load `scan.target` (relationship or explicit query). If
   `target.target_type == TargetType.CIDR`: `scan.status =
   ScanStatus.FAILED`, `scan.error_message = "CIDR range scanning is not
   yet supported"`, `scan.completed_at = datetime.now(UTC)`, commit,
   return.
5. Wrap steps 5-7 in `try/except Exception as exc`: pick the adapter from
   `scan.config.get("scanner", "native")` — `"native"` →
   `NativePortScanner()`, `"nmap"` → `NmapPortScanner()`, anything else →
   raise `ValueError(f"Unknown scanner '{...}'")` (caught by the same
   except block below, becomes a normal `FAILED` outcome, not an
   unhandled crash).
6. Call `adapter.scan(target.value, ports, timeout_seconds=...)` — for
   `"native"`, `ports=COMMON_PORTS` from Task 3; for `"nmap"`, pass an
   empty/`None` ports arg so the adapter uses `--top-ports 1000`
   internally (per Task 4's design) — the orchestration task doesn't need
   to duplicate nmap's own top-ports list.
7. On success: create one `Asset(project_id=scan.project_id,
   target_id=scan.target_id, scan_id=scan.id, host=target.value)`, one
   `Service` row per result in the returned list (`service_name` from
   `PORT_NAMES.get(port)`), `db.add_all(...)`, commit; `scan.status =
   ScanStatus.COMPLETED`, `scan.completed_at = datetime.now(UTC)`, commit.
8. `except Exception as exc`: `scan.status = ScanStatus.FAILED`,
   `scan.error_message = str(exc)[:2000]` (truncate — don't let a huge
   traceback blow out the column), `scan.completed_at = datetime.now(UTC)`,
   commit. Also log the full exception server-side (via the logging
   module from Phase 0) before truncating what goes in the DB column.

**Tests** (`backend/tests/test_scan_orchestration.py`): call
`run_scan_task` directly (not through the broker — call the underlying
function, not `.delay()`) with a **mocked scanner adapter** (patch
`NativePortScanner.scan` or inject a fake) to avoid any real network
activity in this test file (Tasks 3/4 already cover real-scanner
correctness against a local listener). Cover: full happy path (status
ends at `COMPLETED`, `Asset`+`Service` rows exist with correct data); CIDR
target → `FAILED` with the exact expected `error_message`, no scan
attempted; the mocked scanner raising an exception → `FAILED` with
`error_message` containing the exception's message; an already-cancelled
scan → task returns without changing status further.

**Acceptance**: pytest green; every status transition in the sequence
above is exercised by at least one test.

---

## Task 7: API wiring — enqueue on create, revoke on cancel

Update `backend/app/services/scan_service.py`'s `create_scan`: after the
existing authorization/project/target checks and the initial insert
(`status=CREATED`), call `run_scan_task.delay(str(scan.id))`, store
`scan.celery_task_id = result.id`, set `scan.status = ScanStatus.QUEUED`,
commit. If `.delay(...)` itself raises (e.g. Redis unreachable), let the
exception propagate — it becomes a 500 via the existing `SQLAlchemyError`/
catch-all handling path is NOT correct here since this isn't a DB error;
confirm what actually happens (likely an unhandled exception → FastAPI's
default 500) and decide whether that's acceptable for this phase or needs
its own handling — your call, document the reasoning in your report. The
scan row itself should NOT be left half-committed in an inconsistent
state either way (the initial `CREATED` insert already committed
separately from the enqueue step, so worst case a scan sits at `CREATED`
forever if enqueueing fails — note this as a known, acceptable-for-now
gap, not something to solve with cross-transaction tricks in this task).

Update `cancel_scan`: after the existing state-check/transition to
`CANCELLED`, if the scan had a `celery_task_id`, call
`celery_app.control.revoke(scan.celery_task_id)` in a `try/except
Exception` that logs on failure but does NOT prevent the cancel from
succeeding — the DB status change is the authoritative outcome.

**Tests** (`backend/tests/test_scans.py`, extend existing file): patch/mock
`run_scan_task.delay` (so no real broker round-trip happens in this
API-level test) to return a fake result object with a `.id`; confirm
`POST /scans` response has `status="queued"` and a non-null implied
`celery_task_id` (check via a direct DB read if `ScanRead` doesn't expose
it — if it doesn't, that's fine, `celery_task_id` is an internal field,
not necessarily part of the public API response; your call whether to add
it to `ScanRead`, document the decision). Confirm cancelling a `QUEUED`
scan calls the mocked `revoke` with the right task id.

**Acceptance**: pytest green; `ruff`/`black`/`mypy` clean.

---

## Task 8: Full-stack verification pass

Fresh `docker compose down -v && docker compose up --build` (all 5
services). Apply the migration. Then, using a real in-Docker-network,
already-authorized target (e.g. the `backend` service's own hostname on
port 8000, or `postgres`/`redis` — legitimate to scan since they're part
of this same authorized system, no external network access needed):

1. Create a project, an authorized `ip` or `hostname`-type target pointing
   at one of the in-network services, and a scan with
   `config: {"scanner": "native"}`. Poll `/scans/{id}/status` until it
   reaches `completed` (or `failed` — investigate if so). Query
   `assets`/`services` tables directly to confirm the expected port(s)
   show up as open.
2. Repeat with `config: {"scanner": "nmap"}` against the same target,
   confirm broadly equivalent results (exact port sets may differ
   slightly between the curated list and nmap's top-1000 — that's
   expected and fine, just confirm the known-open port(s) show up in
   both).
3. Create a `cidr`-type target, start a scan, confirm it reaches `failed`
   with the exact documented `error_message`.
4. Create and immediately cancel a scan (racing the worker is fine either
   way — confirm the cancel API call succeeds and check `docker compose
   logs worker` for a revoke-related log line or task execution,
   whichever actually happened).
5. Run the full backend suite: `pytest -v`, `ruff check .`, `black
   --check .`, `mypy app` — all green.
6. Bring the stack down cleanly (no `-v`, leave state inspectable).

This is not a feature-writing task — fix only narrow integration issues
you find (same scope-discipline principle as Phase 1's Task 9/13). If
something reveals an architectural gap rather than an integration
correction, report BLOCKED/NEEDS_CONTEXT instead of improvising a
redesign.

**Acceptance**: all 6 steps above pass as described; report the full
transcript/evidence.
