# VulnSight — Phase 2 Implementation Plan: Scan Orchestration

## Context

Phase 0 (foundation) and Phase 1 (Project/Target/Scan CRUD) are complete, merged to `main`, and fully tested (17 backend tests, ruff/black/mypy/eslint/tsc all clean). Right now, creating a scan just inserts a row with `status=CREATED` — nothing actually executes. Phase 2's job, per the master spec's roadmap ("Basic Scanning Pipeline": target submission → scan job creation → background worker → basic host/service discovery → result storage → scan status updates), is to make a scan **actually run**: a Celery worker picks it up, performs real port discovery against the target, persists what it finds, and drives `Scan.status` through the lifecycle.

Decisions confirmed with the project owner before this plan was written:
- **Build both scanner adapters now** (`NativePortScanner` and `NmapPortScanner`) behind one `PortScannerInterface`, proving the adapter pattern immediately rather than deferring the second implementation.
- **Default scan profile**: a conservative "common ports" set (not the full 1–65535 range), with capped concurrency and short per-connection timeouts — fast, low-noise, safe against IDS/rate-limiting even on an authorized target.
- **Backend only this phase.** No frontend changes — verification is via the API/tests/curl, matching the "build vertically" pattern from Phase 0/1. A results view becomes an early Phase 3 task once fingerprinting data makes it worth building.

One thing this plan does that wasn't asked for in the final Phase 0/1 review but follows directly from it: **Target value format validation is Task 1**, before any scanner code exists. The final review flagged that `Target.value` currently accepts any string for any `target_type`, and warned this becomes a real subprocess-safety question the moment a scanner adapter exists (the Nmap adapter shells out to a real binary). Validating IP/hostname/CIDR format up front, and making "the scanner interface never receives an unvalidated string" an explicit invariant, closes that gap before it can bite.

### Explicit scope limits for this phase (documented, not accidental)

- **No CIDR range scanning.** A `Target` with `target_type=cidr` can still be created (existing behavior), but a scan against one fails fast with a clear `error_message` ("CIDR range scanning is not yet supported") rather than silently doing nothing or attempting subnet expansion. Host discovery/ping-sweep logic for ranges is real scope, deliberately deferred rather than bolted on here.
- **No mid-scan cancellation.** Cancelling a scan is only legal from `CREATED`/`QUEUED` (unchanged from Phase 1) — cancelling a `QUEUED` scan now also revokes the pending Celery task. Killing an already-`RUNNING` scan (terminating in-flight sockets/subprocesses safely) is a real feature with its own edge cases, deferred.
- **Service identification is a static port→name lookup only** (e.g. port 22 → "ssh"), not banner grabbing or version detection — that's Phase 3 ("Service Fingerprinting"). Phase 2 answers "is this port open," not "what's running on it."
- **One Asset per scan** (the target's own host) — the `Asset`/`Service` schema is built as first-class entities per the master spec's data model (anchoring future Technology/Finding association), but the *population logic* stays simple until subnet expansion is real: no asset deduplication across repeated scans of the same target yet.

---

## 1. Target Value Validation (Task 1 — must land before any scanner code)

`backend/app/schemas/target.py`'s `TargetCreate` gets a `field_validator` on `value`, dispatched on `target_type`:
- `target_type=ip` → must parse via `ipaddress.ip_address(value)`.
- `target_type=cidr` → must parse via `ipaddress.ip_network(value, strict=False)`.
- `target_type=domain` / `hostname` → must match a conservative hostname regex (RFC 1123-ish: labels of `[a-zA-Z0-9-]`, no leading/trailing hyphen per label, dot-separated, max length checks) — reject anything containing shell metacharacters, whitespace, or control characters outright regardless of regex specifics (belt-and-suspenders, since this string may eventually reach a subprocess argument list).

On failure: `ValueError` → FastAPI 422, consistent with the existing `authorization_confirmed` validator's pattern in the same file.

This is the invariant the rest of the phase leans on: **no code in `app/modules/discovery/` ever needs to re-validate `target.value`'s shape** — by the time a `Target` row exists, its `value` already matches its declared `target_type`.

---

## 2. Data Model Additions

### `backend/app/models/asset.py` (new)
```python
class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=False)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)  # the exact value scanned (mirrors target.value for this phase)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    services: Mapped[list["Service"]] = relationship(back_populates="asset", cascade="all, delete-orphan", passive_deletes=True)
```

### `backend/app/models/service.py` (new)
```python
class Service(Base):
    __tablename__ = "services"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False, default="tcp")
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="open")  # only "open" is persisted this phase
    service_name: Mapped[str | None] = mapped_column(String(50), nullable=True)  # static port->name guess, e.g. "ssh"; null if unknown
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    asset: Mapped["Asset"] = relationship(back_populates="services")
```

### `backend/app/models/scan.py` (additive columns via new migration, not a regeneration — the bootstrap "regenerate the one migration" phase is over now that FK indexes etc. already exist)
- `celery_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)`
- `error_message: Mapped[str | None] = mapped_column(Text, nullable=True)`

`app/db/base.py` gets `Asset`/`Service` added to its model-registration imports (same pattern as `Project`/`Target`/`Scan`). New Alembic migration: `alembic revision --autogenerate -m "add assets, services tables; scan celery_task_id, error_message columns"`.

---

## 3. Discovery Module (`backend/app/modules/discovery/`)

### `interfaces.py`
```python
@dataclass(frozen=True)
class PortScanResult:
    port: int
    protocol: str  # "tcp"
    state: str     # "open"

class PortScannerInterface(Protocol):
    def scan(self, host: str, ports: list[int], timeout_seconds: float) -> list[PortScanResult]: ...
```

### `common_ports.py`
A curated constant list of ~100–150 common TCP ports (FTP, SSH, Telnet, SMTP, DNS, HTTP/HTTPS, POP3, IMAP, SMB, RDP, VNC, common DB ports — MySQL/Postgres/MSSQL/Mongo/Redis/Elasticsearch, Docker/K8s API, common web-app/proxy ports) plus a `PORT_NAMES: dict[int, str]` lookup used to populate `Service.service_name`. Documented explicitly as *a pragmatic curated set, not literally nmap's frequency-ranked top-1000* — the `NmapPortScanner` adapter uses nmap's real `--top-ports 1000` instead when it's the selected engine, so the two adapters don't need to agree on an identical port list.

### `native_scanner.py` — `NativePortScanner`
Pure Python, `asyncio`-based TCP-connect scan: for each port, attempt `asyncio.open_connection(host, port)` with a short timeout (default 1.5s), bounded by a `asyncio.Semaphore` (default max 50 concurrent connections) so the whole run stays a "conservative rate" scan. A successful connect = open; timeout/refused/unreachable = not open (not persisted — only open ports become `Service` rows, per the scope limits above). No external binary, no elevated privileges needed.

### `nmap_scanner.py` — `NmapPortScanner`
Shells out to the real `nmap` binary via `subprocess.run` with **list-form arguments only** (never `shell=True`, never string-formatted into a shell command) — `["nmap", "-sT", "-p", port_spec, "-oX", "-", host]` (`-sT` = TCP connect scan, so no `CAP_NET_RAW` needed in the container; `-oX -` = XML output to stdout). Parses the XML via `xml.etree.ElementTree` into the same `list[PortScanResult]`. The raw XML output is captured and returned/logged alongside the parsed result (not discarded) — this is a deliberate nod to the project's "preserve raw evidence" principle, and sets up Phase 3's fingerprinting work to consume the same XML for service/version detection later. `backend/Dockerfile` gets `apt-get install -y --no-install-recommends nmap` added (this is the same image used for both the `backend` API container and the new `worker` container, so both get it — harmless for the API container, which never invokes it).

Both adapters are exercised by unit tests against a **local test TCP listener** the test spins up itself (`socketserver`/`asyncio.start_server` on `127.0.0.1` with a random free port) — never against a real external host. This proves both "port is open" and "port is not open" detection without any network dependency or safety concern in CI.

---

## 4. Celery Orchestration

### `backend/app/workers/celery_app.py`
```python
celery_app = Celery("vulnsight", broker=settings.REDIS_URL, backend=settings.REDIS_URL)
celery_app.autodiscover_tasks(["app.workers"])
```

### `backend/app/workers/tasks.py` — `run_scan_task(scan_id: str)`
Runs in the worker process (separate from FastAPI — gets its own `SessionLocal()` session, not a request-scoped one). Sequence:
1. Load the `Scan`; if missing or already `CANCELLED`, return early (a cancel-before-pickup race).
2. `status = RUNNING`, `started_at = now()`, commit.
3. `status = DISCOVERY`, commit.
4. Dispatch on `target.target_type`: if `cidr` → `status = FAILED`, `error_message = "CIDR range scanning is not yet supported"`, `completed_at = now()`, commit, return.
5. Otherwise, pick the adapter from `scan.config.get("scanner", "native")` (`"native"` → `NativePortScanner`, `"nmap"` → `NmapPortScanner`; unrecognized value → `FAILED` with a clear `error_message`, not a silent fallback).
6. Run the scan against `target.value` with the default port profile (native: curated list; nmap: `--top-ports 1000`).
7. On success: create one `Asset` row (`host=target.value`) and one `Service` row per open port (with `service_name` from the static lookup where known), commit; `status = COMPLETED`, `completed_at = now()`, commit.
8. On any exception during steps 4–7: `status = FAILED`, `error_message = str(exc)` (truncated to a sane length), `completed_at = now()`, commit — the task must never let an exception propagate silently past this without the DB reflecting `FAILED`.

### `docker-compose.yml`
New `worker` service: same `build: ./backend` as `backend`, `command: celery -A app.workers.celery_app worker --loglevel=info`, same `DATABASE_URL`/`REDIS_URL` env vars, `depends_on: postgres: condition: service_healthy` + `redis`. Bind-mounted like `backend` for hot-reload-equivalent dev convenience (Celery's `--autoreload` isn't reliable across versions, so a manual `docker compose restart worker` after code changes during development is the documented workaround, same spirit as the Windows hot-reload notes already in the README).

### API wiring (`backend/app/services/scan_service.py`, `backend/app/api/routes/scans.py`)
- `create_scan`: after inserting the `Scan` row (`status=CREATED`), immediately calls `run_scan_task.delay(str(scan.id))`, stores the returned task id in `scan.celery_task_id`, sets `status=QUEUED`, commits. (If enqueueing itself raises — e.g. Redis unreachable — the scan is left in `CREATED` with no task id, and the exception propagates as a 500 via the existing catch-all handler; not silently swallowed.)
- `cancel_scan`: unchanged legality check (`CREATED`/`QUEUED` only), but when cancelling a `QUEUED` scan with a `celery_task_id`, also calls `celery_app.control.revoke(scan.celery_task_id)` best-effort (revoke failures are logged, not fatal to the cancel API call — the DB status change is the authoritative outcome either way).

---

## 5. Testing

- **`test_target_validation.py`**: valid/invalid IP, CIDR, hostname values for each `target_type`; confirms 422 on malformed input including shell-metacharacter injection attempts (e.g. `"; rm -rf /"` as a hostname).
- **`test_native_scanner.py`** / **`test_nmap_scanner.py`**: against a local test listener — confirms an open port is detected, a closed/unlistened port is not, and (for nmap) that the XML parsing produces the same `PortScanResult` shape. Nmap tests are skipped gracefully (not failed) if the `nmap` binary isn't on `PATH` in whatever environment runs them — since the Docker image will always have it, this only matters for a hypothetical bare-host test run.
- **`test_scan_orchestration.py`**: calls `run_scan_task` directly (not through the broker) with a mocked scanner adapter — verifies the full status transition sequence, `Asset`/`Service` persistence, the `CIDR`-rejection path, and the exception → `FAILED` + `error_message` path.
- **`test_scans.py` additions**: `POST /scans` (with Celery's `.delay` mocked/patched so the test doesn't need a live worker) results in `status=QUEUED` and a populated `celery_task_id`; cancelling a `QUEUED` scan calls `revoke` (mocked) and still transitions to `CANCELLED`.

---

## 6. Verification Plan

```bash
docker compose up --build   # now also brings up the `worker` service
docker compose exec backend alembic upgrade head

# create project + authorized target (ip type) via curl, as in Phase 1
# create a scan
curl -X POST http://localhost:8000/api/v1/scans -H "Content-Type: application/json" \
  -d '{"project_id":"...","target_id":"...","config":{"scanner":"native"}}'
# -> status "queued", celery_task_id populated

# poll status until it reaches "completed" (or "failed")
curl http://localhost:8000/api/v1/scans/<id>/status

# confirm discovered services persisted
docker compose exec postgres psql -U vulnsight -d vulnsight -c \
  "SELECT s.port, s.service_name FROM services s JOIN assets a ON a.id = s.asset_id WHERE a.scan_id = '<scan_id>';"

# repeat with {"config":{"scanner":"nmap"}} against the same target, confirm equivalent results

# confirm CIDR targets fail cleanly
# confirm cancelling a QUEUED scan actually revokes the Celery task (check worker logs)

docker compose exec backend pytest -v   # all green, including new suites
docker compose exec backend ruff check . && black --check . && mypy app
```

A realistic, reachable, already-authorized scan target for manual verification: the `backend` container itself (via its Docker Compose service name/IP, port 8000) or `postgres`/`redis` (ports 5432/6379) — all inside the same Docker network, safe and legitimate to scan for verification purposes without touching anything external.

---

## Roadmap Beyond This Plan (not detailed here)

- **Phase 3 — Service Fingerprinting**: consume the Nmap adapter's already-preserved raw XML (and HTTP response headers for web ports) to move from "port 80 is open" to "nginx 1.24.0 is running on port 80," with evidence storage. Also the natural point to add a minimal frontend results view, per this phase's deferred scope decision.
- **Phase 4 — Vulnerability Correlation**: CPE mapping, CVE lookup, version-range matching against Phase 3's fingerprints.
- **Phase 5 — Confidence & Validation**, **Phase 6 — Misconfiguration Analysis**, **Phase 7 — Risk Intelligence**, **Phase 8 — Reporting**: unchanged from the original roadmap.

Each retains its own detailed plan once the phase before it is built and verified, per the "build vertically" principle.
