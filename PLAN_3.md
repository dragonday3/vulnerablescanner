# PLAN_3.md — VulnSight Phase 3 Implementation Plan: Service Fingerprinting

## Context

Phase 2 answered "is this port open." Phase 3 answers "what's running on it": for every open `Service` a scan discovers, attach product/version/evidence where it can be obtained cheaply and safely, store the raw evidence for audit/future re-parsing, and expose the result through a minimal frontend results view — closing the gap called out in Phase 2's own roadmap note ("the natural point to add a minimal frontend results view").

Two independent enrichment paths, matched to what each discovery adapter can produce without a second network round trip of unbounded scope:

- **`NmapPortScanner`**: gains `-sV` unconditionally. Nmap's own `-oX` output already carries a `<service>` element (name/product/version/extrainfo/method/conf) and `<cpe>` children the moment `-sV` is on — this is data the adapter is already parsing XML for, so capturing it is additive parsing, not a second scan.
- **`NativePortScanner`**: gains no version-detection ability of its own (a bare TCP connect never will). Instead, for the subset of open ports that look like they're serving HTTP(S), a *new, separate, best-effort* HTTP GET probe (`modules/fingerprinting/http_prober.py`, using `httpx`, promoted from dev-only to a runtime dependency) captures the `Server` header, status code, and page title as evidence. Non-web ports found by the native scanner are explicitly out of scope this phase — deferred, not a gap.

`ScanStatus.FINGERPRINTING` (already in the enum since Phase 0, never set) becomes real: it's set immediately after the discovery-stage `Asset`/`Service` commit, for **both** adapters uniformly (even though an nmap-adapter scan's enrichment work is already done by that point, folded for free into discovery) — this keeps the state machine adapter-agnostic and gives a later phase a stable hook to add more nmap-based enrichment without another status-machine change.

**Fingerprinting failures never fail the scan.** Discovery already succeeded and is already durably committed by the time fingerprinting runs; enrichment is additive evidence, not a hard requirement. A failed HTTP probe, an unreachable web port, or even a bug inside the prober module must leave the scan at `COMPLETED` with some (or all) `Service` fingerprint fields still `null` — never regress an already-successful discovery result to `FAILED`. This is enforced structurally (see §4) by keeping the fingerprinting enrichment in its own `try/except` block, separate from — and after — the existing discovery `try/except` that Phase 2 built.

### Explicit scope limits for this phase (documented, not accidental)

- **No generic banner-grabbing for the native scanner.** Only HTTP header probing, only for a curated allowlist of web-looking ports. A non-web open port found by the native scanner (e.g. a raw TCP service on port 9999) stays `fingerprint_source=None` this phase.
- **No dual-scheme HTTP fallback.** Each candidate port is probed with exactly one scheme, chosen by a small port-based heuristic (`443`/`4443`/`8443` → try `https://` first; everything else → `http://`). If that single attempt fails, the port is left unfingerprinted — no automatic retry with the other scheme. Keeps the enrichment pass's worst-case added time bounded and predictable.
- **No redirect-following in the HTTP prober** (`follow_redirects=False`) — a redirect to an attacker-controlled or unexpected host is exactly the SSRF-adjacent behavior a security-scanning backend must not exhibit automatically. The redirect response itself (3xx status + headers) is legitimate evidence and is captured as-is.
- **CIDR scanning is still unsupported** (Phase 2's scope limit, unchanged) — a CIDR-target scan still fails fast before any adapter runs, so it never reaches fingerprinting either.
- **`fingerprint_source` is documented as `"nmap-sv" | "http" | "port-guess" | None`, but this phase's code never writes `"port-guess"`.** Native-adapter non-web ports stay `fingerprint_source=None`, not `"port-guess"` — `"port-guess"` is reserved in the column's docstring for a possible future phase that might want to explicitly flag "this `service_name` is only the static `PORT_NAMES` lookup, with zero real evidence" as distinct from "we never even tried." Called out here so the reservation isn't silently dropped, but also isn't quietly implemented against instructions.
- **No asset/service deduplication changes** — unchanged from Phase 2, still out of scope.

---

## 1. Data Model Additions

### `backend/app/models/service.py` (edit — additive columns only)

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

    # --- Phase 3 additions ---
    # Structured, commonly-queried evidence fields. Populated from either
    # nmap's `-sV` <service> element or the HTTP prober's parsed `Server`
    # header — whichever adapter/pass produced them. `extrainfo` uses Text
    # (not String) because nmap's extrainfo field is free-text and can run
    # well past a short varchar (e.g. "Ubuntu Linux; protocol 2.0").
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    extrainfo: Mapped[str | None] = mapped_column(Text, nullable=True)
    # "nmap-sv" | "http" | None this phase ("port-guess" reserved, see
    # this doc's scope-limits note — not written by any Phase 3 code path).
    fingerprint_source: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Raw evidence, verbatim: nmap's full <service> attribute set + <cpe>
    # list, or the HTTP prober's status/headers/title. Always the source of
    # truth even when product/version above are only a best-effort parse of
    # part of it (e.g. splitting a `Server` header) — never lossy.
    evidence: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    asset: Mapped["Asset"] = relationship(back_populates="services")
```

New imports needed in `service.py`: `Text` from `sqlalchemy`, `JSONB` from `sqlalchemy.dialects.postgresql` (same pattern already used in `models/scan.py` for `config`).

### Migration (additive, generated — not a regeneration)

`alembic revision --autogenerate -m "add service fingerprint columns (product, version, extrainfo, fingerprint_source, evidence)"`. Expected generated body: five `op.add_column('services', ...)` calls, all nullable, no index changes, no data loss. Review the autogenerated file before applying (same discipline as Phase 2's Task 2), matching the naming/format of `backend/migrations/versions/26de1feba77b_add_assets_services_tables_scan_celery_.py`.

No changes to `Asset`, `Scan`, or `Target` this phase — the `FINGERPRINTING` status already exists in `ScanStatus`.

---

## 2. Discovery Interface & Nmap Adapter Changes

### `backend/app/modules/discovery/interfaces.py` (edit)

`PortScanResult` widens with optional evidence fields, defaulted so `NativePortScanner` (which never populates them) needs zero changes:

```python
@dataclass(frozen=True)
class PortScanResult:
    port: int
    protocol: str
    state: str
    # Optional fingerprinting evidence populated only by adapters that
    # obtain it "for free" during discovery itself — currently only
    # NmapPortScanner, since `-sV` runs in the same subprocess call as the
    # port scan. NativePortScanner leaves these at their defaults; its own
    # (separate, later) HTTP-based enrichment operates on already-persisted
    # Service rows instead (see tasks.py), not through this dataclass.
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    method: str | None = None
    cpe: tuple[str, ...] = ()
    raw_evidence: dict[str, object] | None = None


class PortScannerInterface(Protocol):
    def scan(self, host: str, ports: list[int], timeout_seconds: float) -> list[PortScanResult]: ...
```

### `backend/app/modules/discovery/nmap_scanner.py` (edit)

- Command becomes `cmd = ["nmap", "-sT", "-sV", *port_args, "-oX", "-", host]` — `-sV` added unconditionally, still list-form only, still no shell involvement (Phase 2's subprocess-safety invariant is untouched; `-sV` is just another literal argv element).
- Per `<port>` element, additionally: `service_el = port_el.find("service")`. If present, read `name`/`product`/`version`/`extrainfo`/`method`/`conf` attributes (all optional — nmap omits ones it has no data for) and `cpe_el.text for cpe_el in service_el.findall("cpe")`. Build `raw_evidence` as a dict of only the attributes that were actually present (never inject `None`/empty keys) plus a `"cpe"` list key if any CPEs were found.
- `PortScanResult` gains `service_name=service_el.get("name")`, `product=service_el.get("product")`, etc.; if `service_el is None` (nmap had literally nothing to say about that port), all the new fields stay at their dataclass defaults — this is a normal, expected outcome, not an error.
- Nothing about the "assert exactly one `<host>` element" security check changes.

### Nmap scan timeout re-verification (in `backend/app/workers/tasks.py`, same task)

`-sV` actively probes every *open* port with additional protocol handshakes, which is meaningfully slower than a bare `-sT` connect scan of the same port set (closed ports are unaffected — nmap doesn't run service probes against them). `NMAP_SCAN_TIMEOUT_SECONDS` (currently `120.0`, defined in `tasks.py`) must be re-measured against a real in-network target with `-sV` actually turned on before this phase is considered done — do not leave it at `120.0` by default assumption, and do not blindly double it either. Concretely: from inside the `worker` (or `backend`) container, time `NmapPortScanner().scan("<in-network host>", [], timeout_seconds=300)` against a target with at least one or two open ports (e.g. the `backend` service's own hostname on port 8000, or `postgres` on 5432 — the same authorized in-Docker-network targets Phase 2's verification used), record the observed wall-clock time, and set `NMAP_SCAN_TIMEOUT_SECONDS` to that measurement plus comfortable headroom (e.g. 2–3x, or a fixed floor like 180s, whichever is larger) — document the measured number and the chosen constant directly in the task's report, not just "seems fine."

---

## 3. HTTP Fingerprinting Module (native-adapter enrichment)

### `backend/app/modules/fingerprinting/http_prober.py` (new)

```python
"""Best-effort HTTP header/title probing for native-scanner-discovered
open ports that look like they serve HTTP(S).

Deliberately narrow in scope (see PLAN_3.md): a curated port allowlist,
one scheme attempt per port (no dual-scheme fallback), a short per-request
timeout distinct from the overall scan timeout, no redirect-following
(SSRF hygiene), and a bounded response-body read. Failure to probe an
individual port is swallowed here and simply omits that port from the
returned dict — callers (app.workers.tasks) never treat an empty/partial
result as an error.
"""

# Curated allowlist: the ports PLAN_3.md calls out explicitly, unioned
# with every port in modules.discovery.common_ports.PORT_NAMES whose name
# suggests a general-purpose web server (http/https/http-alt/http-proxy),
# hand-checked to exclude lookalikes that speak HTTP-ish protocols but
# aren't general web servers (e.g. 593 "http-rpc-epmap", 5985 "winrm").
WEB_PORTS: frozenset[int] = frozenset({
    80, 443, 3000, 4443, 4567, 5000, 5001,
    8000, 8008, 8080, 8081, 8088, 8090, 8222, 8443, 8888, 9000, 9999,
})

# Ports where an HTTPS attempt is tried first instead of HTTP.
_TLS_HEURISTIC_PORTS: frozenset[int] = frozenset({443, 4443, 8443})

HTTP_PROBE_TIMEOUT_SECONDS = 3.0
MAX_RESPONSE_BYTES = 8192
DEFAULT_MAX_CONCURRENCY = 10


@dataclass(frozen=True)
class HttpProbeResult:
    port: int
    scheme: str
    status_code: int
    server_header: str | None
    product: str | None       # best-effort parse of server_header
    version: str | None       # best-effort parse of server_header
    extrainfo: str | None     # best-effort parse remainder, if any
    title: str | None
    headers: dict[str, str]


def probe_services(
    host: str,
    ports: Iterable[int],
    timeout_seconds: float = HTTP_PROBE_TIMEOUT_SECONDS,
    max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
) -> dict[int, HttpProbeResult]: ...
```

Design notes:
- Sync wrapper over `asyncio.run(...)` internally using `httpx.AsyncClient(follow_redirects=False, timeout=timeout_seconds)`, bounded by an `asyncio.Semaphore(max_concurrency)` — mirrors `NativePortScanner`'s own concurrency-capping style for consistency.
- Body read is bounded to `MAX_RESPONSE_BYTES` via streaming (`client.stream("GET", url)`, read chunks until the cap, then close) — never buffers an unbounded response from a potentially hostile/misbehaving service.
- Title extraction: a bounded regex (`<title[^>]*>(.*?)</title>`, case-insensitive, dotall) against the capped body text, whitespace-collapsed, truncated to ~200 chars.
- `Server` header parsing (`_parse_server_header`, module-private): a light heuristic regex splitting `"nginx/1.24.0"` → `product="nginx", version="1.24.0"`, `"Apache/2.4.41 (Ubuntu)"` → `product="Apache", version="2.4.41", extrainfo="(Ubuntu)"`. Explicitly documented as best-effort — the raw header string is always also placed in `evidence` by the caller (§4) regardless of how the parse turns out, so nothing is lost if a `Server` header doesn't match the pattern.
- A per-port failure (connection refused, TLS error, timeout, non-HTTP response that can't even be read) is caught individually inside the per-port coroutine and that port is simply absent from the returned dict — never raises. A systemic failure (e.g. the function is called with bad arguments) is allowed to propagate, so it isn't silently indistinguishable from "every port failed" — `tasks.py`'s own outer `try/except` (§4) is the second line of defense against that case reaching the scan's status.

### `backend/requirements.txt` (edit)

Add `httpx~=0.28` (matching the version already verified in `requirements-dev.txt`) as a genuine runtime dependency — this is the one new stack addition this phase.

### `backend/requirements-dev.txt` (edit)

Remove the now-duplicate `httpx~=0.28` line and update the file's header comment (it currently frames httpx as "HTTP test client" / dev-only) — httpx is now a runtime dependency pulled in via `requirements.txt`, and `requirements-dev.txt` no longer needs its own declaration (the dev install already layers on top of the runtime one, per the existing `pip install -r requirements.txt -r requirements-dev.txt` pattern in `backend/Dockerfile`).

---

## 4. Orchestration Changes (`backend/app/workers/tasks.py`)

Sequence (extending, not replacing, Phase 2's `run_scan_task`):

1–5. Unchanged: load scan, `RUNNING`, `DISCOVERY`, CIDR fail-fast, authorization re-check.
6–7 (existing `try/except` block, edited): adapter selection + `adapter.scan(...)` unchanged in shape; `Service` construction now carries the new fields:

```python
service_name=result.service_name or PORT_NAMES.get(result.port),
product=result.product,
version=result.version,
extrainfo=result.extrainfo,
fingerprint_source="nmap-sv" if scanner_name == "nmap" else None,
evidence=result.raw_evidence,
```

  Note the `service_name` precedence flip from Phase 2: nmap's *own* service-name guess (even from its static `nmap-services` table lookup, not just a live probe) now wins over the locally curated `PORT_NAMES` dict when both exist — Phase 2 discarded nmap's own guess unconditionally; Phase 3 fixes that, since nmap's guess is generally more authoritative than a hand-curated fallback list.
  On exception: unchanged `FAILED` handling, **plus an explicit `return`** immediately after that commit (today's code relies on being the last statement in the function; once fingerprinting code follows, an explicit `return` is required so a discovery failure can never fall through into the fingerprinting/`COMPLETED` code below).

8. **New**: `scan.status = ScanStatus.FINGERPRINTING; db.commit()` — reached only after a successful discovery commit. Committed uniformly for both adapters (see §Context for why).

9. **New, its own `try/except Exception`, separate from step 6-7's block**: if `scanner_name == "native"`, compute `web_ports = [s.port for s in services if s.port in WEB_PORTS]` (using the already-in-session `services` ORM objects from step 7 — no re-query needed, matching the "Service rows created first, then updated in place" design chosen below); if any, call `probe_services(target.value, web_ports)`; for each `Service` whose port has a probe result, set `product`/`version`/`extrainfo`/`fingerprint_source="http"`/`evidence={"scheme":..., "status_code":..., "server": probe.server_header, "title": probe.title, "headers": probe.headers}` in place, then one `db.commit()` for the batch. On **any** exception in this block: `db.rollback()`, `logger.exception(...)` (non-fatal — no `scan.status` mutation, no `return`), and fall through to step 10 regardless. If `web_ports` is empty, `probe_services` is never called at all (no wasted work).

10. Unchanged: `scan.status = ScanStatus.COMPLETED; scan.completed_at = ...; db.commit()`.

**Sequencing decision (Service rows first, then updated in place) — and why:** `Service` rows are created and committed during the existing discovery step (unchanged from Phase 2), then updated in place during a second pass in the `FINGERPRINTING` phase, rather than doing per-port fingerprinting inline before any row exists. Reasoning:
- The Celery session (`db`) stays open for the whole task; the `Asset`/`Service` ORM objects created in step 7 remain valid, attached, and mutable for the rest of the task — no re-query is needed to "find" them again in step 9, just a plain attribute-set + one more `commit()`. This is the cheapest option that still respects "every status transition commits immediately."
- Doing fingerprinting inline *before* any `Service` row exists would mean either (a) blocking port-open persistence on a slow HTTP probe per port (worse latency, and couples two independently-failing operations into one atomic step), or (b) inventing a "pending evidence" holding structure to reconcile with rows written later — unnecessary complexity for a phase whose enrichment is explicitly best-effort and allowed to simply be absent.
- For nmap, there is no second pass at all — its evidence is already complete by the time the discovery commit happens (nmap's own subprocess call already ran `-sV`), so nmap-adapter scans pass through the `FINGERPRINTING` state with the enrichment `if` block skipped, and reach `COMPLETED` immediately after the same commit that step 8 already made.

---

## 5. Backend API: Asset/Service Exposure

### `backend/app/schemas/service.py` (new)

```python
class ServiceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    asset_id: uuid.UUID
    port: int
    protocol: str
    state: str
    service_name: str | None
    product: str | None
    version: str | None
    extrainfo: str | None
    fingerprint_source: str | None
    evidence: dict | None
    created_at: datetime
```

### `backend/app/schemas/asset.py` (new)

```python
class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    project_id: uuid.UUID
    target_id: uuid.UUID
    scan_id: uuid.UUID
    host: str
    created_at: datetime
    services: list[ServiceRead] = []
```

### New route: `GET /scans/{scan_id}/assets` — chosen over extending `ScanRead`

Decision: a **new, separate endpoint**, not nested assets/services on `ScanRead`. `ScanRead` is the response shape for `POST /scans`, `GET /scans` (list), and `GET /scans/{id}` — embedding assets there would mean every call to the scans-list endpoint (used by the existing project-detail page's scan table) eagerly loads and serializes every asset and service for every scan in the project's history, even though that table only ever displays a status badge. A dedicated sub-resource endpoint also matches the existing convention already established by `/scans/{id}/status` and `/scans/{id}/cancel` — a natural sibling, not a new shape of thing.

`backend/app/services/scan_service.py` (edit): add

```python
def get_scan_assets(db: Session, scan_id: uuid.UUID) -> list[Asset]:
    get_scan(db, scan_id)  # raises NotFoundError if the scan itself doesn't exist
    return (
        db.query(Asset)
        .options(selectinload(Asset.services))
        .filter(Asset.scan_id == scan_id)
        .order_by(Asset.created_at)
        .all()
    )
```

`backend/app/api/routes/scans.py` (edit): add

```python
@router.get("/{scan_id}/assets", response_model=list[AssetRead])
def get_scan_assets(scan_id: uuid.UUID, db: Session = Depends(get_db)) -> list[Asset]:
    return scan_service.get_scan_assets(db, scan_id)
```

A scan with no results yet (still `QUEUED`/`RUNNING`) returns `[]`, not an error — the frontend page (§6) must treat that as a legitimate "no results yet" state, not a fetch failure.

---

## 6. Frontend: Minimal Results View

### `frontend/src/lib/types/scan.ts` (edit)

Add the missing `error_message: string | null` field to `ScanRead` (fixes a pre-existing drift against the backend's actual `ScanRead` schema — folded into this task rather than its own, per the sizing note).

### `frontend/src/lib/types/asset.ts` (new), `frontend/src/lib/types/service.ts` (new)

TypeScript mirrors of `AssetRead`/`ServiceRead`. `fingerprint_source` typed as a union (`"nmap-sv" | "http" | "port-guess" | null`) even though the backend column is a plain nullable string — for display purposes only, following the same "exhaustive `Record`" convention `StatusBadge.tsx` already established, so adding a new source value later is a type-checked reminder to update the UI mapping, not a silent fallthrough.

### `frontend/src/lib/api/scans.ts` (edit)

Add `getScan(scanId): Promise<ScanRead>` (wraps the already-existing, previously-unused `GET /scans/{scan_id}`) and `getScanAssets(scanId): Promise<AssetRead[]>` (wraps the new route from §5).

### `frontend/src/components/FingerprintBadge.tsx` (new)

Small badge component for `fingerprint_source`, structurally identical to `StatusBadge.tsx`'s `Record<FingerprintSource-minus-null, string>` label/color-mapping pattern, with a distinct neutral style for `null` ("Unfingerprinted").

### `frontend/src/app/projects/[projectId]/scans/[scanId]/page.tsx` (new)

Server component, `export const dynamic = "force-dynamic"` (same reasoning as the existing project-detail page — scan/asset state changes live, must never be statically prerendered). Fetch pattern mirrors `[projectId]/page.tsx` exactly:
- `getScan(scanId)` is the one fetch the page can't render without — `try/catch`, route a genuine `"API error 404:"` to `notFound()`, anything else to the same inline "couldn't load" error card pattern already used.
- `listTargets(projectId)` (already exists, reused rather than adding a new `getTarget(id)` client/route) fetched separately, to resolve `scan.target_id` → the target's `value`/`target_type` for display, same join-client-side approach the project page already uses for its own scan table.
- `getScanAssets(scanId)` fetched separately with its own `try/catch` → inline error banner on failure; an empty array is rendered as "No results yet — scan is `<status>`" rather than an error, since that's the normal state for any non-terminal scan.

Layout: header card (short scan id, `StatusBadge`, resolved target value/type, `started_at`/`completed_at`, and — only when `status === "failed"` — the `error_message`, mirroring how `error_message` already exists on the backend `ScanRead` but was never surfaced anywhere in the frontend until this fix). Below it, one card-styled table per `Asset` (usually just one, per Phase 2's "one Asset per scan" scope limit) listing its `Service` rows: port, protocol, state, `service_name`, `product`/`version` (joined into one display string when both present), a `FingerprintBadge`, and a collapsible `<details>` element per row showing the raw `evidence` JSON for audit purposes — reusing the existing `<div className="... rounded-lg border ... bg-white shadow-sm">` / `<table className="w-full text-left text-sm">` styling already established by the targets/scans tables on the project page, not a new visual language.

### `frontend/src/app/projects/[projectId]/page.tsx` (edit)

The scan-id table cell changes from plain text (`{shortId(scan.id)}`) to `<Link href={`/projects/${projectId}/scans/${scan.id}`} className="font-mono text-xs text-zinc-600 hover:underline">{shortId(scan.id)}</Link>` — the only change to this existing file.

---

## 7. Testing

- **`test_nmap_scanner.py` (extend)**: (a) a deterministic unit test that monkeypatches `subprocess.run` to return a canned XML fixture string containing a `<service name="http" product="nginx" version="1.24.0" extrainfo="..." method="probed" conf="10"><cpe>cpe:/a:nginx:nginx:1.24.0</cpe></service>` element, asserting the exact field mapping into `PortScanResult` (deterministic — doesn't depend on nmap's actual probe behavior against a bare test listener); (b) the existing real-nmap-against-a-local-listener integration test extended to confirm the command now includes `-sV` and that the scan doesn't crash / still correctly reports the open port when nmap's own `-sV` probe against a non-standard test listener can't identify anything (i.e. `<service>` absent or unhelpful is a valid, non-error outcome).
- **`test_http_prober.py` (new)**: spins up a local `http.server.HTTPServer` (stdlib, background thread, `127.0.0.1`, random port) serving a response with a known `Server` header and an HTML `<title>`; asserts `probe_services` returns the correctly parsed `HttpProbeResult`. A second case against a port nothing is listening on → absent from the returned dict, no exception. A third case (a socket that accepts but never responds) → absent from the dict, no exception, and the call doesn't take meaningfully longer than the configured timeout. Never touches a real external host.
- **`test_scan_orchestration.py` (extend)**: nmap-path test asserting `Service.product`/`version`/`extrainfo`/`fingerprint_source="nmap-sv"`/`evidence` are populated from a mocked `NmapPortScanner.scan` return value carrying the new `PortScanResult` fields; native-path test mocking `http_prober.probe_services` to return a canned result for one of several fake open ports, asserting only the matching `Service` row gets `fingerprint_source="http"` + evidence while others stay `None`; a test where `probe_services` raises, asserting the scan still reaches `COMPLETED` with `error_message` still `None` and the affected `Service` rows' fingerprint fields still `None` (the core "never fail the scan" contract); a test confirming `scan.status` passes through `FINGERPRINTING` (assert via a spy/monkeypatch on `db.commit` call sequence, or by checking intermediate state if easily observable); a test confirming `probe_services` is never called at all when none of the discovered open ports are in `WEB_PORTS`.
- **New `test_scan_assets_route.py` (or extend `test_scans.py`)**: seed a scan + asset + services directly via the `db` fixture (same pattern already used elsewhere in the suite), call `GET /scans/{id}/assets`, assert 200 and the nested shape including the new fingerprint fields; 404 for a nonexistent scan id; `[]` for a real scan with no assets yet.

---

## 8. Verification Plan

```bash
docker compose up --build
docker compose exec backend alembic upgrade head
docker compose exec backend nmap --version   # confirm the binary is unchanged from Phase 2

# --- nmap path: real -sV against an in-network, already-authorized target ---
curl -X POST http://localhost:8000/api/v1/scans -H "Content-Type: application/json" \
  -d '{"project_id":"...","target_id":"...","config":{"scanner":"nmap"}}'
# poll until completed
curl http://localhost:8000/api/v1/scans/<id>/status

docker compose exec postgres psql -U vulnsight -d vulnsight -c \
  "SELECT s.port, s.service_name, s.product, s.version, s.fingerprint_source, s.evidence \
   FROM services s JOIN assets a ON a.id = s.asset_id WHERE a.scan_id = '<scan_id>';"
# expect at least one row with fingerprint_source='nmap-sv' and a non-null evidence JSON blob

# --- native path: HTTP evidence against an in-network web-serving target (e.g. the frontend container itself, port 3000) ---
curl -X POST http://localhost:8000/api/v1/scans -H "Content-Type: application/json" \
  -d '{"project_id":"...","target_id":"...","config":{"scanner":"native"}}'
curl http://localhost:8000/api/v1/scans/<id>/status

docker compose exec postgres psql -U vulnsight -d vulnsight -c \
  "SELECT s.port, s.fingerprint_source, s.product, s.evidence \
   FROM services s JOIN assets a ON a.id = s.asset_id WHERE a.scan_id = '<scan_id>';"
# expect the row for port 3000 to show fingerprint_source='http' and evidence containing a
# "server"/"status_code"/"title" — other, non-web open ports on the same asset stay
# fingerprint_source=NULL, exactly as scoped.

# --- new results endpoint ---
curl http://localhost:8000/api/v1/scans/<scan_id>/assets

# --- frontend ---
# open http://localhost:3000/projects/<projectId> — the scan-id cell in the Scans table is
# now a link; clicking it opens /projects/<projectId>/scans/<scanId>, showing a header card
# (status badge, target, timestamps) and a services table with port/product/version/a
# fingerprint-source badge/an expandable raw-evidence panel per row. A scan still QUEUED
# shows "No results yet" instead of an empty/error table.

docker compose exec backend pytest -v
docker compose exec backend ruff check . && black --check . && mypy app
docker compose exec frontend npm run lint && npx tsc --noEmit
```

---

## Roadmap Beyond This Plan (not detailed here)

- **Phase 4 — Vulnerability Correlation**: the `<cpe>` list already captured into `Service.evidence` this phase becomes the direct input to CPE-to-CVE lookup — this was a deliberate design choice this phase, not an accident.
- **Phase 5 — Confidence & Validation**, **Phase 6 — Misconfiguration Analysis** (TLS/header misconfig — natural extension of the HTTP prober's already-captured header set), **Phase 7 — Risk Intelligence**, **Phase 8 — Reporting**: unchanged from the original roadmap.
- Deferred within fingerprinting itself, for a later pass if ever prioritized: generic banner-grabbing for non-web native-scanner ports, dual-scheme HTTP fallback, nmap `--script`/`-A` deeper enumeration, CIDR-aware fingerprinting (blocked on CIDR scanning itself still being unsupported).
