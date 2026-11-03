# PLAN_6.md — VulnSight Phase 6: Misconfiguration Analysis

Narrative plan. Binding authority for anything `PLAN_6_TASKS.md` doesn't
fully specify. Companion: `PLAN_6_TASKS.md` (task breakdown used for
execution).

## Why this phase, and what it actually checks

Per the project's own roadmap (`PLAN_1.md` §Phase 6, reaffirmed in every
later phase's "Roadmap Beyond This Plan" section): **HTTP headers, TLS,
exposed services.** This phase turns that one-liner into three concrete
check families, deliberately scoped to stay inside two hard boundaries
this project has already drawn for itself:

1. **No generic banner-grabbing for non-web ports** (Phase 3's explicit
   scope limit, restated in `CLAUDE.md`'s Conventions). Misconfiguration
   checks never open a new connection to guess what's running on a port
   or whether it's authenticated — "exposed service" checks are a
   static lookup against data already captured by Discovery (port +
   `service_name`), nothing more.
2. **Every outbound network call this project makes is a named,
   reviewed surface** — the HTTP prober (Phase 3) and the NVD client
   (Phase 4) are the only two today. This phase adds exactly one more:
   a bounded, best-effort TLS handshake-and-cert-read, built to the same
   security posture as the HTTP prober. No fourth surface sneaks in
   alongside it.

The three check families:

- **Header checks** (`header_checks.py`) — zero new network calls.
  Reads `Service.evidence["headers"]`, already captured verbatim by
  Phase 3's `http_prober.py` for every HTTP-probed (native-scanner) web
  service. Flags missing `Strict-Transport-Security` (HTTPS only),
  missing `Content-Security-Policy`, missing `X-Frame-Options`, missing
  `X-Content-Type-Options: nosniff`, a `Server` header that leaked a
  parseable product/version (the exact thing `http_prober._parse_server_header`
  already extracts), and a `Set-Cookie` header missing `Secure` (HTTPS
  only) or `HttpOnly`.
- **Exposed-service checks** (`exposed_service_checks.py`) — zero new
  network calls, zero evidence dependency. A static, curated
  port→(label, severity) table (Redis, MongoDB, Memcached,
  Elasticsearch, the Docker Engine API, Telnet, VNC, RDP, SMB, FTP)
  checked against every open `Service` row's `port`, regardless of
  which scanner adapter found it. This is "is a commonly-dangerous-to-
  expose service's default port open", never "did I verify it's
  actually unauthenticated" — verifying that would mean connecting and
  issuing a protocol command, which is exactly the banner-grabbing this
  project has already ruled out.
- **TLS certificate checks** (`tls_inspector.py`) — the one new active
  probe. Opens a raw TLS handshake against candidate TLS ports, reads
  the peer certificate (deliberately *without* validating it — the
  entire point is to inspect certs normal validation would reject),
  and flags self-signed, expired, expiring-within-30-days, and a
  negotiated protocol older than TLS 1.2.

All three run in a new stage, `ScanStatus.ANALYZING`, which already
exists in the `ScanStatus` enum (`backend/app/models/scan.py:22`,
between `FINGERPRINTING` and `CORRELATING`) but has never been used by
any code path — it was reserved for exactly this phase since Phase 1.
Analysis failures are best-effort, same as fingerprinting and
correlation: they can never flip a scan to `FAILED`.

## Scope limits (explicit, not gaps)

- **No validation-state/confidence workflow on `Misconfiguration` this
  phase.** `Finding` shipped bare in Phase 4; Phase 5 added
  confidence/validation as its own, later, deliberate phase. The same
  discipline applies here: ship detection only. An operator triage
  workflow for misconfigurations, if wanted, is a future phase's
  decision, not this one's.
- **No new scan stage beyond `ANALYZING`.** No new `ScanStatus` value is
  added — the slot already exists.
- **No changes to `discovery/`, `fingerprinting/`, or `vulnerability/`.**
  This phase reads their output (`Service.evidence`, `.port`,
  `.service_name`) but never edits `nmap_scanner.py`, `http_prober.py`,
  `native_scanner.py`, `correlator.py`, `nvd_client.py`, `cache.py`, or
  `rate_limiter.py`. The TLS candidate-port heuristic below is an
  independent, small constant inside `misconfiguration/` — not an
  import of `http_prober.py`'s private `_TLS_HEURISTIC_PORTS`, which
  keeps the existing discovery/fingerprinting/misconfiguration module
  separation intact (`CLAUDE.md`'s "Fingerprinting... separate from
  discovery/ by design" principle, extended to this phase's own new
  module).
- **No bulk re-analysis endpoint, no scheduled re-checks.** Analysis
  runs exactly once, as part of the scan it belongs to, same as every
  other per-scan stage.
- **Known, accepted limitation carried from Phase 3, not fixed here**:
  `http_prober.py` stores HTTP response headers as a plain `dict`
  (`dict(response.headers)`), which keeps only the last value for a
  repeated header name. A target sending multiple `Set-Cookie` headers
  will only have the last one visible to the insecure-cookie check.
  This is `http_prober.py`'s existing, already-shipped behavior — not
  something this phase reaches back and changes (see the no-touch rule
  above).

## §1 `Misconfiguration` model + migration

New model, **not** a reuse/generalization of `Finding` — `Finding` is
structurally CVE-specific (`cve_id`, `matched_cpe`, the
`uq_finding_service_cve_cpe` constraint, NVD-shaped `evidence`); forcing
misconfiguration rows into it would mean a pile of always-null CVE
columns. A clean new table, same spirit as `Finding`'s own relationship
to `Service`:

`backend/app/models/misconfiguration.py` (new):

```python
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base

if TYPE_CHECKING:
    from app.models.service import Service


class Misconfiguration(Base):
    __tablename__ = "misconfigurations"
    __table_args__ = (
        UniqueConstraint("service_id", "check_id", name="uq_misconfig_service_check"),
    )
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    service_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("services.id", ondelete="CASCADE"), index=True, nullable=False
    )
    # Which rule fired, e.g. "missing-hsts", "exposed-sensitive-service",
    # "self-signed-cert" — stable identifiers, never translated/localized
    # here. The uq_misconfig_service_check constraint above is load-bearing:
    # the analyzer must never attempt the same check_id twice for one
    # service (see PLAN_6_TASKS.md Global Constraint 9).
    check_id: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    # Plain string, not a DB enum — mirrors Finding.severity's own
    # existing convention exactly (CRITICAL/HIGH/MEDIUM/LOW; "NONE" is
    # never used here since a row only exists when something was
    # actually flagged).
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    # Raw supporting evidence, verbatim — same convention as
    # Finding.evidence/Service.evidence: always populated meaningfully,
    # never a stand-in for a missing structured field.
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    service: Mapped["Service"] = relationship(back_populates="misconfigurations")
```

Edit `backend/app/models/service.py`: add

```python
    # order_by created_at (insertion order), not a severity-sort
    # expression — deliberately the simplest option; a worst-first
    # sort is a frontend/API concern to add later if actually wanted,
    # not something to build ahead of need.
    misconfigurations: Mapped[list["Misconfiguration"]] = relationship(
        back_populates="service",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="Misconfiguration.created_at",
    )
```

and the matching `TYPE_CHECKING` import.

Migration: purely additive `CREATE TABLE`, no backfill needed (unlike
Phase 5's `confidence_score` — there are no pre-existing
`Misconfiguration` rows to retrofit, since the table itself is new).
`down_revision` = current head, confirmed by directly reading every
file's `revision`/`down_revision` pair in `backend/migrations/versions/`
while writing this plan: `111ce3c92341` → `26de1feba77b` →
`d6b7d6e6b8c8` → `45f7e770cdbb` → `8f08312a037b` (head) — a single
linear chain, no branching. Re-verify this is still the head before
generating the new revision; don't trust a stale value if more
migrations landed since this was written.

## §2 Header checks + exposed-service checks (pure, zero network)

`backend/app/modules/misconfiguration/checks.py` (new) — a small shared
shape both check families return, so the analyzer (§4) can treat them
uniformly:

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class MisconfigCandidate:
    check_id: str
    title: str
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    description: str
    evidence: dict
```

`backend/app/modules/misconfiguration/header_checks.py` (new):

```python
def check_headers(service: "Service") -> list[MisconfigCandidate]:
    """Pure function: reads service.evidence["headers"] (already
    captured verbatim by http_prober.py), returns zero or more
    candidates. Never raises — a missing/malformed evidence shape
    (evidence is None, not a dict, or has no "headers" key) means
    "nothing to check", an empty list, not an error. Case-insensitive
    header lookup (HTTP header names are case-insensitive; the stored
    dict preserves whatever casing the origin server used).
    """
```

Exact checks (header lookup via a small case-insensitive helper, since
`evidence["headers"]` is a plain `dict[str, str]` with origin-server
casing preserved verbatim from Phase 3, never normalized):

| check_id | Trigger | severity |
|---|---|---|
| `missing-hsts` | `evidence.get("scheme") == "https"` and no `Strict-Transport-Security` header | MEDIUM |
| `missing-csp` | no `Content-Security-Policy` header | LOW |
| `missing-x-frame-options` | no `X-Frame-Options` header | LOW |
| `missing-x-content-type-options` | no `X-Content-Type-Options` header, or present but not `nosniff` (case-insensitive) | LOW |
| `verbose-server-header` | `http_prober` already parsed a `product`/`version` out of the `Server` header (i.e. `evidence.get("server")` is non-empty and matched `_SERVER_HEADER_RE`'s shape — re-derive this with the same regex locally, don't re-import `http_prober`'s private one; see the no-import rule in §0) | LOW |
| `insecure-cookie` | a `Set-Cookie` header is present and (missing `HttpOnly`, case-insensitive) or (`evidence.get("scheme") == "https"` and missing `Secure`, case-insensitive) | MEDIUM |

Only ever runs where `service.evidence` has a `headers` key — i.e.
HTTP-probed native-scanner services, exactly mirroring
`correlator.py`'s own "filter by evidence content, not by
`fingerprint_source`/scanner name" precedent (`CLAUDE.md`: "`correlator.py`
filters `Service` rows by 'does `evidence` have a non-empty `cpe` key'
... never by `scanner_name`"). An nmap-scanned HTTPS service has no
`headers` evidence at all (nmap's `-sV` doesn't capture response
headers) — it simply produces zero header-check candidates, not an
error.

`backend/app/modules/misconfiguration/exposed_service_checks.py` (new):

```python
# Curated, deliberately small: ports whose exposure is itself
# meaningful signal regardless of what's actually listening (we never
# connect to verify — see PLAN_6.md's scope limits). Values are
# (label, severity).
SENSITIVE_PORTS: dict[int, tuple[str, str]] = {
    21: ("FTP", "MEDIUM"),
    23: ("Telnet", "HIGH"),
    445: ("SMB", "MEDIUM"),
    2375: ("Docker Engine API", "CRITICAL"),
    3306: ("MySQL", "MEDIUM"),
    3389: ("RDP", "MEDIUM"),
    5432: ("PostgreSQL", "MEDIUM"),
    5900: ("VNC", "HIGH"),
    6379: ("Redis", "HIGH"),
    9200: ("Elasticsearch", "HIGH"),
    11211: ("Memcached", "HIGH"),
    27017: ("MongoDB", "HIGH"),
}


def check_exposed_service(service: "Service") -> MisconfigCandidate | None:
    """Pure, static lookup by service.port only. Returns None (not an
    empty list — at most one candidate per service, unlike
    check_headers) when the port isn't in SENSITIVE_PORTS. Never raises.
    """
```

check_id for every row this produces: `"exposed-sensitive-service"`
(one rule, many possible ports — the port/label/severity live in
`evidence`, not in a per-port check_id, so the
`uq_misconfig_service_check` constraint still holds one row per
service for this rule).

## §3 TLS certificate inspection (the one new active probe)

New runtime dependency: **`cryptography`**, added to
`backend/requirements.txt`. Needed because `ssl.SSLSocket.getpeercert()`
(the parsed-dict form) returns an **empty dict** whenever the
certificate wasn't validated — and `verify_mode=ssl.CERT_NONE` (required
below, deliberately, to even reach a self-signed/expired cert without
the handshake itself raising) means it's never validated. Only
`getpeercert(binary_form=True)` returns anything (raw DER bytes)
under `CERT_NONE`; parsing DER into subject/issuer/notBefore/notAfter by
hand is exactly the kind of security-relevant hand-rolled parsing this
project has avoided everywhere else (see `CLAUDE.md`'s NVD-client
lessons about trusting real shapes, not reinventing parsers).
`cryptography` is the standard, actively-maintained library for this.
Pin it the same way every other dependency in `requirements.txt` is
pinned: `~=` against the version actually verified working in this
project's Docker image, not a guessed number — check
`docker compose exec backend pip show cryptography` after installing it
and pin to that.

`backend/app/modules/misconfiguration/tls_inspector.py` (new):

```python
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography import x509

# Deliberately an independent copy, not an import of
# fingerprinting.http_prober's private _TLS_HEURISTIC_PORTS — see
# PLAN_6.md's no-touch-other-modules rule. Extended at call time (in
# analyzer.py) with any Service whose service_name suggests TLS on a
# non-standard port.
TLS_CANDIDATE_PORTS: frozenset[int] = frozenset({443, 4443, 8443})

TLS_PROBE_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_WORKERS = 10
EXPIRING_SOON_WINDOW = timedelta(days=30)
WEAK_PROTOCOLS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})


@dataclass(frozen=True)
class TlsInspectionResult:
    port: int
    protocol_version: str | None  # ssl_socket.version(), e.g. "TLSv1.3"
    subject: str | None  # RFC4514 string, e.g. "CN=example.com"
    issuer: str | None
    not_valid_before: datetime | None
    not_valid_after: datetime | None
    is_self_signed: bool  # subject == issuer (as parsed Name objects)


def _inspect_port(host: str, port: int, timeout_seconds: float) -> TlsInspectionResult | None:
    """One port, one blocking TLS handshake, verify disabled on purpose
    (see module docstring: the entire point is to inspect certs normal
    validation would reject). socket.settimeout bounds connect AND the
    handshake itself (both happen before this function does anything
    else — there is no subsequent data read to need a separate
    total-operation deadline the way http_prober.py's body-streaming
    does). Any failure (refused, reset, non-TLS port, timeout) returns
    None — never raises. This function makes the only new outbound
    network call this phase adds; it must never be called from
    anywhere except inspect_tls below.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock, \
                context.wrap_socket(sock, server_hostname=host) as tls_sock:
            der_cert = tls_sock.getpeercert(binary_form=True)
            protocol_version = tls_sock.version()
    except Exception:
        return None
    if der_cert is None:
        return TlsInspectionResult(port, protocol_version, None, None, None, None, False)
    try:
        cert = x509.load_der_x509_certificate(der_cert)
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        return TlsInspectionResult(
            port=port,
            protocol_version=protocol_version,
            subject=subject,
            issuer=issuer,
            not_valid_before=cert.not_valid_before_utc,
            not_valid_after=cert.not_valid_after_utc,
            is_self_signed=(cert.subject == cert.issuer),
        )
    except Exception:
        # Cert fetched but unparseable (corrupt/unsupported) — still a
        # real, if partial, result: protocol_version alone is still
        # useful to check_tls_result below.
        return TlsInspectionResult(port, protocol_version, None, None, None, None, False)


def inspect_tls(
    host: str,
    ports: list[int],
    timeout_seconds: float = TLS_PROBE_TIMEOUT_SECONDS,
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> dict[int, TlsInspectionResult]:
    """Sync, thread-pool-concurrent (not asyncio — plain blocking
    socket/ssl, mirroring http_prober.py's concurrency *shape* with
    threads instead of coroutines since there's no async ssl handshake
    primitive in the stdlib). Per-port failures are swallowed inside
    _inspect_port; this function itself only raises for genuine misuse.
    """
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        results = pool.map(lambda p: _inspect_port(host, p, timeout_seconds), ports)
    return {r.port: r for r in results if r is not None}


def check_tls_result(result: TlsInspectionResult) -> list["MisconfigCandidate"]:
    """Pure function over an already-fetched TlsInspectionResult — the
    network I/O (inspect_tls above) and the check logic are deliberately
    separate, same split as tls_inspector vs. checks.py for the other
    two families. Never raises.
    """
```

Exact checks (import `MisconfigCandidate` from `checks.py`):

| check_id | Trigger | severity |
|---|---|---|
| `self-signed-cert` | `result.is_self_signed` | MEDIUM |
| `expired-cert` | `result.not_valid_after` is not None and `< datetime.now(UTC)` | HIGH |
| `expiring-soon-cert` | not expired, and `not_valid_after < datetime.now(UTC) + EXPIRING_SOON_WINDOW` | LOW |
| `weak-tls-protocol` | `result.protocol_version in WEAK_PROTOCOLS` | HIGH |

`expired-cert` and `expiring-soon-cert` are mutually exclusive (check
expired first, `elif` into expiring-soon) — never both for one
service.

## §4 Analyzer orchestrator + `ANALYZING` stage wiring

`backend/app/modules/misconfiguration/analyzer.py` (new):

```python
def analyze_services(db: Session, services: list[Service], target_host: str) -> None:
    """Orchestrates all three check families for one scan's services.
    Mirrors correlator.py's isolation discipline: one commit per
    service, each service's own try/except, so one service's failure
    (e.g. a weird evidence shape) never aborts analysis of the rest.
    Never raises out of this function — callers rely on that the same
    way tasks.py relies on correlate_services never raising.
    """
    # 1. Resolve the TLS candidate port set across ALL services once:
    #    TLS_CANDIDATE_PORTS, unioned with any service whose
    #    service_name matches /ssl|https|tls/i (case-insensitive,
    #    None-safe). One inspect_tls() call for the whole scan, not one
    #    per service — avoids redundant repeated handshakes against the
    #    same host.
    # 2. For each service: run check_exposed_service unconditionally;
    #    run check_headers if evidence has a "headers" key; run
    #    check_tls_result if this service's port is in the resolved TLS
    #    candidate set AND inspect_tls actually returned a result for
    #    it (a refused/non-TLS port on a port we only guessed might be
    #    TLS simply contributes no TLS candidates — not an error).
    # 3. Build Misconfiguration rows from the collected candidates,
    #    db.add_all + commit once per service, inside that service's own
    #    try/except (log + rollback + continue on failure, matching
    #    correlator.py's per-unit except block).
```

Edit `backend/app/workers/tasks.py`: insert a new stage between Step 9
(HTTP fingerprinting, existing) and Step 10 (CORRELATING, existing) —
re-verify the real current step numbers/line numbers directly in the
file before editing; do not trust stale numbers from this plan if the
file has moved since this was written:

```python
# Step N (Phase 6): ANALYZING. Same best-effort shape as Steps 9/10:
# analysis failures must never fail the scan, so any exception here is
# logged and swallowed — no scan.status mutation, no return, always
# falls through to CORRELATING below. Runs for BOTH adapters
# unconditionally (TLS/header/exposed-service checks are all orthogonal
# to which scanner found the port), same precedent as CORRELATING's own
# unconditional call.
scan.status = ScanStatus.ANALYZING
db.commit()
try:
    analyze_services(db, services, target.value)
except Exception:
    db.rollback()
    logger.exception("run_scan_task: scan %s misconfiguration analysis failed", scan_id)
```

This sits strictly between the existing Step 9 block and the existing
`scan.status = ScanStatus.CORRELATING` line — no reordering of anything
else in the function.

## §5 API additions

Edit `backend/app/schemas/service.py`: add a new `MisconfigurationRead`
schema (new file `backend/app/schemas/misconfiguration.py`, mirroring
`FindingRead`'s shape exactly — `id`, `service_id`, `check_id`, `title`,
`severity: str`, `description`, `evidence: dict`, `created_at`, all via
`ConfigDict(from_attributes=True)`), then add
`misconfigurations: list[MisconfigurationRead] = []` to `ServiceRead`,
same pattern as the existing `findings: list[FindingRead] = []`. No new
route — this rides the existing `GET /scans/{id}/assets` endpoint, same
as `findings` did in Phase 4. No PATCH route this phase (see Scope
limits — no validation workflow yet).

## §6 Frontend additions

`frontend/src/lib/types/misconfiguration.ts` (new): `MisconfigurationRead`
interface mirroring the Pydantic schema; reuse the **existing**
`Severity` type from `finding.ts` (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`NONE`)
rather than inventing a parallel one — `SeverityBadge.tsx` already
renders any `Severity` value and needs zero changes to work for
misconfigurations too.

Edit `frontend/src/lib/types/service.ts` (confirmed location of
`interface ServiceRead`): add `misconfigurations: MisconfigurationRead[]`,
alongside the existing `findings: FindingRead[]` field.

Edit `frontend/src/app/projects/[projectId]/scans/[scanId]/page.tsx`:
add a per-service misconfigurations block, sibling to the existing
findings block, rendering each `Misconfiguration` as its `title`,
`SeverityBadge`, and `description` — no CVE link (nothing to link to),
no confidence text, no validation control (none exists this phase). Do
not touch the existing findings block.

## §7 Testing strategy

- `header_checks.py`: one test per check_id (triggered and
  not-triggered), plus a "no headers key at all → empty list, no raise"
  defensive test, plus a "scheme missing (not https, not http) → HSTS
  check correctly skipped" edge case.
- `exposed_service_checks.py`: one test per `SENSITIVE_PORTS` entry
  (or at minimum a representative sample across severities), plus a
  "port not in the table → None" test.
- `tls_inspector.py`: `_inspect_port`/`inspect_tls` need a real TLS
  listener to test against meaningfully — use Python's `ssl` module to
  generate a throwaway self-signed cert + a local `socket`/`ssl`-wrapped
  TCP server fixture (or an existing test-fixture pattern if one
  already exists in this repo for TLS; check before inventing one) so
  `test_tls_inspector.py` exercises a real handshake, not a mock of
  `ssl`/`socket` — this project's own `CLAUDE.md` lesson ("trust the
  live shape over a mock") applies here too: a mocked `getpeercert()`
  would never catch e.g. a wrong assumption about what `CERT_NONE`
  actually returns. `check_tls_result` itself (pure, given a
  `TlsInspectionResult`) can be tested with plain constructed fixtures,
  no real cert needed — self-signed/expired/weak-protocol/clean cases.
- `analyzer.py`: a correlator.py-style test with 2+ services where one
  service's check raises (simulate via a malformed evidence shape) and
  confirm the other service's misconfigurations still get persisted —
  the per-service isolation claim, proven, not just asserted.
- `test_scans.py` (extend): the existing `GET /scans/{id}/assets` test
  gains an assertion that `misconfigurations` appears (possibly empty)
  on `ServiceRead`.

## §8 Verification plan

Fresh migration against a database with pre-existing `Service` rows
(no backfill needed, but still confirm the table creates cleanly
alongside them). A real scan against a target exposing at least one
checkable condition in each family (e.g. a local test HTTP server
missing security headers, a port in `SENSITIVE_PORTS` open, a
self-signed-cert TLS listener) — confirm `Misconfiguration` rows appear
with the exact expected `check_id`/`severity` for each, confirm the scan
reaches `COMPLETED` (not `FAILED`) even when a deliberately-broken TLS
target is included (proving the best-effort swallow actually works),
confirm `GET /scans/{id}/assets` nests `misconfigurations` correctly,
confirm the frontend page renders them. Full backend+frontend
lint/type/test suites green.
