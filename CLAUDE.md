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
- **Phase 3** (Service Fingerprinting) — done, merged to `main`. nmap
  scans now run with `-sV` and capture `<service>`/`<cpe>` XML evidence;
  native-scanner scans get a separate best-effort HTTP header/title probe
  (`backend/app/modules/fingerprinting/http_prober.py`) against a curated
  allowlist of web-looking ports. `Service` gained `product`/`version`/
  `extrainfo`/`fingerprint_source`/`evidence` (JSONB) columns. A new
  `GET /scans/{id}/assets` endpoint and the project's first frontend
  results view (`/projects/[projectId]/scans/[scanId]`) expose it. See
  `PLAN_3.md` / `PLAN_3_TASKS.md`.
- **Phase 4** (Vulnerability Correlation) — done, merged to `main`. For
  every nmap-sourced `Service` with CPE evidence, correlates against the
  NVD CVE API 2.0 (cached locally in `cve_cache`, keyed by CPE string,
  7-day TTL) and persists matches as `Finding` rows. A new
  `ScanStatus.CORRELATING` stage, a Redis Lua-script rate limiter (see
  below), and `findings` nested onto the existing results endpoint/page
  with severity badges + NVD links. Native-scanner/HTTP-prober services
  never get findings — no CPE evidence exists for them, by design. See
  `PLAN_4.md` / `PLAN_4_TASKS.md`.
- **Phase 5** (Confidence & Validation) — done, merged to `main`. Two
  independent mechanisms added to `Finding` rows (they share a table,
  nothing else): a continuous 0-100 `confidence_score` computed once per
  `Service` (not once per `Finding`/CVE) from nmap's own `method`/`conf`
  evidence by a pure function, `compute_confidence`
  (`backend/app/modules/vulnerability/confidence.py`), wired into
  `correlator.py`'s existing per-CPE loop; and an operator-settable
  `validation_state` (`UNVALIDATED`/`CONFIRMED`/`FALSE_POSITIVE`) with an
  optional free-text `validation_note` and a `validated_at` timestamp,
  via a standalone `PATCH /findings/{id}`
  (`backend/app/services/finding_service.py`,
  `backend/app/api/routes/findings.py`) that never touches scan state.
  Transitions are unrestricted (including back to `UNVALIDATED`, which
  clears both `validation_note` and `validated_at`); a note is
  full-replace on every PATCH, never merged with a prior one. The
  migration backfills `confidence_score` for pre-existing rows with its
  own inlined copy of the formula (migrations never import application
  code — see Conventions). Frontend: confidence text, `ValidationBadge`,
  and `FindingValidationControl` on the existing scan-results page;
  false-positive findings get `opacity-50` + a struck-through CVE link,
  never hidden entirely. See `PLAN_5.md` / `PLAN_5_TASKS.md`.
- **Phase 6** (Misconfiguration Analysis) — done, merged to `main`.
  Three independent check families, all producing rows on a new,
  standalone `Misconfiguration` model (`backend/app/models/
  misconfiguration.py` — deliberately not a `Finding` reuse, since
  `Finding` is structurally CVE-specific): **header checks**
  (`header_checks.py`, zero new network calls — reads
  `Service.evidence["headers"]` already captured by Phase 3's HTTP
  prober; missing HSTS/CSP/X-Frame-Options/X-Content-Type-Options, a
  verbose `Server` header, insecure cookie flags); **exposed-service
  checks** (`exposed_service_checks.py`, zero new network calls — a
  static port→(label, severity) table lookup against commonly-
  dangerous-to-expose services, e.g. Redis/MongoDB/the Docker Engine
  API; never connects to verify anything, preserving the existing
  no-banner-grabbing boundary from Phase 3); **TLS certificate
  inspection** (`tls_inspector.py`, the one new active-probe surface
  this phase introduces — the **third** outbound-network-call surface
  in the project, alongside the HTTP prober and the NVD client). All
  three are orchestrated by `analyzer.py` (mirrors `correlator.py`'s
  per-unit commit/isolation discipline) inside `ScanStatus.ANALYZING`,
  an enum value reserved-but-unused since Phase 1, now finally wired up
  in `tasks.py` between `FINGERPRINTING` and `CORRELATING`. Analysis is
  best-effort — same never-flip-to-`FAILED` contract as fingerprinting/
  correlation. Surfaced read-only via the existing
  `GET /scans/{id}/assets` (`misconfigurations` nested on `ServiceRead`,
  eager-loaded alongside `findings`) and a sibling block on the scan-
  results page. **Detection-only this phase, deliberately** — no
  validation-state/confidence workflow, mirroring how `Finding` itself
  shipped bare in Phase 4 before Phase 5 added that layer separately.
  New runtime dependency: **`cryptography`** (DER-only certificate
  parsing — Python's stdlib `ssl.getpeercert()` returns an empty dict
  whenever the cert wasn't validated, which is always, by design, in
  this module). `tls_inspector.py`'s `_inspect_port` deliberately sets
  BOTH `verify_mode=ssl.CERT_NONE`/`check_hostname=False` (the whole
  point is reading certs normal validation would reject — mirrors
  `http_prober.py`'s `verify=False` posture) AND a lowered
  `context.minimum_version`/permissive cipher policy — the latter fixed
  late in this phase's final review: `PROTOCOL_TLS_CLIENT`'s *default*
  minimum version (TLS 1.2) makes the handshake itself fail against a
  legacy-TLS host, which silently produced zero TLS findings for
  exactly the hosts most likely to have genuinely bad certs, and made
  the `weak-tls-protocol` check undetectable in production — caught
  only by testing against a real TLS listener, not by any mocked unit
  test (the same "mocks hide the live shape" lesson as the NVD-client
  bugs below). See `PLAN_6.md` / `PLAN_6_TASKS.md`.
- **Phase 7+** (risk scoring, reporting) — not started. Placeholder
  empty packages already exist under `backend/app/modules/` for each.
  Known, deliberately deferred gaps for whichever phase picks them up:
  CVSS v4 (`cvssMetricV40`) isn't read, so a V4-only-scored CVE shows
  severity `NONE`; a scan with zero findings looks identical whether
  that's a genuinely clean result or a correlation failure (NVD outage,
  rate-limit timeout) — no per-scan outcome tracking yet;
  `confidence_score`'s band constants (`PROBED_FLOOR`/`TABLE_CEILING`/
  etc.) are a first-pass judgment call, not tuned against real-world
  nmap scan data — Phase 5's final review flagged that most real `-sV`
  probed matches cluster near 100.0, so revisit the bands before
  leaning on this score for prioritization; Phase 6's exposed-service
  checks and `SENSITIVE_PORTS` table are a first-pass curated list, not
  exhaustive — expand it with real-world findings before leaning on it
  for coverage claims; a TLS candidate port whose handshake fails for
  any reason (unreachable, non-TLS listener) produces zero TLS findings,
  indistinguishable from a port with no TLS-relevant issues at all — the
  same "clean vs. failed, looks identical" ambiguity Phase 4 already
  has for CVE correlation.
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
- **Fingerprinting** (`backend/app/modules/fingerprinting/`): separate
  from `discovery/` by design — discovery answers "is this port open",
  fingerprinting answers "what's running on it". `run_scan_task` passes
  through a real `ScanStatus.FINGERPRINTING` state for both adapters;
  fingerprinting failures are always best-effort and can never flip a
  scan to `FAILED` (only the discovery stage can do that — see the
  explicit `return` at the end of its `except` block in `tasks.py`,
  which is load-bearing: without it a `FAILED` scan falls through and
  gets silently overwritten). `http_prober.py` makes real outbound
  requests to arbitrary scan targets, so its guardrails are security
  controls, not style: `follow_redirects=False`, a genuine
  total-operation deadline (`asyncio.wait_for`, not just httpx's
  per-operation timeouts — those don't bound a slow-drip target), a
  hard response-body cap enforced via `aiter_raw()` (not `aiter_bytes()`,
  which would let a compressed response decompress past the cap before
  it's ever checked), and `verify=False` (deliberate — this project's
  targets are typically self-signed/internal-CA, and the prober sends
  no credentials and follows no redirects, so it's evidence-gathering
  only). Remote-controlled strings (`Server` header, nmap XML attributes)
  are clamped before writing to bounded `varchar` columns; `evidence`
  (JSONB) and `extrainfo` (Text) stay verbatim always.
- **Frontend**: Next.js App Router (`frontend/src/app`), typed API client
  in `frontend/src/lib/api/`. `next dev`/`next build` both need
  `--webpack` in `frontend/package.json` — Turbopack has a route-discovery
  bug with nested dynamic routes under this project's Docker/Windows
  bind-mount setup (see README's Windows-specific notes).
- **Vulnerability correlation** (`backend/app/modules/vulnerability/`):
  `correlator.py` filters `Service` rows by "does `evidence` have a
  non-empty `cpe` key" (never by `scanner_name`), converts each CPE
  2.2→2.3 (`cpe_utils.py`), dedups identical CPEs within one scan, caps
  at 25 distinct CPEs/scan, and commits once per distinct CPE — not
  batched at the end — with its own per-CPE `try/except` so one CPE's
  failure never aborts the rest of the scan's correlation. Correlation
  failures (like fingerprinting's) can never flip a scan to `FAILED`.
  `nvd_client.py` talks to the live NVD CVE API 2.0 — this is the
  **second** outbound-network-call surface this project makes (alongside
  the HTTP prober), and the worker container needs real internet access
  for it to do anything. **Redis is now a direct dependency, not just the
  Celery broker**: `rate_limiter.py`'s `NvdRateLimiter` uses a single
  global Redis key (`vulnsight:nvd:ratelimit`) and a Lua script to make
  the whole check-trim-claim sequence atomic across the worker's ~12
  concurrent prefork processes — NVD's 5-req/30s keyless limit is global,
  not per-process, so a per-task `time.sleep()` would not coordinate it;
  never add a second ad hoc throttle alongside this one. `cache.py`'s
  `store()` is structurally unable to cache a failed lookup (its own type
  signature excludes `None` — `fetch_cves_for_cpe` returns `[]` for a
  genuine zero-CVE success vs. `None` for literally any failure), and is
  itself an atomic upsert (`ON CONFLICT DO UPDATE`) since concurrent scans
  can race on the same new CPE. **Trust the live API's actual shape over
  how it looks in a mock**: two real bugs shipped from exactly that gap —
  NVD rejecting `isVulnerable=true` (needs `isVulnerable=""`), and CVSS
  v2's `baseSeverity` living beside `cvssData` on the metric object, not
  nested inside it (unlike v3) — both were invisible to every mocked unit
  test and only surfaced via a real live NVD call. Backend tests need a
  reachable Redis (`TEST_REDIS_URL`, defaults to `REDIS_URL` on DB index
  15) in addition to the Postgres test database.
- **Confidence & validation** (Phase 5): `confidence.py`'s
  `compute_confidence` is a pure function — no DB/Redis/network, every
  branch (missing `method`, missing/malformed/out-of-range `conf`)
  returns a concrete float, never `None`, never raises. `correlator.py`
  builds one `confidence_by_service` dict per distinct CPE (one call per
  service, reused across that service's multiple `Finding`/CVE rows) —
  never regress into calling it inside the full `(service, cve)`
  comprehension. `finding_service.update_validation` never touches
  `confidence_score`; `correlator.py` never touches
  `validation_state`/`validation_note`/`validated_at` — keep these two
  mechanisms independent even though they live on the same row. No
  bulk/batch validation endpoint, no audit log beyond `validated_at`, no
  automatic false-positive heuristics — deliberately out of scope.
- **Misconfiguration analysis** (Phase 6): `analyzer.py` resolves the
  TLS-candidate port set (`tls_inspector.TLS_CANDIDATE_PORTS` ∪ any
  service whose `service_name` suggests TLS) **intersected with the
  ports this scan's services actually have open** before calling
  `inspect_tls` exactly once per scan (never once per service) — don't
  regress into probing the full candidate set unconditionally, that was
  a real wasted-traffic bug fixed in this phase's final review.
  `check_headers`/`check_exposed_service`/`check_tls_result` are all
  pure functions — never raise, never touch DB/Redis/network;
  `analyzer.py` itself commits once per service inside that service's
  own `try/except` (mirrors `correlator.py`'s per-CPE isolation) plus
  an outer safety net, and never touches `scan.status` (it takes
  `services`, not `scan`). The `uq_misconfig_service_check` unique
  constraint on `(service_id, check_id)` is load-bearing; `analyzer.py`
  has its own defensive dedup on top of it. `exposed_service_checks.py`
  is a pure port→label table lookup — it never connects to verify
  anything, preserving the no-banner-grabbing boundary. `tls_inspector.py`
  is the only module in this phase allowed to open a network
  connection — don't add a second ad hoc probe elsewhere. Its
  `verify_mode=ssl.CERT_NONE`/`check_hostname=False` AND its lowered
  `minimum_version`/permissive cipher policy are both deliberate, not
  vulnerabilities to "fix": this project's TLS inspector sends no
  credentials and treats every handshake as passive evidence only,
  exactly like `http_prober.py`'s `verify=False` — refusing a legacy or
  self-signed handshake would just hide the misconfiguration this
  module exists to detect. `header_checks.py`'s `insecure-cookie` check
  parses `Set-Cookie` by splitting on `;` and comparing exact trimmed
  attribute names, never raw substring search (a cookie literally named
  `secure_session=...` must not look like it has the `Secure` flag set).

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
- Service identification beyond nmap's `-sV` evidence and the HTTP
  prober's header/title parsing is out of scope — no generic
  banner-grabbing for non-web ports on the native scanner (deferred,
  not a gap; see PLAN_3.md's explicit scope limits).
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
