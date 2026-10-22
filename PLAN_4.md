# PLAN_4.md — VulnSight Phase 4 Implementation Plan: Vulnerability Correlation

## Context

Phase 3 answered "what's running on it" — nmap `-sV` scans now capture `<cpe>` evidence (CPE 2.2 URI-binding strings, e.g. `cpe:/a:nginx:nginx:1.24.0`, confirmed by reading `backend/app/modules/discovery/nmap_scanner.py:138,154`: `cpe = tuple(cpe_el.text for cpe_el in service_el.findall("cpe") if cpe_el.text)` then `evidence["cpe"] = list(cpe)` — nmap emits **CPE 2.2 form**, never 2.3, so a format-conversion step is mandatory before this evidence can be sent to NVD, see §2) into `Service.evidence["cpe"]`. Phase 4 answers "is any of this actually vulnerable": for every `Service` row carrying nmap-sourced CPE evidence, look up matching CVEs against the NVD CVE API 2.0, cache the result locally (keyed by CPE string, reusable across services/scans), and persist the matches as `Finding` rows — exactly the "deliberate design choice, not an accident" called out in `PLAN_3.md`'s own roadmap note.

Two binding decisions already made (not re-litigated here): the NVD CVE API 2.0 is the CVE source, cached in Postgres rather than called live every scan; no NVD API key is used (design for the public, keyless 5-requests/30-seconds limit, but leave a one-line-later hook for a key).

The single hardest constraint this phase introduces, absent from every prior phase: **the rate limit is global and cross-process**, not per-task. The worker runs Celery prefork with multiple concurrent worker processes (observed 12 in a prior phase's startup banner — an implicit, CPU-count-derived default, not a `docker-compose.yml` flag, so it can vary by host; the rate limiter must not assume a fixed count). A `time.sleep(6)` inside one task coordinates nothing across 12 OS processes each independently deciding "it's been 6 seconds since *my* last call." Redis — already a hard dependency as the Celery broker/result-backend, already available via the already-pinned `redis~=8.1` package used today only indirectly through Celery — is used directly this phase for the first time, as a cross-process sliding-window rate limiter (§3). No new runtime dependency is needed for either this or the NVD client itself: `httpx~=0.28` (promoted to a runtime dependency in Phase 3) is reused as-is.

### Explicit scope limits for this phase (documented, not accidental)

- **No version-range math of our own.** NVD's `cpeName=<full versioned CPE 2.3 string>` + `isVulnerable=true` does all version-range matching server-side (`versionStartIncluding`/`versionEndExcluding` etc.) — this phase never parses or compares version strings itself.
- **No CPE *construction* from HTTP-prober product/version strings.** The HTTP prober's `HttpProbeResult` has no `vendor` field and no `cpe` field at all (confirmed: `backend/app/modules/fingerprinting/http_prober.py`'s dataclass has no `cpe` attribute) — building a CPE from a bare `product`/`version` pair would require guessing a vendor string, which is out of scope, deferred indefinitely (not just "to a later phase" — there's no roadmap phase that owns this either, since confidence scoring in Phase 5 would need to apply to a *guessed* CPE and that's a bigger can of worms than this phase should open). Consequence: **native-adapter scans produce zero `Finding` rows, always**, this phase. Only `fingerprint_source == "nmap-sv"` rows ever carry CPE evidence.
- **CPE 2.2→2.3 *format conversion* of nmap's own, already-complete CPE string is explicitly in scope**, and is a different, much narrower thing than the construction bullet above: nmap already identified vendor+product+version; converting its emitted `cpe:/a:vendor:product:version` string into the `cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*` shape NVD's API requires is a mechanical reformatting of data nmap already fully supplied, not a new matching heuristic. Called out explicitly so this isn't confused with the construction bullet it sits next to.
- **No full CPE 2.3 spec compliance in the converter.** The hand-rolled converter (`cpe_utils.py`, §2) is sized to nmap's actual observed output shape (clean, rarely-percent-encoded `cpe:/a:vendor:product:version[:update[:edition]]` strings) — not a general-purpose CPE grammar/escaping library. A CPE that doesn't cleanly convert (unexpected character count, post-unquote characters outside the safe set) is skipped defensively (logged, not sent to NVD) rather than risking a malformed `cpeName` query. No third-party CPE-parsing library is adopted this phase.
- **No multi-page NVD pagination.** One request per CPE, `resultsPerPage=200`. A fully-versioned CPE string realistically returns a handful of CVEs at most; if `totalResults > resultsPerPage` (rare), the first page is used and the truncation is logged — never a second request for the same CPE in the same lookup.
- **No proactive/background cache refresh.** Staleness (§4) is checked lazily, only when a scan's correlation pass actually needs that CPE again. No Celery Beat job pre-warms or refreshes the cache.
- **No false-positive/confidence scoring** (that's Phase 5 — Confidence & Validation) and **no risk scoring** (Phase 7) — a `Finding` is recorded as "NVD says this CPE matches this CVE," full stop, no judgment about how trustworthy that match is beyond what NVD itself asserts via `isVulnerable=true`.
- **No cross-scan Finding dedup/supersession.** Unchanged from Phase 2's "no asset/service dedup" scope limit: re-scanning the same host creates a fresh `Asset`/`Service` tree and, now, a fresh set of `Finding` rows tied to *that* scan's `Service` rows. The `cve_cache` table is the only thing shared across scans — by design, since it's keyed by CPE string, not by scan.
- **No NVD API key usage.** `NVD_API_KEY: str | None = None` is added to `Settings` and read by the client (header, not query param) but is `None` in every environment this phase — wired, not used, so getting a key later is a one-line config change, not a code change.
- **`ScanStatus.ANALYZING`, `RISK_ANALYSIS`, `REPORT_GENERATION` are untouched.** Only `CORRELATING` is used this phase (reasoning in §5) — `ANALYZING` stays reserved for whatever later phase actually needs a distinct pre-processing sub-stage; this phase's in-memory CPE selection/dedup is milliseconds of work, not worth its own status transition/commit.
- **No new project-wide findings dashboard.** Findings render only on the existing per-scan results page (§7); a cross-scan/cross-project findings view is a plausible future addition, not built here.

---

## 1. Data Model Additions

Two new tables, both additive, no changes to existing tables beyond `Service` gaining a relationship (no new column — `Service` already has everything correlation needs to read, via `evidence["cpe"]`).

### `backend/app/models/cve_cache.py` (new)

The cache is keyed **by CPE string**, not by `Finding` or by scan — deliberately, so that 20 `Service` rows across 5 different scans that all happen to be `nginx 1.24.0` share exactly one cache entry and cost at most one NVD call total, ever (until it goes stale).

```python
class CveCache(Base):
    __tablename__ = "cve_cache"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    # The CPE 2.3-formatted string actually sent to NVD as `cpeName` (post
    # cpe_utils conversion) — the canonical cache key. Unique+indexed: this
    # table's whole purpose is O(1) lookup by this column.
    cpe: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    # When this entry was last successfully fetched from NVD. A failed
    # lookup NEVER reaches this table at all (see §4) — every row here
    # represents a real, successful NVD response, even one with zero CVEs.
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # NVD's own `totalResults` for this cpeName+isVulnerable=true query, for
    # audit (lets an operator later notice "NVD said there were 40 but we
    # only cached the first 200" truncation cases per the no-pagination
    # scope limit).
    total_results: Mapped[int] = mapped_column(Integer, nullable=False)
    # Normalized CVE list (see nvd_client.NormalizedCve), JSONB, one entry
    # per CVE: {cve_id, description, severity, cvss_score, cvss_vector,
    # references, raw}. An empty list `[]` is a real, meaningful, cacheable
    # "NVD confirms zero known CVEs for this CPE" result — distinct from
    # this row not existing at all (= never successfully looked up).
    cves: Mapped[list] = mapped_column(JSONB, nullable=False)
```

### `backend/app/models/finding.py` (new)

```python
class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("service_id", "cve_id", "matched_cpe", name="uq_finding_service_cve_cpe"),
    )
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    service_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("services.id", ondelete="CASCADE"), index=True, nullable=False
    )
    cve_id: Mapped[str] = mapped_column(String(20), nullable=False)  # "CVE-2021-41773"
    # The exact CPE 2.3 string that produced this match — joins cleanly back
    # to cve_cache.cpe for audit ("why do we think this service has this
    # CVE" -> look up this exact cpe in cve_cache). A Service can carry
    # multiple CPEs in evidence["cpe"] (nmap sometimes reports more than
    # one, e.g. an OS cpe alongside an app cpe); each contributes its own
    # Finding rows, never silently merged.
    matched_cpe: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    # "NONE" is a real, non-null value here (not Optional) — CVSS itself
    # defines a None/Low/Medium/High/Critical severity banding, so a CVE
    # with no CVSS metrics at all (rare but real, e.g. very old or
    # reserved-but-unscored CVEs) legitimately IS severity "NONE", not an
    # absence of data requiring a nullable column + separate UI branch
    # (contrast with FingerprintBadge's null="never fingerprinted" case,
    # which has no CVSS equivalent here).
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="NONE")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(100), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Raw NVD `cve` object subtree for this CVE, verbatim — mirrors the
    # Service.evidence convention exactly: structured columns above are a
    # convenience projection, this JSONB is the source of truth, never
    # lossy even when the parse above is a reasonable-but-lossy summary.
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    service: Mapped["Service"] = relationship(back_populates="findings")
```

### `backend/app/models/service.py` (edit — one relationship, no new column)

```python
findings: Mapped[list["Finding"]] = relationship(
    back_populates="service",
    cascade="all, delete-orphan",
    passive_deletes=True,
    order_by="Finding.cvss_score.desc()",
)
```
(`order_by` descending by score: worst-first display, same spirit as `Asset.services`' `order_by="Service.port"` keeping a stable, meaningful row order rather than heap order.)

No normalized global `Vulnerability`/`Cve` table is introduced — a CVE's display fields (`description`, `severity`, `cvss_score`, etc.) are denormalized directly onto each `Finding` row at correlation time, copied from whatever `cve_cache` held at that moment. This mirrors the project's existing "evidence is embedded, not joined out" style (`Service.evidence` isn't normalized into a separate table either) and keeps this phase's query surface simple — if duplicate CVE metadata across many `Finding` rows ever becomes a real storage/consistency concern, extracting a `Vulnerability` table is a clean, additive future refactor, not blocked by anything built here.

### Why `Finding` isn't named `Vulnerability`

`Finding` was chosen over `Vulnerability` deliberately: "vulnerability" more naturally names the CVE-level fact itself (a thing true independent of any particular scan — which is closer to what `cve_cache` rows represent), while "finding" names the scan-time event of *discovering* that fact attached to a specific `Service` — matching this project's own roadmap vocabulary ("Phase 5 — Confidence & Validation" operates on findings, scoring how much to trust each one; "finding" is the term used industry-wide for exactly this scan-result-provenance concept). Keeping "Vulnerability" unused this phase leaves it available, undamaged, for a future normalized CVE-metadata table if one is ever built.

### Migration (additive, generated — not a regeneration)

`alembic revision --autogenerate -m "add cve_cache and findings tables"`. Expected generated body: two `op.create_table(...)` calls (`cve_cache`, `findings`), the `findings` one including its FK to `services.id` (`ondelete="CASCADE"`), its unique constraint, and an index on `service_id` and `matched_cpe`; the `cve_cache` one including the unique index on `cpe`. No changes to any existing table. Review the generated file before applying — autogenerate sometimes needs the unique-constraint/index names adjusted to match this project's existing naming (compare against `26de1feba77b_add_assets_services_tables_scan_celery_.py`'s FK/index style) — same discipline Phase 2/3 both called out explicitly for their own migrations.

`backend/app/db/base.py` (edit): add `from app.models.cve_cache import CveCache  # noqa: F401,E402` and `from app.models.finding import Finding  # noqa: F401,E402`, alongside the existing five model imports — required so `relationship()` string references (`Mapped["Finding"]` on `Service`) resolve, exactly the reasoning already documented in that file's header comment.

### `backend/app/core/config.py` (edit — one line)

```python
NVD_API_KEY: str | None = None
```
Unused this phase (per the binding "no API key" decision); the NVD client (§2) checks it and adds an `apiKey` header only if set, so supplying a key later needs zero code changes.

---

## 2. The CPE Conversion Helper + NVD Client

### `backend/app/modules/vulnerability/cpe_utils.py` (new)

```python
def to_cpe23(cpe22: str) -> str | None:
    """Convert an nmap-emitted CPE 2.2 URI-binding string
    (`cpe:/a:nginx:nginx:1.24.0`) into the CPE 2.3 formatted string NVD's
    `cpeName` query parameter requires
    (`cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*`).

    Deliberately narrow (see PLAN_4.md scope limits): splits on `:`, strips
    any URI percent-encoding nmap's output might carry, maps the up-to-7
    CPE 2.2 fields (part, vendor, product, version, update, edition,
    language) onto CPE 2.3's first 7 of 11 fields, pads every missing
    trailing field (including all of sw_edition/target_sw/target_hw/other,
    which 2.2 has no equivalent for) with `*`. Returns `None` — never
    raises — if the input doesn't look like a clean `cpe:/...` string
    (wrong prefix, more than 7 fields, or a post-unquote character outside
    the conservative safe set) rather than risk sending NVD a malformed
    cpeName. Callers must treat `None` as "skip this CPE", not an error.
    """
```

### `backend/app/modules/vulnerability/nvd_client.py` (new)

```python
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_REQUEST_TIMEOUT_SECONDS = 10.0
NVD_RESULTS_PER_PAGE = 200  # no pagination beyond this, see scope limits

@dataclass(frozen=True)
class NormalizedCve:
    cve_id: str
    description: str | None
    severity: str          # "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"NONE" — never None
    cvss_score: float | None
    cvss_vector: str | None
    references: list[str]
    raw: dict               # the original NVD `cve` object subtree, verbatim

def fetch_cves_for_cpe(
    cpe23: str,
    redis_client: "redis.Redis",
    rate_limiter: NvdRateLimiter | None = None,
) -> list[NormalizedCve] | None:
    """Fetch and normalize CVEs for one CPE 2.3 string.

    Returns `[]` for a real, successful "NVD confirms zero known
    vulnerabilities" result (cacheable). Returns `None` for ANY failure —
    rate-limiter timeout, network error, non-2xx response (403/429/5xx),
    malformed/unexpected JSON shape — so a caller (cache.py) can tell "no
    vulnerabilities" apart from "we don't actually know" and never cache
    the latter as a clean bill of health. Never raises past this function.
    """
```

Call shape: `GET {NVD_BASE_URL}?cpeName={cpe23}&isVulnerable=true&resultsPerPage=200`, header `apiKey: <value>` added only if `get_settings().NVD_API_KEY` is set, timeout `NVD_REQUEST_TIMEOUT_SECONDS`. Before issuing the request, calls `rate_limiter.acquire()` (constructed by the caller — see §3 — or built internally from `redis_client` with the module's default `max_requests=5, window_seconds=30` if none is passed, so every call site is rate-limited by default with no way to forget). The rate-limiter call lives *inside* this function, not left to callers, specifically so there is exactly one place in the codebase that can ever make an outbound NVD request, and it is structurally impossible to add a second call site that bypasses the limiter.

Parsing: `response.json()["vulnerabilities"]` (an explicit note in the docstring: NVD nests results under `vulnerabilities`, not a flat list). For each `{"cve": {...}}` entry: `cve_id = cve["id"]`; `description` = first `descriptions[]` entry with `lang == "en"`; severity/score/vector from `metrics.cvssMetricV31[0].cvssData` if present, else `cvssMetricV30[0].cvssData`, else `cvssMetricV2[0].cvssData` (NVD computes `baseSeverity` for V2 metrics too), else severity defaults to `"NONE"` with score/vector `None`; `references` = `[r["url"] for r in cve.get("references", [])]`; `raw = cve` (the whole subtree, verbatim, per the `Service.evidence`-mirroring convention).

Error handling (all converted to a logged warning + `return None`, mirroring `http_prober.py`'s per-item failure-isolation philosophy — a lookup failure for one CPE must never raise past this function into the orchestration layer):
- `RateLimiterTimeoutError` (rate limiter gave up waiting) → log, `None`.
- `httpx.TimeoutException`, `httpx.ConnectError`, any `httpx.RequestError` → log, `None`.
- Non-2xx status (explicitly check for 403/429 and log them distinctly from other 4xx/5xx, since those two specifically mean "the rate limit or key check failed server-side" and are worth being able to grep for) → log, `None`.
- `response.json()` raising, or the expected `vulnerabilities`/`cve`/`id` keys missing/wrong-typed → caught as a broad `(KeyError, TypeError, ValueError)` → log, `None`.

---

## 3. The Redis-Based Rate Limiter

### `backend/app/modules/vulnerability/rate_limiter.py` (new)

Lives in its **own module**, imported by `nvd_client.py` — kept separate (rather than inlined into the client) specifically so it has its own focused, deterministic tests against a real ephemeral Redis (§8) independent of any HTTP/NVD concern, and so a future caller (if one is ever added) can reuse the exact same global limiter without going through the NVD client.

Design: a Redis **sorted set** (ZSET), one single **global** key (not per-process, not per-CPE — the limit is NVD's aggregate rate across the whole worker pool, regardless of which CPE or which of the 12 prefork processes is asking): `vulnsight:nvd:ratelimit`. Member = a fresh UUID per request (unique, avoids score collisions when two requests land in the same millisecond); score = request timestamp (`time.time()`, float epoch seconds).

The check-trim-conditionally-add sequence **must be atomic** across concurrent processes — a plain `ZCARD` then `ZADD` from two different prefork processes could both observe `count < 5` and both add, exceeding the limit (a classic check-then-act race, exactly the hazard called out for this phase). This is implemented as a single Lua script run via `redis.Redis.eval`/`register_script`, so Redis itself serializes the whole "trim expired, count, conditionally add" sequence as one atomic operation regardless of how many processes call it simultaneously:

```lua
-- KEYS[1] = ratelimit key, ARGV[1] = now, ARGV[2] = window_seconds,
-- ARGV[3] = max_requests, ARGV[4] = member (uuid)
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, ARGV[1] - ARGV[2])
local count = redis.call('ZCARD', KEYS[1])
if count < tonumber(ARGV[3]) then
    redis.call('ZADD', KEYS[1], ARGV[1], ARGV[4])
    redis.call('EXPIRE', KEYS[1], ARGV[2] * 2)
    return 1
end
return 0
```

```python
class RateLimiterTimeoutError(RuntimeError):
    """Raised by `NvdRateLimiter.acquire()` when `max_wait_seconds` elapses
    without ever claiming a slot — the caller (nvd_client) treats this
    exactly like any other lookup failure: log, return None, never raise
    further.
    """

class NvdRateLimiter:
    def __init__(
        self,
        redis_client: "redis.Redis",
        max_requests: int = 5,          # bump to 50 once NVD_API_KEY is set
        window_seconds: int = 30,
        max_wait_seconds: float = 60.0,
        poll_interval_seconds: float = 1.0,
    ) -> None: ...

    def try_acquire(self) -> bool:
        """One atomic attempt (the Lua script above). True = slot claimed,
        caller may proceed immediately. False = window is full right now."""

    def acquire(self) -> None:
        """Blocking retry loop over try_acquire(), sleeping
        poll_interval_seconds between attempts, until a slot is claimed or
        max_wait_seconds total elapses (-> RateLimiterTimeoutError). A
        worker process blocking here is acceptable and intentional: it's a
        Celery prefork process already inside a synchronous task, not an
        event loop that would otherwise be doing other work."""
```

`max_wait_seconds=60.0` is a deliberate ceiling: in the worst case (every one of 12 workers simultaneously wants an NVD call, window already full), a caller waits at most 60s before giving up and the NVD lookup degrades to "failed, no finding" rather than blocking a scan's correlation stage indefinitely.

---

## 4. The Cache-Check-Then-Fetch Flow

### `backend/app/modules/vulnerability/cache.py` (new)

```python
CVE_CACHE_TTL_DAYS = 7
# NVD data isn't hourly-volatile (a CVE's CVSS score/description rarely
# changes after initial publication), but new CVEs are added continuously
# and a CPE's applicability set can occasionally be revised after the
# fact. 7 days balances that slow drift against this project's heavily
# rate-limited, keyless NVD access — re-fetching a popular CPE daily would
# burn a meaningful fraction of the whole worker pool's 5-req/30s budget
# for no real freshness gain; a month would risk missing a newly-disclosed
# CVE for a long-lived cache entry. Revisit if an API key is ever added
# (the 10x higher limit makes a shorter TTL cheap).

def get_cached(db: Session, cpe23: str) -> CveCache | None:
    """Returns the cache row for this exact CPE 2.3 string, or None if
    never successfully looked up."""

def is_stale(entry: CveCache) -> bool:
    return datetime.now(UTC) - entry.fetched_at > timedelta(days=CVE_CACHE_TTL_DAYS)

def store(db: Session, cpe23: str, cves: list[NormalizedCve], total_results: int) -> CveCache:
    """Upsert: insert a new row, or update fetched_at/total_results/cves in
    place if cpe23 already has a (now-stale) row. Called ONLY with a
    successful fetch_cves_for_cpe() result (including a successful empty
    list) — never called with None. This is the single enforcement point
    of "a failed lookup is never cached": there is no code path from a
    `None` return value into this function."""
```

The "zero CVEs is a real cacheable outcome, a failed lookup is not" distinction is enforced structurally by `fetch_cves_for_cpe`'s own return-type contract (`list[NormalizedCve] | None`, §2) plus `store()` simply never being called when that value is `None` — there's no sentinel/flag to get wrong, the type itself makes the two cases distinguishable at every call site.

Flow for one CPE 2.3 string, used by `correlator.py` (§5):
1. `entry = get_cached(db, cpe23)`.
2. If `entry is not None and not is_stale(entry)`: use `entry.cves` directly — **zero NVD calls, zero rate-limiter interaction**.
3. Else (`entry is None`, or stale): call `cves = fetch_cves_for_cpe(cpe23, redis_client)` (rate-limited internally, §2/§3).
   - If `cves is None` (failure): log, treat as "no findings for this CPE this run" — do **not** call `store()`, so the next scan that needs this same CPE gets a fresh chance rather than inheriting a falsely-cached failure.
   - Else: `store(db, cpe23, cves, total_results)`, then use `cves`.

---

## 5. Orchestration Wiring (`backend/app/workers/tasks.py`)

### `backend/app/modules/vulnerability/correlator.py` (new) — the one function `tasks.py` calls

```python
MAX_DISTINCT_CPES_PER_SCAN = 25
# Worst case (every CPE a cache miss, rate limiter saturated by other
# concurrent scans): ~25 * (up to max_wait_seconds, nominally far less
# under the real 6s/request cadence) added latency to one scan's
# correlation stage — bounded, not unbounded, against a pathological scan
# fingerprinting many distinct products. CPEs beyond the cap are skipped
# entirely (logged), not retried next run, not a scan failure.

def correlate_services(db: Session, redis_client: "redis.Redis", services: list[Service]) -> None:
    """Best-effort: for every `services` row carrying nmap-sourced CPE
    evidence, look up (cache-first) matching CVEs and persist Finding rows.
    Never raises past this function in the ordinary case — per-CPE lookup
    failures are already swallowed by cache.py/nvd_client.py. Commits
    incrementally, once per distinct CPE processed (see the commit-cadence
    note below) — NOT once at the end.
    """
```

Logic:
1. Filter `services` to those with non-empty `evidence["cpe"]` (this alone is sufficient to select exactly the nmap-sourced rows — only the nmap adapter ever writes an `evidence["cpe"]` key; HTTP-prober evidence and `fingerprint_source is None` rows never have one).
2. Convert each raw CPE 2.2 string to CPE 2.3 via `cpe_utils.to_cpe23`; drop unconvertible ones (logged).
3. Build `cpe_to_services: dict[str, list[Service]]` (the dedup step — a CPE shared by 20 services across this one scan maps to one dict entry with 20 services, so cache.py's flow above runs once per *distinct* CPE regardless of how many services share it).
4. Take the first `MAX_DISTINCT_CPES_PER_SCAN` distinct CPEs in first-encountered order (stable, since `Asset.services` is already `order_by="Service.port"`); log + skip the remainder if the dict has more.
5. For each distinct CPE (one at a time, sequentially — correctness here matters more than throughput, and the rate limiter already serializes real NVD traffic across the whole pool anyway): run the cache-check-then-fetch flow (§4) to get `cves: list[NormalizedCve]`; for every `Service` mapped to this CPE, build one `Finding` row per `NormalizedCve` (`service_id`, `cve_id`, `matched_cpe=cpe23`, and the rest copied straight off `NormalizedCve`), `db.add_all(...)`, **`db.commit()` right here, once per distinct CPE** — not batched across the whole loop.

**The commit-cadence subtlety the implementer must not miss** (this phase's equivalent of Phase 3's "explicit return after discovery failure" lesson): Phase 3's fingerprinting block does exactly one `db.commit()` at the very end of its loop, because a single HTTP-probe failure there is already fully isolated *inside* `probe_services` (it just omits that port from the returned dict — nothing downstream of that can fail). Correlation's per-CPE work is not that cleanly isolated: it involves its own DB write (`cve_cache` upsert) interleaved with `Finding` inserts, across up to 25 iterations. If the whole loop were wrapped in one outer `try/except` with a single commit at the end (mirroring Phase 3's shape literally), then a late-loop failure (CPE #20 of 25 hits an unexpected DB error) would roll back the *uncommitted* work of CPEs #1-19 too — even though each of those individually "succeeded" per the never-fail contract. Committing once per distinct CPE means a `db.rollback()` from the outer safety-net `except` (step 6 below) only ever discards the *one* CPE that was mid-flight when the exception hit; everything already committed stays committed. This is a direct extension of Phase 3's own "Service rows first, then updated in place, committed as a batch" sequencing rationale, taken one step further because this phase's per-item cost (a possible real NVD round trip) is much higher and much more failure-prone than a single in-memory dict update.
6. The whole function body (the CPE-selection loop) is still additionally wrapped in a single outer `try/except Exception` in `correlate_services` itself, purely as the same kind of structural safety net Phase 3 used — catching any genuinely unexpected failure (e.g. a DB connectivity blip, a bug in `cpe_utils`) that step 5's per-CPE isolation didn't anticipate. On any such exception: `db.rollback()` (rolls back only the current, uncommitted CPE's work, per the note above), `logger.exception(...)`, and the function simply returns — it never raises, and it never touches `scan.status`.

### `backend/app/workers/tasks.py` (edit)

Insertion point: between the existing Step 9 (native HTTP enrichment) `try/except` block and the final Step 10 `COMPLETED` transition:

```python
        # Step 10 (Phase 4): CORRELATING. A new, separate try/except, same
        # shape as Step 9's: fingerprinting/correlation failures must never
        # fail the scan, so any exception here is logged and swallowed —
        # no scan.status mutation, no return, always falls through to
        # COMPLETED below. Unlike Step 9's native-only guard, this runs for
        # BOTH adapters uniformly: only nmap-adapter Service rows will ever
        # actually have evidence["cpe"], but correlate_services's own
        # filtering (not a scanner_name check here) is what decides that —
        # keeping this call unconditional means a future adapter that
        # somehow also produces CPE evidence doesn't need this call site
        # touched again, matching the FINGERPRINTING transition's own
        # existing "adapter-agnostic status machine" precedent.
        scan.status = ScanStatus.CORRELATING
        db.commit()
        try:
            redis_client = redis.Redis.from_url(get_settings().REDIS_URL)
            correlate_services(db, redis_client, services)
        except Exception:
            db.rollback()
            logger.exception("run_scan_task: scan %s vulnerability correlation failed", scan_id)

        # Step 11: unchanged (was Step 10).
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(UTC)
        db.commit()
```

No explicit `return` is added to this new `except` block — unlike Phase 3's discovery-failure `except` block, which needed one because fingerprinting/`COMPLETED` code was newly added *after* it in the function body (so falling through without a `return` would have been a regression). This correlation `except` block has nothing after it except the unconditional `COMPLETED` transition, which is exactly the desired "fall through" behavior — identical in shape to Step 9's existing fingerprinting `except` block, which also has no `return`. Called out explicitly here so a reviewer doesn't flag its absence as an oversight.

**The never-fail-the-scan contract, restated for this stage specifically:** only the original discovery-stage `except` block (Phase 2, with Phase 3's added `return`) may ever set `scan.status = ScanStatus.FAILED`. Neither the fingerprinting block nor this new correlation block may do so, under any circumstance — a CPE that fails to resolve, an NVD outage, a Redis connection error reaching the rate limiter, a malformed cache row — none of it may regress an already-`COMPLETED`-bound scan. This is unchanged, inherited policy, not a new rule, but it is worth re-stating because this phase is the first to add a *second* external network dependency (NVD, alongside the HTTP prober's probes) whose failure modes (DNS, TLS, 403/429, timeouts) are easy to imagine incorrectly "deserving" a `FAILED` scan — they do not.

---

## 6. API Exposure

**Decision: nest `findings: list[FindingRead] = []` directly onto `ServiceRead`**, exposed through the *existing* `GET /scans/{scan_id}/assets` endpoint — no new endpoint this phase.

Justification, directly addressing why Phase 3's reasoning for a *separate* endpoint doesn't re-apply the same way here: Phase 3 added `GET /scans/{scan_id}/assets` specifically to avoid bloating `GET /scans` (a frequently-polled, multi-row **list** endpoint used for a simple status table) with full nested evidence nobody there needs. `GET /scans/{scan_id}/assets` is not that endpoint — it is already a dedicated, single-scan, deep-results endpoint whose entire reason to exist is nested evidence (it already returns `Service.evidence` verbatim per row). Adding `findings` to the same response is the same shape of thing it already does, not a new category of cost: one more JSONB-shaped field per row, on an endpoint that's fetched once per results-page view, not polled in a tight loop. A separate `GET /scans/{scan_id}/findings` would only earn its keep if some consumer needed findings decoupled from services/assets (e.g., a future cross-scan findings dashboard, explicitly out of scope this phase) — building it now with no such consumer is YAGNI; add it later if/when Phase 7/8 reporting needs a flat list.

### `backend/app/schemas/finding.py` (new)

```python
class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    service_id: uuid.UUID
    cve_id: str
    matched_cpe: str
    severity: str
    cvss_score: float | None
    cvss_vector: str | None
    description: str | None
    evidence: dict
    created_at: datetime
```

### `backend/app/schemas/service.py` (edit)

Add `from app.schemas.finding import FindingRead` and `findings: list[FindingRead] = []` to `ServiceRead`.

### `backend/app/services/scan_service.py` (edit)

`get_scan_assets`'s eager-load chain widens to avoid N+1 on the new relationship: `.options(selectinload(Asset.services).selectinload(Service.findings))`.

No change to `backend/app/api/routes/scans.py` — the route body is unchanged; only its response shape, via the schema edit above, gains the new field.

---

## 7. Frontend

### `frontend/src/lib/types/finding.ts` (new)

```typescript
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";

export interface FindingRead {
  id: string;
  service_id: string;
  cve_id: string;
  matched_cpe: string;
  severity: Severity;
  cvss_score: number | null;
  cvss_vector: string | null;
  description: string | null;
  evidence: Record<string, unknown>;
  created_at: string;
}
```

### `frontend/src/lib/types/service.ts` (edit)

Add `import type { FindingRead } from "./finding";` and `findings: FindingRead[];` to `ServiceRead`.

### `frontend/src/components/SeverityBadge.tsx` (new)

Same exhaustive-`Record` convention as `StatusBadge.tsx`/`FingerprintBadge.tsx` — but unlike `FingerprintBadge`'s `Exclude<..., null>` pattern, `Severity` has no `null` member (per §1's "NONE is a real value" decision), so this is a plain `Record<Severity, string>`, no separate null-case branch needed:

```typescript
const SEVERITY_STYLES: Record<Severity, string> = {
  CRITICAL: "bg-red-100 text-red-800 ring-red-400",
  HIGH: "bg-orange-100 text-orange-700 ring-orange-300",
  MEDIUM: "bg-amber-100 text-amber-700 ring-amber-300",
  LOW: "bg-sky-100 text-sky-700 ring-sky-300",
  NONE: "bg-zinc-100 text-zinc-500 ring-zinc-300",
};
```

### `frontend/src/app/projects/[projectId]/scans/[scanId]/page.tsx` (edit)

Inside each service `<tr>`, under the existing "Evidence" `<details>` cell (or as an additional cell — implementer's call on exact layout, acceptance criterion is just that it renders per-service, not per-asset): when `service.findings.length > 0`, render one line per finding: `<SeverityBadge severity={finding.severity} />`, then `<a href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`} target="_blank" rel="noopener noreferrer" className="font-mono text-xs text-blue-600 hover:underline">{finding.cve_id}</a>`, then the CVSS score if present. When `service.findings.length === 0`, render nothing extra — no "No findings" placeholder, no error state; this is the overwhelmingly common case (every HTTP-prober-sourced service, every unfingerprinted service, and any nmap-sourced service whose CPE genuinely has zero known CVEs) and must look identical to "nothing to say here," not a degraded or error state.

This is the one place in the whole project that links to an external site. That's fine specifically because: (a) NVD is a static, well-known, public US-government reference page, not a third-party service VulnSight's *backend* talks to on the user's behalf (the backend already talks to NVD, server-side, for the lookup itself — that's an outbound API call already covered by §2/§3's httpx+timeout+error-handling discipline, not a frontend concern); (b) this specific link is navigated by a human clicking it in their own browser, carrying no VulnSight credentials, cookies, or scan data in the URL beyond the already-public CVE id — there is no SSRF, data-exfiltration, or trust concern analogous to why `http_prober.py` is so defensive about the targets *it* probes, because the direction of trust here is the opposite (a human choosing to leave the app), not the backend reaching out to an attacker-influenced host.

---

## 8. Testing

- **`backend/tests/test_cpe_utils.py` (new)**: a table of real nmap-shaped CPE 2.2 inputs (`cpe:/a:nginx:nginx:1.24.0`, one with an `update`/`edition` field present, one OS cpe `cpe:/o:linux:linux_kernel:5.4`) asserting the exact CPE 2.3 output string; a malformed-input case (wrong prefix, too many fields, an unexpected character after unquoting) asserting `None`, never an exception.
- **`backend/tests/test_nvd_client.py` (new)**: never makes a real network call — `httpx.Response` objects are constructed directly in-test (`httpx.Response(200, json=CANNED_BODY)`) and patched in as the return value of whatever `httpx.Client` method `nvd_client.py` calls, mirroring this project's "never touch a real external host in tests" discipline while matching the real NVD response shape exactly (`{"resultsPerPage":..., "totalResults":..., "vulnerabilities":[{"cve":{...}}]}` — nested under `vulnerabilities`). Cases: a normal multi-CVE response parses into the exact expected `NormalizedCve` list (including correct `cvssMetricV31` > `V30` > `V2` fallback priority); a `"vulnerabilities": []` response returns `[]` (not `None`); a 403 response returns `None`; a 429 response returns `None`; a mocked `httpx.TimeoutException` returns `None`; a response missing the expected `cve`/`id` keys returns `None` without raising; a rate-limiter mock raising `RateLimiterTimeoutError` returns `None`. A separate case asserts the `apiKey` header is present only when `NVD_API_KEY` is set (monkeypatch `get_settings`).
- **`backend/tests/test_rate_limiter.py` (new)**: needs a real ephemeral Redis — **new test infrastructure**, since up to now this suite's only Redis usage was the Celery broker/backend, entirely abstracted away by mocking `run_scan_task.apply_async`/`celery_app.control.revoke` (`conftest.py`'s two autouse fixtures) rather than ever touching Redis as a data store. Add a new fixture (following the exact precedent already set for the Postgres test database): a `TEST_REDIS_URL` env var defaulting to `REDIS_URL` with its database index swapped to a dedicated test index (e.g. `/0` → `/15`, mirroring the `vulnsight`/`vulnsight_test` database-name-swap pattern), a fixture that connects and calls `flushdb()` before/after each test for isolation (safe — it's a dedicated index, never the real broker's `/0`). Tests: construct `NvdRateLimiter(client, max_requests=3, window_seconds=1, max_wait_seconds=0.5)` for fast determinism; 3 immediate `try_acquire()` calls succeed, a 4th fails immediately (`try_acquire() is False`); a 4th via `acquire()` either succeeds after the ~1s window rolls over or raises `RateLimiterTimeoutError` if `max_wait_seconds` is set shorter than the window; a concurrency test using `concurrent.futures.ThreadPoolExecutor` firing 10 simultaneous `try_acquire()` calls against `max_requests=5` and asserting exactly 5 (never more) return `True` — this is the test that actually proves the race the Lua script's atomicity is there to prevent, and it must be run enough times or with enough threads that a non-atomic, buggy implementation would flake it.
- **`backend/tests/test_cve_cache.py` (new)**: pure DB logic, uses the existing `db` fixture, no Redis/HTTP needed. A cache miss (`get_cached` returns `None`) on first lookup; `store()` then `get_cached()` round-trips the exact `NormalizedCve` list; a row older than `CVE_CACHE_TTL_DAYS` is reported `is_stale() is True`, a fresh one `False`; calling `store()` again for the same `cpe23` updates the existing row in place (asserted via the unique `cpe` column still having exactly one row, not two).
- **`backend/tests/test_correlator.py` (new)**: unit-level tests of `correlate_services` with `nvd_client.fetch_cves_for_cpe` mocked directly (no real Redis/HTTP) — dedup (two `Service` rows sharing one CPE string → the mock is called exactly once, two sets of `Finding` rows persisted, one per service); the per-scan cap (more distinct CPEs than `MAX_DISTINCT_CPES_PER_SCAN` → only the capped number are looked up, the rest skipped, asserted via mock call count); a mocked `None` return (lookup failure) → zero `Finding` rows for that CPE, no exception, no `cve_cache` row written; a cache-hit case (seed a `CveCache` row directly, assert the mock is never called at all for that CPE); the incremental-commit behavior (a mocked failure on the *second* of three CPEs still leaves the first CPE's `Finding` rows committed and queryable).
- **`backend/tests/test_scan_orchestration.py` (extend)**: mocking `correlator.correlate_services` itself at this level (not its internals — that's `test_correlator.py`'s job) to keep this file's existing "no real network, no real Redis" character: assert `scan.status` passes through `CORRELATING` for both adapters; assert a `correlate_services`-raises case still reaches `COMPLETED` with `error_message` still `None` (the never-fail-the-scan contract, this stage's version); assert `correlate_services` is called with the full `services` list regardless of adapter (its own internal CPE-presence filtering is what matters, not a `scanner_name` check at this call site — covered by `test_correlator.py`, not re-tested here).
- **Extend the Phase 3 scan-assets route test** (`test_scan_assets_route.py` or `test_scans.py`): seed a `Service` row with one or more `Finding` rows directly via the `db` fixture; `GET /scans/{id}/assets` response includes the expected nested `findings` array with all `FindingRead` fields; a `Service` with no findings returns `"findings": []`, not an omitted key or `null`.

---

## 9. Verification Plan

Getting nmap to reliably assign a `<cpe>` against the Docker-internal targets this project's prior verification passes used (`postgres`, the `backend` container's own uvicorn) is **not guaranteed** — nmap only emits a `<cpe>` when one of its service probes positively matches a signature that happens to carry a CPE in its `nmap-service-probes` database, which is probabilistic, not something this plan can promise ahead of time. Rather than block verification on that, this plan uses the practical, legally/safely uncomplicated approach: seed a `Service` row's `evidence["cpe"]` directly with a real, long-published CPE (e.g. `cpe:/a:apache:http_server:2.4.49`, the affected version for CVE-2021-41773, a well-known, fully patched, publicly documented CVE) and run the correlation pipeline against it with a **real, live NVD network call** — this is not "scanning" or "attacking" anything; it is asking a public reference database a question about a version string, which carries no target-authorization concern at all (nothing is being scanned; `target.authorization_confirmed` never enters into this path). Attempting a real nmap-detected CPE first is still worth trying and documented below; the seeded fallback is the deterministic, always-available path.

```bash
docker compose up --build
docker compose exec backend alembic upgrade head

# --- 1. Attempt a real nmap -sV CPE detection (best-effort, not guaranteed) ---
curl -X POST http://localhost:8000/api/v1/scans -H "Content-Type: application/json" \
  -d '{"project_id":"...","target_id":"<an in-network authorized target, e.g. postgres>","config":{"scanner":"nmap"}}'
docker compose exec postgres psql -U vulnsight -d vulnsight -c \
  "SELECT port, evidence->'cpe' FROM services WHERE evidence ? 'cpe';"
# if this returns any row, a real end-to-end nmap->Finding pass can be observed directly in
# step 4 below against that scan_id instead of the seeded one. If empty (nmap didn't recognize
# anything with an associated CPE this run), that's an expected, documented outcome — proceed
# to the seeded path below, which exercises the identical correlate_services() code path.

# --- 2. Seed a known-CPE Service row directly and run correlation against it, for real ---
docker compose exec backend python -c "
from app.db.session import SessionLocal
from app.models.project import Project
from app.models.target import Target, TargetType
from app.models.scan import Scan, ScanStatus
from app.models.asset import Asset
from app.models.service import Service
from app.modules.vulnerability.correlator import correlate_services
import redis
from app.core.config import get_settings

db = SessionLocal()
project = Project(name='Phase 4 verification')
db.add(project); db.flush()
target = Target(project_id=project.id, value='127.0.0.1', target_type=TargetType.IP, authorization_confirmed=True)
db.add(target); db.flush()
scan = Scan(project_id=project.id, target_id=target.id, status=ScanStatus.CORRELATING)
db.add(scan); db.flush()
asset = Asset(project_id=project.id, target_id=target.id, scan_id=scan.id, host='127.0.0.1')
db.add(asset); db.flush()
service = Service(asset_id=asset.id, port=80, protocol='tcp', state='open',
                   fingerprint_source='nmap-sv', evidence={'cpe': ['cpe:/a:apache:http_server:2.4.49']})
db.add(service); db.commit()

redis_client = redis.Redis.from_url(get_settings().REDIS_URL)
correlate_services(db, redis_client, [service])
db.commit()
print('scan_id:', scan.id, 'service_id:', service.id)
"
# note the printed scan_id / service_id for the queries below

# --- 3. Confirm real Finding rows with real CVE data ---
docker compose exec postgres psql -U vulnsight -d vulnsight -c \
  "SELECT cve_id, severity, cvss_score, matched_cpe FROM findings WHERE service_id = '<service_id>';"
# expect at least CVE-2021-41773 (and likely CVE-2021-42013, the follow-up) with real severity/score

# --- 4. Confirm the cache is populated ---
docker compose exec postgres psql -U vulnsight -d vulnsight -c \
  "SELECT cpe, total_results, fetched_at FROM cve_cache WHERE cpe LIKE '%apache%';"

# --- 5. Confirm a second identical lookup does NOT re-hit NVD ---
# Re-run step 2's script a second time with a NEW Service row carrying the SAME cpe string.
# Expect a 'cache hit' log line on the second run and no new NVD request — grep the worker's
# JSON logs: docker compose logs backend worker | grep -i "nvd_client\|cve_cache" | grep -i "cpe:/a:apache"
# A mocked-call-count assertion covers this deterministically in test_correlator.py already;
# this step is the live-system confirmation of the same behavior.

# --- 6. Confirm the rate limiter actually throttles concurrent calls ---
docker compose exec backend python -c "
import time, redis
from concurrent.futures import ThreadPoolExecutor
from app.core.config import get_settings
from app.modules.vulnerability.rate_limiter import NvdRateLimiter

client = redis.Redis.from_url(get_settings().REDIS_URL)
limiter = NvdRateLimiter(client, max_requests=5, window_seconds=30, max_wait_seconds=2)
results = []
def attempt():
    results.append((time.time(), limiter.try_acquire()))
with ThreadPoolExecutor(max_workers=10) as pool:
    list(pool.map(lambda _: attempt(), range(10)))
granted = sum(1 for _, ok in results if ok)
print('granted immediately:', granted, '(expect exactly 5 of 10)')
"

# --- 7. New results shape ---
curl http://localhost:8000/api/v1/scans/<scan_id>/assets
# expect the port-80 service to include a non-empty "findings" array

# --- 8. Frontend ---
# open http://localhost:3000/projects/<projectId>/scans/<scanId> — the services table now shows
# severity-colored badges and clickable CVE ids (opening nvd.nist.gov in a new tab) under the
# port-80 row; every other row (no CPE evidence) shows nothing extra, not an error.

docker compose exec backend pytest -v
docker compose exec backend ruff check . && black --check . && mypy app
docker compose exec frontend npm run lint && npx tsc --noEmit
```

---

## Roadmap Beyond This Plan (not detailed here)

- **Phase 5 — Confidence & Validation**: confidence scoring and validation states applied on top of this phase's `Finding` rows — e.g. weighting how much to trust an nmap version-probe match vs. a definitive banner, and letting an operator mark a `Finding` as a confirmed false positive. This phase deliberately does none of that; every `Finding` row here is an unweighted, unvalidated "NVD says so."
- **Phase 6 — Misconfiguration Analysis**: TLS/header misconfiguration checks, a natural extension of the HTTP prober's already-captured header set from Phase 3 — unrelated to CVE correlation, orthogonal to this phase.
- **Phase 7 — Risk Intelligence**: risk scoring that will consume both this phase's `Finding.severity`/`cvss_score` and Phase 5's confidence scores together.
- **Phase 8 — Reporting**: likely the first real consumer of a cross-scan/cross-project findings view, at which point a dedicated `GET /scans/{id}/findings` (or a project-wide findings endpoint) becomes worth building — explicitly deferred, not built this phase (§6).
- Deferred within correlation itself, for a later pass if ever prioritized: CPE construction from HTTP-prober evidence (needs a vendor-inference strategy this phase explicitly declines to build), full CPE 2.3 spec-compliant conversion (a real library, not the hand-rolled converter), NVD multi-page pagination, a proactive/background cache-refresh job, and raising the rate limiter's limits once an `NVD_API_KEY` is actually configured.
