# PLAN_7.md — VulnSight Phase 7: Risk Intelligence (VRPS Scoring)

Narrative plan. Binding authority for anything `PLAN_7_TASKS.md` doesn't
fully specify. Companion: `PLAN_7_TASKS.md` (task breakdown used for
execution).

**Architecture decisions below were made directly by the controller**,
not through the usual brainstorming conversation — the user opted out
("continue", following the same pattern as Phase 6's "i would rather you
pick") before any question was actually posed. Every call below is
therefore flagged as a controller judgment, not a user-confirmed
requirement, exactly as Phase 6's equivalent calls were.

## Why this phase, and what it actually computes

Per the project's own roadmap (reaffirmed across `PLAN_4.md`/`PLAN_5.md`/
`PLAN_6.md`'s "Roadmap Beyond This Plan" sections): **configurable VRPS
(Vulnerability Risk Prioritization Score) scoring** — the first phase
that *combines* evidence from three earlier phases into a single
prioritization signal, rather than adding a new evidence source of its
own:

- Phase 4's `Finding.severity`/`cvss_score` — what was found, how bad it
  is per NVD/CVSS.
- Phase 5's `Finding.confidence_score`/`validation_state` — how sure we
  are it's real, and whether a human has already ruled it out.
- Phase 6's `Misconfiguration.severity` — detection-only evidence with no
  CVE/confidence/validation linkage at all.

`PLAN_5.md`'s own closing section named this phase's job precisely:
"discounting a Finding's contribution to an overall risk score by its
confidence, and likely excluding (or heavily discounting)
FALSE_POSITIVE-marked findings from that score entirely." This plan
takes that as the binding shape of the Finding side of the formula, and
extends the same spirit to Misconfiguration (no confidence/validation
signal exists for it, so it contributes at a flat, severity-only,
relatively-discounted weight — see §2).

Runs in `ScanStatus.RISK_ANALYSIS`, reserved-but-unused in the enum since
Phase 1, sitting between `CORRELATING` and `REPORT_GENERATION`
(`backend/app/models/scan.py:25`) — exactly the same "slot already
exists, this phase finally wires it up" precedent as `ANALYZING` was for
Phase 6. `REPORT_GENERATION` itself is still not wired up (Phase 8's
job), so in practice this stage currently falls straight through to
`COMPLETED`, same as `ANALYZING` fell straight through to `CORRELATING`
before Phase 6 existed.

**Zero new network surface.** Unlike Phase 4 (NVD client) and Phase 6
(TLS inspector), this phase reads only already-persisted `Finding`/
`Misconfiguration` rows and writes two new columns — no outbound call,
no new runtime dependency.

## Controller's architecture calls (the four open questions)

1. **Scoring unit: both per-Asset and per-Scan**, not a choice between
   them. `Asset` gains `risk_score`/`risk_tier` (aggregated across all of
   that asset's services' findings+misconfigs); `Scan` gains its own
   `risk_score`/`risk_tier` (aggregated across that scan's assets, using
   the exact same aggregation function one level up — see §2). No
   `Service`-level score: nobody asked for that granularity, and `Asset`
   is already the practical "which host do I fix first" unit the
   roadmap's own framing targets.
2. **"Configurable" means named, documented constants in one file this
   phase, not a DB-backed/admin-editable config.** `scoring_config.py`
   holds every tunable number (severity-fallback weights, the
   misconfiguration-vs-finding relative weight, the tier bands) as
   module-level constants a future phase could expose through a real
   config surface. This mirrors the project's own established precedent
   exactly: `confidence_score`'s band constants and Phase 6's
   `SENSITIVE_PORTS` table are both hardcoded-but-named and explicitly
   flagged in `CLAUDE.md` as first-pass, not yet tunable at runtime. No
   new config table, no new API this phase.
3. **The score is persisted, not computed on-the-fly at read time.** New
   nullable columns (`risk_score: float | None`, `risk_tier: str | None`)
   on both `Asset` and `Scan`, written once during `RISK_ANALYSIS` and
   never recomputed outside a scan run — same "computed once, stored"
   precedent as `confidence_score`. **Nullable, unlike `confidence_score`**:
   every `Finding` is created by a pure function with no missing-data
   path, so `confidence_score` is `NOT NULL`; every pre-existing `Asset`/
   `Scan` row (and every scan that hasn't reached `RISK_ANALYSIS` yet)
   genuinely never went through scoring, so `NULL` here means "not yet
   scored" — a real, distinct state from a computed score of `0.0`/tier
   `"NONE"` ("scored, nothing found"). No backfill migration needed,
   same reasoning Phase 6's additive `CREATE TABLE` used (no existing
   rows have a value to retrofit).
4. **Scale/presentation: both.** A continuous `risk_score` (0-100) plus a
   `risk_tier` (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`NONE`) banded from it.
   `risk_tier` deliberately reuses the exact same vocabulary as
   `Finding.severity`/`Misconfiguration.severity` (including `NONE` as a
   real, distinct value, not an absence) — this lets the frontend reuse
   `Severity`/`SeverityBadge` unchanged, the same reuse Phase 6 already
   did for `Misconfiguration`.

## Known, accepted limitation: today there is only ever one Asset per scan

`CLAUDE.md`'s own Conventions section: "One `Asset` per non-CIDR scan, no
cross-scan dedup yet." That means in every real scan today, the
per-Asset score and the per-Scan score are numerically identical — this
phase still implements and stores both independently and correctly,
because (a) the schema already structurally supports multiple assets per
scan and a future CIDR-scanning phase would otherwise need this redone,
and (b) the roadmap explicitly asked for "per-Asset breakdown... or
both," not "per-Asset breakdown, only relevant once multi-asset scans
exist."

## Scope limits (explicit, not gaps)

- **No scoring-config override API/table this phase.** Constants live in
  one file; no per-project/per-scan override exists yet. Flagged in
  `CLAUDE.md` as a first-pass judgment call needing real-world tuning,
  same framing as `confidence_score`'s bands and `SENSITIVE_PORTS`.
- **No re-scoring when a `Finding`'s `validation_state` changes after the
  scan completed.** `risk_score`/`risk_tier` are a snapshot taken once
  during `RISK_ANALYSIS`, exactly like `confidence_score` is a snapshot
  taken once during `CORRELATING`. `finding_service.update_validation`
  does **not** recompute `Asset`/`Scan` risk — keeping the scoring and
  validation mechanisms independent, the same discipline `CLAUDE.md`
  already states for `correlator.py`/`finding_service.py`. Known,
  accepted limitation: confirming or invalidating findings after a scan
  completes leaves that scan's risk score stale until its next run — the
  same "stale until re-run" class of gap already documented for
  correlation/analysis failures elsewhere in this project.
- **No `Service`-level persisted score.**
- **No new `ScanStatus` value.** The slot already exists.
- **No bulk/manual re-score endpoint, no scheduled re-scoring.**
- **No changes to `discovery/`, `fingerprinting/`, `vulnerability/`, or
  `misconfiguration/` modules.** This phase only reads their already-
  persisted `Finding`/`Misconfiguration` rows.

## §1 Migration: `risk_score`/`risk_tier` on `Asset` and `Scan`

Edit `backend/app/models/asset.py` — add:

```python
    # --- Phase 7 additions ---
    # NULL means "not yet risk-scored" (pre-Phase-7 row, or this scan
    # hasn't reached RISK_ANALYSIS yet) -- a real, distinct state from a
    # computed score of 0.0/tier "NONE" ("scored, nothing found"). See
    # PLAN_7.md's architecture-decision #3 for why this is nullable where
    # Finding.confidence_score is not.
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    # CRITICAL/HIGH/MEDIUM/LOW/NONE -- same vocabulary and same
    # plain-string-not-enum convention as Finding.severity/
    # Misconfiguration.severity.
    risk_tier: Mapped[str | None] = mapped_column(String(20), nullable=True)
```

(needs `Float` added to the existing `sqlalchemy` import line.)

Edit `backend/app/models/scan.py` — add the identical pair of columns to
`Scan` (same types, same nullability, same reasoning).

Migration: purely additive `ADD COLUMN`, no backfill (no pre-existing
row has a value to retrofit — every row's new columns are genuinely
`NULL`, meaning exactly what `NULL` is defined to mean here). `down_revision`
= current head, confirmed by directly reading every file in
`backend/migrations/versions/` while writing this plan: `111ce3c92341` →
`26de1feba77b` → `d6b7d6e6b8c8` → `45f7e770cdbb` → `8f08312a037b` →
`60f5828d656a` (head) — a single linear chain, no branching. Re-verify
this is still the head before generating the new revision.

## §2 Scoring config + pure scoring functions

`backend/app/modules/risk/scoring_config.py` (new) — every tunable
number, named and commented with its own reasoning (the package already
exists as an empty placeholder — `backend/app/modules/risk/__init__.py`):

```python
# CVSS is 0-10; every contribution in this module is normalized to the
# same 0-100 scale as risk_score/confidence_score/Misconfiguration has
# no numeric equivalent of, so everything meets at 0-100.
CVSS_TO_100_SCALE = 10.0

# Fallback weight (0-100 scale) for a Finding with no cvss_score at all
# -- a real, non-null-equivalent case (Finding.severity's own docstring:
# "a CVE with no CVSS metrics at all legitimately IS severity 'NONE'").
# Reused unchanged for Misconfiguration.severity below -- both models
# share the exact same CRITICAL/HIGH/MEDIUM/LOW/NONE vocabulary.
SEVERITY_FALLBACK_WEIGHT: dict[str, float] = {
    "CRITICAL": 90.0,
    "HIGH": 70.0,
    "MEDIUM": 40.0,
    "LOW": 15.0,
    "NONE": 0.0,
}

# A matched CVE (Finding) is a specific, identified vulnerability; a
# misconfiguration is a weaker, more heuristic signal (e.g. a missing
# security header is bad practice, not a proven exploit path). This is
# this phase's single most consequential, least-validated judgment call
# -- flag for revisit in CLAUDE.md, same framing as confidence_score's
# bands and Phase 6's SENSITIVE_PORTS table.
MISCONFIG_RELATIVE_WEIGHT = 0.6

# 0-100 score -> tier, descending, first threshold met wins. A score of
# exactly 0.0 (no contributions at all, or every contribution excluded
# as a false positive) lands on the RISK_TIER_FLOOR below, not "LOW" --
# "nothing found" is not the same claim as "something low-severity
# found" (mirrors Finding.severity's own NONE-is-a-real-value precedent).
RISK_TIER_BANDS: list[tuple[float, str]] = [
    (75.0, "CRITICAL"),
    (50.0, "HIGH"),
    (25.0, "MEDIUM"),
    (0.01, "LOW"),
]
RISK_TIER_FLOOR = "NONE"
```

`backend/app/modules/risk/scoring.py` (new) — pure functions, no DB/
network, mirroring `confidence.py`'s own "every branch returns a
concrete float, never raises" discipline:

```python
from app.models.finding import Finding, FindingValidationState
from app.models.misconfiguration import Misconfiguration
from app.modules.risk.scoring_config import (
    CVSS_TO_100_SCALE,
    MISCONFIG_RELATIVE_WEIGHT,
    RISK_TIER_BANDS,
    RISK_TIER_FLOOR,
    SEVERITY_FALLBACK_WEIGHT,
)


def score_finding_contribution(finding: Finding) -> float:
    """0-100. FALSE_POSITIVE findings contribute exactly zero -- per
    PLAN_5.md's own stated expectation for this phase. UNVALIDATED and
    CONFIRMED both contribute at full confidence-discounted weight;
    CONFIRMED gets no additional boost -- confidence_score is already
    the "how sure are we" signal, and double-counting validation on top
    of it would conflate two mechanisms CLAUDE.md is explicit about
    keeping independent.
    """
    if finding.validation_state == FindingValidationState.FALSE_POSITIVE:
        return 0.0
    base = (
        finding.cvss_score * CVSS_TO_100_SCALE
        if finding.cvss_score is not None
        else SEVERITY_FALLBACK_WEIGHT.get(finding.severity, 0.0)
    )
    base = min(base, 100.0)
    return base * (finding.confidence_score / 100.0)


def score_misconfiguration_contribution(misconfig: Misconfiguration) -> float:
    """0-100. No confidence/validation signal exists for Misconfiguration
    (Phase 6 deliberately scoped that out) -- flat severity weight,
    relatively discounted against a matched-CVE Finding's own weight.
    """
    return SEVERITY_FALLBACK_WEIGHT.get(misconfig.severity, 0.0) * MISCONFIG_RELATIVE_WEIGHT


def aggregate_risk(contributions: list[float]) -> float:
    """Noisy-OR aggregation: treats each 0-100 contribution as a
    0.0-1.0 'probability this thing alone makes the asset/scan risky',
    combines them as independent probabilities (1 - product(1 - p_i)),
    scales back to 0-100. A single near-100 contribution dominates the
    result; many small contributions add up without a plain sum blowing
    past 100. Empty input -> 0.0 (no evidence of risk), never raises.
    Used identically at both the per-Asset level (over that asset's
    Finding/Misconfiguration contributions) and the per-Scan level (over
    its assets' own already-aggregated risk_score values) -- see
    risk_scorer.py.
    """
    if not contributions:
        return 0.0
    survival = 1.0
    for contribution in contributions:
        clamped = max(0.0, min(contribution, 100.0)) / 100.0
        survival *= 1.0 - clamped
    return round((1.0 - survival) * 100.0, 2)


def tier_for_score(score: float) -> str:
    """Never raises -- RISK_TIER_FLOOR is always the fallback for any
    score below every band's threshold, including 0.0.
    """
    for threshold, tier in RISK_TIER_BANDS:
        if score >= threshold:
            return tier
    return RISK_TIER_FLOOR
```

## §3 `risk_scorer.py` orchestrator + `RISK_ANALYSIS` stage wiring

`backend/app/modules/risk/risk_scorer.py` (new):

```python
def score_assets(db: Session, scan: Scan, assets: list[Asset]) -> None:
    """Best-effort per-Asset scoring, then one per-Scan aggregate.
    Mirrors correlator.py/analyzer.py's per-unit isolation: each asset
    gets its own try/except and its own commit, so one asset's scoring
    failure never aborts scoring of the rest (same class of isolation,
    same reasoning).

    UNLIKE correlator.py/analyzer.py, this function's signature DOES
    take `scan` -- not just `assets`. The inherited discipline from
    Phase 4/6 is "never touch scan.status", not "never touch scan at
    all": scan.risk_score/scan.risk_tier are this function's own columns
    to write, and writing them is the entire point of its second half. A
    reviewer should treat any write to scan.status inside this module as
    a Critical finding; the scan.risk_score/scan.risk_tier writes below
    are not that.

    No network, no Redis -- purely a DB-read + pure-function + DB-write
    stage. Never raises past this function.
    """
```

Body, per the architecture decisions above:

1. For each `asset` in `assets` (its own try/except): gather every
   `score_finding_contribution(finding)` across every `service.findings`
   for `service in asset.services`, plus every
   `score_misconfiguration_contribution(misconfig)` across every
   `service.misconfigurations`, into one flat `contributions` list.
   `asset.risk_score = aggregate_risk(contributions)`;
   `asset.risk_tier = tier_for_score(asset.risk_score)`. Commit. On
   failure: rollback, log, continue to the next asset (that asset's
   score is simply never set this run — `NULL`, not a crash, and not
   silently "0.0/NONE" either, preserving the "not yet scored" vs
   "scored clean" distinction even on a partial failure).
2. After the loop (its own, separate try/except): collect the
   `risk_score` of every asset that was successfully scored above (an
   asset that failed step 1 contributes nothing to the scan aggregate —
   the same "a failed unit looks like a clean one" ambiguity class
   `CLAUDE.md` already documents for correlation/analysis failures).
   `scan.risk_score = aggregate_risk(asset_scores)`;
   `scan.risk_tier = tier_for_score(scan.risk_score)`. Commit.

Edit `backend/app/workers/tasks.py`: insert a new stage between the
existing `CORRELATING` block (Step 10) and the existing `COMPLETED` line
(Step 11) — re-verify the real current step numbers/line numbers
directly in the file before editing, do not trust stale references from
this plan:

```python
# Step N (Phase 7): RISK_ANALYSIS. Same best-effort shape as Steps
# 9/9.5/10: scoring failures must never fail the scan, so any exception
# here is logged and swallowed -- no scan.status mutation, no return,
# always falls through to COMPLETED below. Sits in the slot the
# ScanStatus enum already reserved between CORRELATING and
# REPORT_GENERATION; REPORT_GENERATION itself isn't wired up yet (Phase
# 8), so this stage currently falls straight through to COMPLETED, same
# as ANALYZING fell straight through to CORRELATING before Phase 6
# existed.
scan.status = ScanStatus.RISK_ANALYSIS
db.commit()
try:
    score_assets(db, scan, [asset])
except Exception:
    db.rollback()
    logger.exception("run_scan_task: scan %s risk scoring failed", scan_id)
```

`asset` is the single `Asset` ORM object already constructed and in
scope from Step 5-7 above (`CLAUDE.md`: "One `Asset` per non-CIDR scan"
— passed as a one-element list for signature symmetry with
`correlate_services`/`analyze_services`, and to avoid this call site
needing to change if a future phase makes multi-asset scans real).

## §4 API additions

Edit `backend/app/schemas/scan.py`: add `risk_score: float | None` and
`risk_tier: str | None` to `ScanRead` (not to `ScanStatusRead` — that's
the lightweight polling schema, left untouched, same restraint every
prior phase has shown about not touching every schema that happens to
reference `Scan`).

Edit `backend/app/schemas/asset.py`: add the identical pair of fields to
`AssetRead`.

No new route — this rides the existing `GET /scans/{id}` (`ScanRead`)
and `GET /scans/{id}/assets` (`AssetRead`, already nested with
`services`/`findings`/`misconfigurations`) endpoints.

## §5 Frontend additions

Edit `frontend/src/lib/types/scan.ts`: add `risk_score: number | null`
and `risk_tier: Severity | null` to `ScanRead` (import `Severity` from
`./finding` — reusing the exact same union
`"CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE"` deliberately, the same
reuse Phase 6 already did for `Misconfiguration.severity`, so
`SeverityBadge` needs zero changes to render a risk tier).

Edit `frontend/src/lib/types/asset.ts`: add the identical pair of fields
to `AssetRead`.

Edit `frontend/src/app/projects/[projectId]/scans/[scanId]/page.tsx`:

- In the existing scan-summary `<section>` (around the `StatusBadge`/
  target line, `page.tsx:107-120`), add the scan's own risk score/tier
  alongside: render nothing when `scan.risk_tier` is `null` (same
  "renders nothing" convention `ValidationBadge` already uses for
  `unvalidated`), otherwise a `SeverityBadge severity={scan.risk_tier}`
  plus the numeric `scan.risk_score` (one decimal place).
- Per-asset, next to each asset's `host` line (`page.tsx:163-165`), the
  same pattern using `asset.risk_tier`/`asset.risk_score`.

Do not touch the existing findings/misconfigurations render blocks.

## §6 Testing strategy

- `scoring.py`: `score_finding_contribution` — cvss-present case,
  cvss-absent severity-fallback case, confidence-discount applied
  correctly, `FALSE_POSITIVE` → exactly `0.0` regardless of
  severity/confidence, `UNVALIDATED`/`CONFIRMED` both contribute
  identically (no validation-state boost beyond the exclusion rule).
  `score_misconfiguration_contribution` — one case per severity,
  confirms `MISCONFIG_RELATIVE_WEIGHT` is applied. `aggregate_risk` —
  empty list → `0.0`; single contribution → recognizable noisy-OR
  result (not a plain pass-through, not a plain sum); a 100.0
  contribution alongside small ones still saturates near 100; many
  small contributions never exceed 100; order-independence (shuffling
  the input list produces the same result, proving it's a true
  product-based aggregation, not an accumulator bug that depends on
  order). `tier_for_score` — a boundary-value test at each band edge
  (`24.99`→MEDIUM-not-triggered/LOW, `25.0`→MEDIUM, etc.), plus `0.0`→
  `"NONE"`.
- `risk_scorer.py`: a correlator.py-style test with 2+ assets where one
  asset's scoring is deliberately broken (e.g. a malformed relationship
  access) and the other asset's `risk_score`/`risk_tier` are still
  correctly persisted — per-asset isolation, proven, not just asserted.
  A test confirming the scan-level aggregate is computed from the
  assets' own persisted `risk_score` values (not recomputed from raw
  findings), and a test confirming an asset with zero findings/
  misconfigs lands on `risk_score=0.0`/`risk_tier="NONE"`, not `NULL`
  (distinguishing "scored, nothing found" from "never scored" — the
  `NULL`-only-means-"not yet scored" invariant this phase's nullability
  decision depends on).
- `test_scan_orchestration.py` (extend): a full `run_scan_task` run
  reaches `COMPLETED` with `scan.risk_score`/`risk_tier` populated; a
  deliberately-broken risk-scoring path (simulate via a monkeypatched
  `score_assets` that raises) still reaches `COMPLETED`, not `FAILED` —
  the best-effort contract, exercised.
- `test_scans.py` (extend): `GET /scans/{id}` and `GET /scans/{id}/assets`
  both surface the new fields (possibly `null` for a pre-Phase-7/
  not-yet-scored fixture scan).

## §7 Verification plan

Fresh migration against a database with pre-existing `Asset`/`Scan` rows
— confirm every existing row's new columns come back `NULL`, not `0`/
`"NONE"`. A real scan producing at least one `Finding` (any severity),
one `FALSE_POSITIVE`-validated `Finding` (confirm it contributes
nothing), and one `Misconfiguration` — confirm the persisted
`Asset.risk_score`/`risk_tier` and `Scan.risk_score`/`risk_tier` match
hand-computed expected values from `scoring.py`'s own formula. Confirm
`GET /scans/{id}` and `GET /scans/{id}/assets` both surface the new
fields correctly. Confirm the frontend page renders both the scan-level
and asset-level risk badges. Full backend+frontend lint/type/test suites
green.
