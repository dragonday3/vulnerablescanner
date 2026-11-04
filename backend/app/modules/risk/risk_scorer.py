"""Risk-scoring orchestration glue (Phase 7, PLAN_7.md section 3).

The one place per-Asset and per-Scan VRPS aggregation meet: turns a scan's
already-persisted `Finding`/`Misconfiguration` rows (reached via each
Asset's `services`) into `Asset.risk_score`/`risk_tier` and
`Scan.risk_score`/`risk_tier`. Mirrors `vulnerability/correlator.py`'s and
`misconfiguration/analyzer.py`'s per-unit isolation discipline exactly:
each asset gets its own try/except and its own commit, so one asset's
scoring failure never aborts scoring of the rest.

UNLIKE those two modules, this function's signature DOES take `scan` --
not just `assets`. The inherited discipline from Phase 4/6 is "never
touch scan.status", not "never touch scan at all":
`scan.risk_score`/`scan.risk_tier` are this function's own columns to
write, and writing them is the entire point of its second half. A
reviewer should treat any write to `scan.status` inside this module as a
Critical finding; the `scan.risk_score`/`scan.risk_tier` writes below are
not that.

No network, no Redis -- purely a DB-read + pure-function + DB-write
stage. Never raises past this function.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.scan import Scan
from app.modules.risk.scoring import (
    aggregate_risk,
    score_finding_contribution,
    score_misconfiguration_contribution,
    tier_for_score,
)
from app.modules.vulnerability.finding_dedup import dedupe_findings_by_cve

logger = logging.getLogger(__name__)


def score_assets(db: Session, scan: Scan, assets: list[Asset]) -> None:
    """Best-effort per-Asset scoring, then one per-Scan aggregate.

    Step 1: for each `asset`, gather every `score_finding_contribution`
    across `service.findings` and every `score_misconfiguration_contribution`
    across `service.misconfigurations`, for every `service` in
    `asset.services`, into one flat contributions list; aggregate and
    persist onto `asset.risk_score`/`risk_tier`, committing once per asset.
    On failure: roll back, log, and move on to the next asset -- that
    asset's score stays whatever it was before this call (`None` if it was
    never scored), never silently coerced to 0.0/"NONE".

    Step 2 (separate try/except, after the loop): aggregate the
    `risk_score` of every asset that was *successfully* scored in step 1
    (a failed asset contributes nothing to the scan-level aggregate -- the
    same "a failed unit looks like a clean one" ambiguity class CLAUDE.md
    already documents for correlation/analysis failures) onto
    `scan.risk_score`/`risk_tier`, committed once. If `assets` was
    non-empty but every single one failed in step 1 -- leaving nothing
    successfully scored to aggregate -- `scan.risk_score`/`risk_tier` are
    left untouched (not coerced to 0.0/"NONE", which would be
    indistinguishable from a genuinely clean scan) and a warning is
    logged instead.
    """
    scored_asset_scores: list[float] = []

    for asset in assets:
        try:
            contributions: list[float] = []
            for service in asset.services:
                # Dedup is scoped to this one service's own findings -- the
                # same CVE matched twice here via two CPEs is a correlation
                # artifact (one vulnerability, double-counted); the same CVE
                # on a different service is a second, real vulnerable
                # surface and must still contribute its own term. See
                # finding_dedup.py's docstring.
                for finding in dedupe_findings_by_cve(service.findings):
                    contributions.append(score_finding_contribution(finding))
                for misconfig in service.misconfigurations:
                    contributions.append(score_misconfiguration_contribution(misconfig))

            asset.risk_score = aggregate_risk(contributions)
            asset.risk_tier = tier_for_score(asset.risk_score)
            db.commit()
            scored_asset_scores.append(asset.risk_score)
        except Exception:
            # Per-asset isolation (mirrors correlator.py's per-CPE /
            # analyzer.py's per-service isolation): roll back only this
            # asset's uncommitted work and move on to the next asset -- do
            # not let one asset's failure abort scoring of the rest.
            db.rollback()
            logger.exception(
                "score_assets: risk scoring failed for asset %s, leaving its risk_score "
                "unset this run",
                asset.id,
            )
            continue

    if assets and not scored_asset_scores:
        # Every asset's scoring failed in step 1 above -- there is nothing
        # legitimate to aggregate. Committing aggregate_risk([]) here would
        # produce 0.0/"NONE", indistinguishable from "scored, genuinely
        # nothing found" (the exact ambiguity CLAUDE.md's Global Constraint
        # 6 forbids). Leave scan.risk_score/risk_tier exactly as they were
        # (NULL if never scored) and let the caller/next run retry.
        logger.warning(
            "score_assets: every asset failed scoring for scan %s, leaving scan-level "
            "risk_score/risk_tier untouched this run",
            scan.id,
        )
        return

    try:
        scan.risk_score = aggregate_risk(scored_asset_scores)
        scan.risk_tier = tier_for_score(scan.risk_score)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("score_assets: scan-level risk aggregation failed for scan %s", scan.id)
