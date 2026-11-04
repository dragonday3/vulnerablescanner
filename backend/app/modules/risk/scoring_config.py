# Tunable constants for VRPS risk scoring (Phase 7). Named, documented, and
# hardcoded for now -- no DB-backed or admin-editable override exists yet
# (PLAN_7.md architecture decision #2). First-pass judgment calls, not tuned
# against real-world scan data.

# CVSS is 0-10; every contribution in this module is normalized to the same
# 0-100 scale as risk_score/confidence_score. Misconfiguration has no CVSS
# equivalent, so its contribution is a severity-table weight already on that
# 0-100 scale.
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
