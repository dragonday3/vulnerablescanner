"""Pure report-assembly function (Phase 8, PLAN_8.md §2).

No DB session, no network, no Redis -- reads only already-loaded ORM
objects (Scan -> target, Asset -> services -> findings/misconfigurations)
and returns a plain nested dict. Every branch produces a concrete value;
nothing here raises on a well-typed input.
"""

from app.models.asset import Asset
from app.models.finding import FindingValidationState
from app.models.scan import Scan

_SEVERITY_KEYS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")


def _validation_state_key(state: FindingValidationState | None) -> str:
    # The DB column always carries a value (server default UNVALIDATED), but
    # an in-memory Finding that was never flushed has validation_state=None.
    # Treat that as UNVALIDATED rather than raising AttributeError.
    if state is None:
        return FindingValidationState.UNVALIDATED.value
    return state.value


def build_report_summary(scan: Scan, assets: list[Asset]) -> dict:
    """Assemble the full report document for `scan` from its `assets`
    (each already carrying its own services -> findings/misconfigurations
    via the existing ORM relationships, exactly as risk_scorer.py already
    traverses them). Pure: no DB write, no network. Deliberately excludes
    every Service/Finding/Misconfiguration's raw `evidence` JSONB -- a
    report is a readable summary, not a second copy of raw evidence
    (still reachable via GET /scans/{id}/assets for anyone who wants it).
    """
    findings_by_severity = dict.fromkeys(_SEVERITY_KEYS, 0)
    findings_by_validation_state = {"unvalidated": 0, "confirmed": 0, "false_positive": 0}
    misconfigs_by_severity = dict.fromkeys(_SEVERITY_KEYS, 0)
    findings_total = 0
    misconfigs_total = 0
    asset_entries: list[dict] = []

    for asset in assets:
        service_entries: list[dict] = []
        for service in asset.services:
            finding_entries: list[dict] = []
            for finding in service.findings:
                findings_total += 1
                findings_by_severity[finding.severity] = (
                    findings_by_severity.get(finding.severity, 0) + 1
                )
                state_key = _validation_state_key(finding.validation_state)
                findings_by_validation_state[state_key] = (
                    findings_by_validation_state.get(state_key, 0) + 1
                )
                finding_entries.append(
                    {
                        "cve_id": finding.cve_id,
                        "severity": finding.severity,
                        "cvss_score": finding.cvss_score,
                        "confidence_score": finding.confidence_score,
                        "validation_state": state_key,
                    }
                )

            misconfig_entries: list[dict] = []
            for misconfig in service.misconfigurations:
                misconfigs_total += 1
                misconfigs_by_severity[misconfig.severity] = (
                    misconfigs_by_severity.get(misconfig.severity, 0) + 1
                )
                misconfig_entries.append(
                    {
                        "check_id": misconfig.check_id,
                        "title": misconfig.title,
                        "severity": misconfig.severity,
                        "description": misconfig.description,
                    }
                )

            service_entries.append(
                {
                    "port": service.port,
                    "protocol": service.protocol,
                    "service_name": service.service_name,
                    "product": service.product,
                    "version": service.version,
                    "findings": finding_entries,
                    "misconfigurations": misconfig_entries,
                }
            )

        asset_entries.append(
            {
                "host": asset.host,
                "risk_score": asset.risk_score,
                "risk_tier": asset.risk_tier,
                "services": service_entries,
            }
        )

    return {
        # TargetType is a `str, enum.Enum` mixin: `.value` yields the plain
        # "ip"/"domain"/"hostname"/"cidr" string the report needs. Plain
        # str() on it would render "TargetType.IP" on Python 3.12.
        "target": {"value": scan.target.value, "target_type": scan.target.target_type.value},
        "risk": {"score": scan.risk_score, "tier": scan.risk_tier},
        "findings_summary": {
            "total": findings_total,
            "by_severity": findings_by_severity,
            "by_validation_state": findings_by_validation_state,
        },
        "misconfigurations_summary": {
            "total": misconfigs_total,
            "by_severity": misconfigs_by_severity,
        },
        "assets": asset_entries,
    }
