"""Unit tests for the pure report-assembly function (Phase 8, PLAN_8.md §6).

Zero DB/network/Redis dependency inside the function under test: Scan,
Target, Asset, Service, Finding and Misconfiguration instances are built
directly in memory (no session, never added/flushed). Relationships are
wired by assignment, which SQLAlchemy supports without a session.
"""

from __future__ import annotations

from app.models.asset import Asset
from app.models.finding import Finding, FindingValidationState
from app.models.misconfiguration import Misconfiguration
from app.models.scan import Scan
from app.models.service import Service
from app.models.target import Target, TargetType
from app.modules.reporting.report_builder import build_report_summary


def _finding(
    *,
    cve_id: str = "CVE-2021-41773",
    severity: str = "HIGH",
    cvss_score: float | None = 7.5,
    confidence_score: float = 100.0,
    validation_state: FindingValidationState = FindingValidationState.UNVALIDATED,
) -> Finding:
    return Finding(
        cve_id=cve_id,
        matched_cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        severity=severity,
        cvss_score=cvss_score,
        evidence={"raw": "must-not-appear-in-report"},
        confidence_score=confidence_score,
        validation_state=validation_state,
    )


def _misconfig(check_id: str, severity: str) -> Misconfiguration:
    return Misconfiguration(
        check_id=check_id,
        title=f"Title for {check_id}",
        severity=severity,
        description=f"Description for {check_id}",
        evidence={"raw": "must-not-appear-in-report"},
    )


def _service(
    port: int,
    *,
    service_name: str | None = "http",
    findings: list[Finding] | None = None,
    misconfigurations: list[Misconfiguration] | None = None,
) -> Service:
    return Service(
        port=port,
        protocol="tcp",
        service_name=service_name,
        product="nginx",
        version="1.25",
        findings=findings or [],
        misconfigurations=misconfigurations or [],
        evidence={"raw": "must-not-appear-in-report"},
    )


def _asset(
    host: str,
    services: list[Service],
    *,
    risk_score: float | None = 42.0,
    risk_tier: str | None = "MEDIUM",
) -> Asset:
    return Asset(host=host, services=services, risk_score=risk_score, risk_tier=risk_tier)


def _scan(
    *,
    value: str = "10.0.0.5",
    target_type: TargetType = TargetType.IP,
    risk_score: float | None = 42.0,
    risk_tier: str | None = "MEDIUM",
) -> Scan:
    scan = Scan(risk_score=risk_score, risk_tier=risk_tier)
    scan.target = Target(value=value, target_type=target_type)
    return scan


# --- top-level shape -------------------------------------------------------


def test_top_level_keys_and_target_serialization() -> None:
    scan = _scan(value="example.com", target_type=TargetType.DOMAIN)
    report = build_report_summary(scan, [])

    assert set(report.keys()) == {
        "target",
        "risk",
        "findings_summary",
        "misconfigurations_summary",
        "assets",
    }
    # Plain lowercase strings, not the enum repr ("TargetType.DOMAIN").
    assert report["target"] == {"value": "example.com", "target_type": "domain"}
    assert report["risk"] == {"score": 42.0, "tier": "MEDIUM"}


def test_risk_none_passes_through_as_unscored() -> None:
    scan = _scan(risk_score=None, risk_tier=None)
    report = build_report_summary(scan, [])
    assert report["risk"] == {"score": None, "tier": None}


# --- empty inputs ----------------------------------------------------------


def test_no_assets_produces_all_zero_counts_and_empty_list() -> None:
    report = build_report_summary(_scan(), [])

    assert report["assets"] == []
    assert report["findings_summary"] == {
        "total": 0,
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0},
        "by_validation_state": {"unvalidated": 0, "confirmed": 0, "false_positive": 0},
    }
    assert report["misconfigurations_summary"] == {
        "total": 0,
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0},
    }


def test_asset_with_no_services_is_present_with_empty_services_list() -> None:
    asset = _asset("10.0.0.5", services=[])
    report = build_report_summary(_scan(), [asset])

    assert len(report["assets"]) == 1
    entry = report["assets"][0]
    assert entry == {
        "host": "10.0.0.5",
        "risk_score": 42.0,
        "risk_tier": "MEDIUM",
        "services": [],
    }
    assert report["findings_summary"]["total"] == 0
    assert report["misconfigurations_summary"]["total"] == 0


def test_asset_with_zero_findings_and_misconfigs_has_empty_nested_lists() -> None:
    service = _service(443)
    report = build_report_summary(_scan(), [_asset("10.0.0.5", [service])])

    (asset_entry,) = report["assets"]
    (service_entry,) = asset_entry["services"]
    assert service_entry["findings"] == []
    assert service_entry["misconfigurations"] == []
    assert report["findings_summary"]["total"] == 0
    assert report["misconfigurations_summary"]["total"] == 0


# --- findings counts -------------------------------------------------------


def test_findings_by_severity_counts() -> None:
    service = _service(
        80,
        findings=[
            _finding(cve_id="CVE-1", severity="CRITICAL", cvss_score=9.8),
            _finding(cve_id="CVE-2", severity="HIGH", cvss_score=7.5),
            _finding(cve_id="CVE-3", severity="HIGH", cvss_score=8.1),
            _finding(cve_id="CVE-4", severity="MEDIUM", cvss_score=5.0),
            _finding(cve_id="CVE-5", severity="LOW", cvss_score=2.0),
            _finding(cve_id="CVE-6", severity="NONE", cvss_score=None),
        ],
    )
    report = build_report_summary(_scan(), [_asset("10.0.0.5", [service])])

    assert report["findings_summary"]["total"] == 6
    assert report["findings_summary"]["by_severity"] == {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 1,
        "LOW": 1,
        "NONE": 1,
    }


def test_findings_by_validation_state_counts_use_lowercase_keys() -> None:
    service = _service(
        80,
        findings=[
            _finding(cve_id="CVE-1", validation_state=FindingValidationState.UNVALIDATED),
            _finding(cve_id="CVE-2", validation_state=FindingValidationState.UNVALIDATED),
            _finding(cve_id="CVE-3", validation_state=FindingValidationState.CONFIRMED),
            _finding(cve_id="CVE-4", validation_state=FindingValidationState.FALSE_POSITIVE),
        ],
    )
    report = build_report_summary(_scan(), [_asset("10.0.0.5", [service])])

    assert report["findings_summary"]["by_validation_state"] == {
        "unvalidated": 2,
        "confirmed": 1,
        "false_positive": 1,
    }


def test_false_positive_finding_stays_in_detail_list_but_is_counted() -> None:
    fp = _finding(
        cve_id="CVE-FP",
        severity="HIGH",
        validation_state=FindingValidationState.FALSE_POSITIVE,
    )
    kept = _finding(cve_id="CVE-OK", severity="LOW")
    service = _service(80, findings=[fp, kept])
    report = build_report_summary(_scan(), [_asset("10.0.0.5", [service])])

    detail_cves = [f["cve_id"] for f in report["assets"][0]["services"][0]["findings"]]
    assert "CVE-FP" in detail_cves
    assert "CVE-OK" in detail_cves

    fp_entry = next(
        f for f in report["assets"][0]["services"][0]["findings"] if f["cve_id"] == "CVE-FP"
    )
    assert fp_entry["validation_state"] == "false_positive"

    # Counted in both totals, including the severity bucket.
    assert report["findings_summary"]["total"] == 2
    assert report["findings_summary"]["by_validation_state"]["false_positive"] == 1
    assert report["findings_summary"]["by_severity"]["HIGH"] == 1


def test_finding_detail_entry_shape_excludes_raw_evidence() -> None:
    service = _service(80, findings=[_finding(cve_id="CVE-1", cvss_score=7.5)])
    report = build_report_summary(_scan(), [_asset("10.0.0.5", [service])])

    (entry,) = report["assets"][0]["services"][0]["findings"]
    assert entry == {
        "cve_id": "CVE-1",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "confidence_score": 100.0,
        "validation_state": "unvalidated",
    }
    assert "evidence" not in entry


def test_in_memory_finding_with_unset_validation_state_counts_as_unvalidated() -> None:
    # A never-flushed Finding has validation_state=None (the column default
    # only applies on INSERT). Must not raise; treated as UNVALIDATED.
    finding = Finding(
        cve_id="CVE-NOSTATE",
        matched_cpe="cpe:2.3:a:x:y:1:*:*:*:*:*:*:*",
        severity="LOW",
        cvss_score=None,
        evidence={},
        confidence_score=50.0,
    )
    service = _service(80, findings=[finding])
    report = build_report_summary(_scan(), [_asset("10.0.0.5", [service])])

    assert report["findings_summary"]["by_validation_state"]["unvalidated"] == 1
    assert report["assets"][0]["services"][0]["findings"][0]["validation_state"] == "unvalidated"


# --- misconfiguration counts -----------------------------------------------


def test_one_misconfiguration_of_each_severity_is_counted() -> None:
    service = _service(
        443,
        misconfigurations=[
            _misconfig("c", "CRITICAL"),
            _misconfig("h", "HIGH"),
            _misconfig("m", "MEDIUM"),
            _misconfig("l", "LOW"),
        ],
    )
    report = build_report_summary(_scan(), [_asset("10.0.0.5", [service])])

    assert report["misconfigurations_summary"]["total"] == 4
    assert report["misconfigurations_summary"]["by_severity"] == {
        "CRITICAL": 1,
        "HIGH": 1,
        "MEDIUM": 1,
        "LOW": 1,
        "NONE": 0,
    }


def test_misconfiguration_detail_entry_shape_excludes_raw_evidence() -> None:
    service = _service(443, misconfigurations=[_misconfig("missing-hsts", "MEDIUM")])
    report = build_report_summary(_scan(), [_asset("10.0.0.5", [service])])

    (entry,) = report["assets"][0]["services"][0]["misconfigurations"]
    assert entry == {
        "check_id": "missing-hsts",
        "title": "Title for missing-hsts",
        "severity": "MEDIUM",
        "description": "Description for missing-hsts",
    }
    assert "evidence" not in entry


# --- nesting ---------------------------------------------------------------


def test_multi_asset_multi_service_nesting_and_aggregate_totals() -> None:
    asset_a = _asset(
        "10.0.0.5",
        [
            _service(
                22,
                service_name="ssh",
                findings=[_finding(cve_id="CVE-A1", severity="HIGH")],
            ),
            _service(
                443,
                misconfigurations=[_misconfig("missing-hsts", "MEDIUM")],
                findings=[_finding(cve_id="CVE-A2", severity="CRITICAL", cvss_score=9.8)],
            ),
        ],
        risk_score=80.0,
        risk_tier="HIGH",
    )
    asset_b = _asset(
        "10.0.0.6",
        [
            _service(
                6379,
                service_name="redis",
                misconfigurations=[
                    _misconfig("exposed-sensitive-service", "CRITICAL"),
                    _misconfig("weak-tls-protocol", "HIGH"),
                ],
            ),
        ],
        risk_score=None,
        risk_tier=None,
    )
    report = build_report_summary(_scan(), [asset_a, asset_b])

    # Two assets, in the order given, each with its own services.
    assert [a["host"] for a in report["assets"]] == ["10.0.0.5", "10.0.0.6"]
    assert [s["port"] for s in report["assets"][0]["services"]] == [22, 443]
    assert [s["port"] for s in report["assets"][1]["services"]] == [6379]

    # Per-asset risk passes through, including an unscored asset as None.
    assert report["assets"][0]["risk_score"] == 80.0
    assert report["assets"][0]["risk_tier"] == "HIGH"
    assert report["assets"][1]["risk_score"] is None
    assert report["assets"][1]["risk_tier"] is None

    # Findings nested under the right service.
    assert [f["cve_id"] for f in report["assets"][0]["services"][0]["findings"]] == ["CVE-A1"]
    assert report["assets"][0]["services"][0]["findings"][0]["severity"] == "HIGH"
    assert report["assets"][0]["services"][1]["findings"][0]["cve_id"] == "CVE-A2"
    assert report["assets"][1]["services"][0]["findings"] == []

    # Totals aggregate across every asset and service.
    assert report["findings_summary"]["total"] == 2
    assert report["findings_summary"]["by_severity"]["HIGH"] == 1
    assert report["findings_summary"]["by_severity"]["CRITICAL"] == 1
    assert report["misconfigurations_summary"]["total"] == 3
    assert report["misconfigurations_summary"]["by_severity"] == {
        "CRITICAL": 1,
        "HIGH": 1,
        "MEDIUM": 1,
        "LOW": 0,
        "NONE": 0,
    }


def test_service_entry_carries_identifying_fields() -> None:
    service = _service(8080, service_name="http-proxy")
    report = build_report_summary(_scan(), [_asset("10.0.0.5", [service])])

    assert report["assets"][0]["services"][0] == {
        "port": 8080,
        "protocol": "tcp",
        "service_name": "http-proxy",
        "product": "nginx",
        "version": "1.25",
        "findings": [],
        "misconfigurations": [],
    }
