"""API-level tests for `GET /scans/{scan_id}/report` (Phase 8 Task 4,
PLAN_8.md section 4/6's fourth bullet).

Mirrors `test_scans.py`'s own style: `_create_authorized_target`/
`_create_scan` build a real scan through the API, and a `Report` row is
seeded directly via the `db` fixture (same DB-bypass pattern already used
throughout `test_scans.py` for state a test doesn't want to drive a real
Celery worker to reach) rather than running the actual worker task --
`generate_report`/`run_scan_task`'s own orchestration is covered
separately by `test_report_generator.py`/`test_scan_orchestration.py`.
"""

import uuid
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.report import Report
from app.models.scan import Scan, ScanStatus


def _create_authorized_target(client: TestClient) -> dict[str, Any]:
    project = client.post("/api/v1/projects", json={"name": "Report Test Project"}).json()
    target = client.post(
        f"/api/v1/projects/{project['id']}/targets",
        json={
            "value": "10.0.0.20",
            "target_type": "ip",
            "authorization_confirmed": True,
        },
    ).json()
    return {"project": project, "target": target}


def _create_scan(client: TestClient, ctx: dict[str, Any]) -> dict[str, Any]:
    resp = client.post(
        "/api/v1/scans",
        json={"project_id": ctx["project"]["id"], "target_id": ctx["target"]["id"]},
    )
    assert resp.status_code == 201
    return resp.json()


def test_get_scan_report_returns_404_for_nonexistent_scan(client: TestClient) -> None:
    resp = client.get(f"/api/v1/scans/{uuid.uuid4()}/report")

    assert resp.status_code == 404


def test_get_scan_report_returns_404_before_report_generation(client: TestClient) -> None:
    """A freshly-created scan (status `queued`, never actually run) has no
    `Report` row yet -- the two-step `get_report` contract (scan exists, but
    no Report for it) must surface as 404, distinct from the scan-doesn't-
    exist-at-all 404 above.
    """
    ctx = _create_authorized_target(client)
    scan = _create_scan(client, ctx)

    resp = client.get(f"/api/v1/scans/{scan['id']}/report")

    assert resp.status_code == 404


def test_get_scan_report_returns_200_with_expected_summary_shape(
    client: TestClient, db: Session
) -> None:
    """Once a `Report` row exists for a scan (here seeded directly, bypassing
    the worker -- same DB-bypass convention `test_scans.py` already uses for
    post-pipeline state), the endpoint returns it with the full `ReportRead`
    shape: `id`/`scan_id`/`summary`/`generated_at`, and `summary` passed
    through verbatim as the JSONB document `build_report_summary` produces.
    """
    ctx = _create_authorized_target(client)
    scan = _create_scan(client, ctx)

    scan_row = db.get(Scan, uuid.UUID(scan["id"]))
    assert scan_row is not None
    scan_row.status = ScanStatus.COMPLETED
    summary = {
        "target": {"value": "10.0.0.20", "target_type": "ip"},
        "risk": {"score": 42.0, "tier": "MEDIUM"},
        "findings_summary": {
            "total": 1,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "NONE": 0},
            "by_validation_state": {"unvalidated": 1, "confirmed": 0, "false_positive": 0},
        },
        "misconfigurations_summary": {
            "total": 0,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0},
        },
        "assets": [
            {
                "host": "10.0.0.20",
                "risk_score": 42.0,
                "risk_tier": "MEDIUM",
                "services": [
                    {
                        "port": 443,
                        "protocol": "tcp",
                        "service_name": "https",
                        "product": "nginx",
                        "version": "1.24.0",
                        "findings": [
                            {
                                "cve_id": "CVE-2024-0001",
                                "severity": "MEDIUM",
                                "cvss_score": 5.3,
                                "confidence_score": 100.0,
                                "validation_state": "unvalidated",
                            }
                        ],
                        "misconfigurations": [],
                    }
                ],
            }
        ],
    }
    report = Report(scan_id=scan_row.id, summary=summary)
    db.add(report)
    db.commit()
    db.refresh(report)

    resp = client.get(f"/api/v1/scans/{scan['id']}/report")

    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == str(report.id)
    assert body["scan_id"] == scan["id"]
    assert body["summary"] == summary
    assert "generated_at" in body
