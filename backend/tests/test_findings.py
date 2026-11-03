import uuid

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import Finding, FindingValidationState
from app.models.service import Service


def _seed_finding(
    db: Session,
    *,
    validation_state: FindingValidationState = FindingValidationState.UNVALIDATED,
    validation_note: str | None = None,
    validated_at: object = None,
) -> Finding:
    """Seeds a full Project -> Target -> Scan -> Asset -> Service -> Finding
    chain directly via the ORM, mirroring the pattern already used in
    test_scans.py's nested-findings test, rather than inventing a new
    seeding helper. Only this module's two direct ORM-FK fields (asset_id
    via service, service_id via finding) actually need real parent rows for
    the DB's FK constraints to be satisfied.
    """
    from app.models.project import Project
    from app.models.scan import Scan
    from app.models.target import Target, TargetType

    project = Project(name="Finding Validation Project")
    db.add(project)
    db.flush()
    target = Target(
        project_id=project.id,
        value="10.0.0.20",
        target_type=TargetType.IP,
        authorization_confirmed=True,
    )
    db.add(target)
    db.flush()
    scan = Scan(project_id=project.id, target_id=target.id)
    db.add(scan)
    db.flush()
    asset = Asset(project_id=project.id, target_id=target.id, scan_id=scan.id, host="10.0.0.20")
    db.add(asset)
    db.flush()
    service = Service(
        asset_id=asset.id,
        port=80,
        protocol="tcp",
        state="open",
        service_name="http",
        fingerprint_source="nmap-sv",
        evidence={"cpe": ["cpe:/a:apache:http_server:2.4.49"]},
    )
    db.add(service)
    db.flush()
    finding = Finding(
        service_id=service.id,
        cve_id="CVE-2021-41773",
        matched_cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        severity="CRITICAL",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        description="Path traversal and file disclosure in Apache HTTP Server 2.4.49.",
        evidence={"id": "CVE-2021-41773", "sourceIdentifier": "nvd@nist.gov"},
        confidence_score=100.0,
        validation_state=validation_state,
        validation_note=validation_note,
        validated_at=validated_at,
    )
    db.add(finding)
    db.commit()
    return finding


def test_patch_finding_confirmed_with_note_sets_state_note_and_timestamp(
    client: TestClient, db: Session
) -> None:
    finding = _seed_finding(db)

    resp = client.patch(
        f"/api/v1/findings/{finding.id}",
        json={"validation_state": "confirmed", "validation_note": "verified manually"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["validation_state"] == "confirmed"
    assert body["validation_note"] == "verified manually"
    assert body["validated_at"] is not None
    assert body["confidence_score"] == 100.0

    db.expire_all()
    row = db.get(Finding, finding.id)
    assert row is not None
    assert row.validation_state == FindingValidationState.CONFIRMED
    assert row.validation_note == "verified manually"
    assert row.validated_at is not None


def test_patch_finding_false_positive_without_note_leaves_note_null_but_sets_timestamp(
    client: TestClient, db: Session
) -> None:
    finding = _seed_finding(db)

    resp = client.patch(
        f"/api/v1/findings/{finding.id}",
        json={"validation_state": "false_positive"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["validation_state"] == "false_positive"
    assert body["validation_note"] is None
    assert body["validated_at"] is not None

    db.expire_all()
    row = db.get(Finding, finding.id)
    assert row is not None
    assert row.validation_state == FindingValidationState.FALSE_POSITIVE
    assert row.validation_note is None
    assert row.validated_at is not None


def test_patch_finding_invalid_validation_state_rejected_with_422(
    client: TestClient, db: Session
) -> None:
    finding = _seed_finding(db)

    resp = client.patch(
        f"/api/v1/findings/{finding.id}",
        json={"validation_state": "bogus"},
    )

    assert resp.status_code == 422

    # Confirms the invalid payload never reached update_validation at all -
    # the row is untouched.
    db.expire_all()
    row = db.get(Finding, finding.id)
    assert row is not None
    assert row.validation_state == FindingValidationState.UNVALIDATED


def test_patch_nonexistent_finding_returns_404(client: TestClient) -> None:
    resp = client.patch(
        f"/api/v1/findings/{uuid.uuid4()}",
        json={"validation_state": "confirmed"},
    )

    assert resp.status_code == 404


def test_patch_already_confirmed_finding_to_false_positive_replaces_note_not_merges(
    client: TestClient, db: Session
) -> None:
    """The one subtlety most worth a dedicated test (per PLAN_5.md §6): a
    Finding already CONFIRMED with a note, re-PATCHed to FALSE_POSITIVE with
    NO note on this second call, must end up with validation_note == None -
    not the old note silently surviving via an exclude_unset-style merge.
    """
    finding = _seed_finding(db)
    first = client.patch(
        f"/api/v1/findings/{finding.id}",
        json={"validation_state": "confirmed", "validation_note": "note A"},
    )
    assert first.status_code == 200
    assert first.json()["validation_note"] == "note A"

    second = client.patch(
        f"/api/v1/findings/{finding.id}",
        json={"validation_state": "false_positive"},
    )

    assert second.status_code == 200
    body = second.json()
    assert body["validation_state"] == "false_positive"
    assert body["validation_note"] is None

    db.expire_all()
    row = db.get(Finding, finding.id)
    assert row is not None
    assert row.validation_state == FindingValidationState.FALSE_POSITIVE
    assert row.validation_note is None


def test_patch_confirmed_finding_back_to_unvalidated_clears_note_and_timestamp(
    client: TestClient, db: Session
) -> None:
    finding = _seed_finding(db)
    confirm = client.patch(
        f"/api/v1/findings/{finding.id}",
        json={"validation_state": "confirmed", "validation_note": "note A"},
    )
    assert confirm.status_code == 200
    assert confirm.json()["validation_note"] == "note A"
    assert confirm.json()["validated_at"] is not None

    resp = client.patch(
        f"/api/v1/findings/{finding.id}",
        json={"validation_state": "unvalidated"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["validation_state"] == "unvalidated"
    assert body["validation_note"] is None
    assert body["validated_at"] is None

    db.expire_all()
    row = db.get(Finding, finding.id)
    assert row is not None
    assert row.validation_state == FindingValidationState.UNVALIDATED
    assert row.validation_note is None
    assert row.validated_at is None
