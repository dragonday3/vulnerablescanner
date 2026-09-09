import uuid
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.target import Target


def _create_authorized_target(client: TestClient) -> dict[str, Any]:
    project = client.post("/api/v1/projects", json={"name": "Scan Project"}).json()
    target = client.post(
        f"/api/v1/projects/{project['id']}/targets",
        json={
            "value": "10.0.0.10",
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


def test_create_scan_against_authorized_target_succeeds(client: TestClient) -> None:
    ctx = _create_authorized_target(client)

    resp = client.post(
        "/api/v1/scans",
        json={"project_id": ctx["project"]["id"], "target_id": ctx["target"]["id"]},
    )

    assert resp.status_code == 201
    assert resp.json()["status"] == "created"


def test_create_scan_rejected_for_target_with_authorization_revoked(
    client: TestClient, db: Session
) -> None:
    ctx = _create_authorized_target(client)

    # Bypass the API to flip authorization directly via the DB session,
    # simulating a target record whose authorization was revoked after
    # creation. TargetCreate's Pydantic validator can't catch this - it
    # only runs at target-creation time - so this exercises the
    # service-layer defense-in-depth check in scan_service.create_scan.
    target_row = db.get(Target, uuid.UUID(ctx["target"]["id"]))
    assert target_row is not None
    target_row.authorization_confirmed = False
    db.commit()

    resp = client.post(
        "/api/v1/scans",
        json={"project_id": ctx["project"]["id"], "target_id": ctx["target"]["id"]},
    )

    assert resp.status_code == 400


def test_scan_status_endpoint_reflects_status(client: TestClient) -> None:
    ctx = _create_authorized_target(client)
    scan = _create_scan(client, ctx)

    resp = client.get(f"/api/v1/scans/{scan['id']}/status")

    assert resp.status_code == 200
    assert resp.json()["status"] == "created"


def test_cancel_created_scan_transitions_to_cancelled(client: TestClient) -> None:
    ctx = _create_authorized_target(client)
    scan = _create_scan(client, ctx)

    resp = client.post(f"/api/v1/scans/{scan['id']}/cancel")

    assert resp.status_code == 200
    assert resp.json()["status"] == "cancelled"


def test_cancel_already_cancelled_scan_returns_409(client: TestClient) -> None:
    ctx = _create_authorized_target(client)
    scan = _create_scan(client, ctx)
    first_cancel = client.post(f"/api/v1/scans/{scan['id']}/cancel")
    assert first_cancel.status_code == 200

    resp = client.post(f"/api/v1/scans/{scan['id']}/cancel")

    assert resp.status_code == 409
