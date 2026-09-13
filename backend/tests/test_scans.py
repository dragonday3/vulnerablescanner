import uuid
from typing import Any
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.scan import Scan
from app.models.target import Target
from tests.conftest import FAKE_CELERY_TASK_ID

# `mock_run_scan_task_delay` and `mock_celery_control_revoke` (conftest.py)
# are both autouse, so every `POST /scans` and `/cancel` call in this file
# already avoids a real broker round trip without any of these tests
# needing to request them explicitly - they're only requested by name below
# where a test needs to assert against (or reconfigure) the mock itself.


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
    assert resp.json()["status"] == "queued"


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
    assert resp.json()["status"] == "queued"


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


def test_create_scan_rejects_target_from_a_different_project(client: TestClient) -> None:
    """Cross-tenant authorization boundary: a target_id that exists but
    belongs to a project other than the project_id in the request body must
    be rejected, not silently accepted against the wrong project.
    scan_service.create_scan already enforces `target.project_id !=
    data.project_id` -> NotFoundError, but this had zero test coverage.
    """
    ctx_a = _create_authorized_target(client)
    project_b = client.post("/api/v1/projects", json={"name": "Other Project"}).json()

    resp = client.post(
        "/api/v1/scans",
        json={"project_id": project_b["id"], "target_id": ctx_a["target"]["id"]},
    )

    assert resp.status_code == 404


def test_create_scan_enqueues_task_and_stores_celery_task_id(
    client: TestClient, db: Session, mock_run_scan_task_delay: MagicMock
) -> None:
    """`celery_task_id` is an internal field, not exposed on `ScanRead` (see
    task-7 report for that decision), so it's checked via a direct DB read
    rather than the response body.
    """
    ctx = _create_authorized_target(client)

    resp = client.post(
        "/api/v1/scans",
        json={"project_id": ctx["project"]["id"], "target_id": ctx["target"]["id"]},
    )

    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "queued"

    mock_run_scan_task_delay.assert_called_once_with(body["id"])

    scan_row = db.get(Scan, uuid.UUID(body["id"]))
    assert scan_row is not None
    assert scan_row.celery_task_id == FAKE_CELERY_TASK_ID
    assert scan_row.status.value == "queued"


def test_cancel_queued_scan_revokes_celery_task(
    client: TestClient, mock_celery_control_revoke: MagicMock
) -> None:
    ctx = _create_authorized_target(client)
    scan = _create_scan(client, ctx)

    resp = client.post(f"/api/v1/scans/{scan['id']}/cancel")

    assert resp.status_code == 200
    assert resp.json()["status"] == "cancelled"
    mock_celery_control_revoke.assert_called_once_with(FAKE_CELERY_TASK_ID)


def test_cancel_still_succeeds_when_revoke_raises(
    client: TestClient, mock_celery_control_revoke: MagicMock
) -> None:
    """The DB status change is the authoritative outcome of cancelling a
    scan - a broker error while revoking the Celery task must not prevent
    the cancel API call from succeeding.
    """
    mock_celery_control_revoke.side_effect = RuntimeError("broker down")
    ctx = _create_authorized_target(client)
    scan = _create_scan(client, ctx)

    resp = client.post(f"/api/v1/scans/{scan['id']}/cancel")

    assert resp.status_code == 200
    assert resp.json()["status"] == "cancelled"
