import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.scan import Scan
from app.models.target import Target
from app.services import project_service


def test_create_and_list_project(client: TestClient) -> None:
    create_resp = client.post(
        "/api/v1/projects", json={"name": "Acme Corp", "description": "A test project"}
    )
    assert create_resp.status_code == 201
    created = create_resp.json()
    assert created["name"] == "Acme Corp"
    assert created["description"] == "A test project"

    list_resp = client.get("/api/v1/projects")
    assert list_resp.status_code == 200
    projects = list_resp.json()
    assert any(p["id"] == created["id"] for p in projects)


def test_get_project_by_id(client: TestClient) -> None:
    created = client.post("/api/v1/projects", json={"name": "Get Me"}).json()

    resp = client.get(f"/api/v1/projects/{created['id']}")

    assert resp.status_code == 200
    assert resp.json()["id"] == created["id"]


def test_patch_project(client: TestClient) -> None:
    created = client.post("/api/v1/projects", json={"name": "Old Name"}).json()

    resp = client.patch(f"/api/v1/projects/{created['id']}", json={"name": "New Name"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "New Name"
    assert body["id"] == created["id"]


def test_delete_project_then_get_is_404(client: TestClient) -> None:
    created = client.post("/api/v1/projects", json={"name": "Delete Me"}).json()

    delete_resp = client.delete(f"/api/v1/projects/{created['id']}")
    assert delete_resp.status_code == 204

    get_resp = client.get(f"/api/v1/projects/{created['id']}")
    assert get_resp.status_code == 404


def test_delete_project_cascades_to_targets_and_scans(client: TestClient, db: Session) -> None:
    """Deleting a project must actually remove its child target/scan rows
    from the database (ON DELETE CASCADE at the DB level, paired with
    passive_deletes=True on Project.targets/Project.scans) - not merely make
    the project itself 404 afterward while orphaning children.
    """
    project = client.post("/api/v1/projects", json={"name": "Cascade Me"}).json()
    target = client.post(
        f"/api/v1/projects/{project['id']}/targets",
        json={
            "value": "10.0.0.20",
            "target_type": "ip",
            "authorization_confirmed": True,
        },
    ).json()
    scan = client.post(
        "/api/v1/scans",
        json={"project_id": project["id"], "target_id": target["id"]},
    ).json()

    delete_resp = client.delete(f"/api/v1/projects/{project['id']}")
    assert delete_resp.status_code == 204

    # Query the DB directly (not the API) to confirm the child rows
    # themselves are gone, not just unreachable via the now-404'd project.
    db.expire_all()
    assert db.get(Target, uuid.UUID(target["id"])) is None
    assert db.get(Scan, uuid.UUID(scan["id"])) is None


def test_unhandled_db_error_returns_uniform_500_envelope(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A DB-layer error that escapes the service layer (e.g. a constraint
    violation the Pydantic schema didn't catch) must be caught by the
    catch-all SQLAlchemyError handler and returned in the same
    {"detail", "code"} envelope shape as every other domain exception -
    not FastAPI's bare default 500 body, and not a leaked raw DB error.
    """

    def raise_integrity_error(*_args: object, **_kwargs: object) -> None:
        raise IntegrityError("INSERT INTO projects ...", {}, Exception("simulated DB failure"))

    monkeypatch.setattr(project_service, "create_project", raise_integrity_error)

    resp = client.post("/api/v1/projects", json={"name": "Will Fail"})

    assert resp.status_code == 500
    body = resp.json()
    assert body == {"detail": "Internal server error", "code": "internal_error"}
    assert "simulated DB failure" not in resp.text
