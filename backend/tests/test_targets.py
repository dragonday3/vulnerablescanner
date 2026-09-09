from typing import Any

from fastapi.testclient import TestClient


def _create_project(client: TestClient, name: str = "Target Project") -> dict[str, Any]:
    resp = client.post("/api/v1/projects", json={"name": name})
    assert resp.status_code == 201
    return resp.json()


def test_create_target_rejects_unconfirmed_authorization(client: TestClient) -> None:
    project = _create_project(client)

    resp = client.post(
        f"/api/v1/projects/{project['id']}/targets",
        json={
            "value": "10.0.0.1",
            "target_type": "ip",
            "authorization_confirmed": False,
        },
    )

    assert resp.status_code == 422


def test_create_target_accepts_confirmed_authorization(client: TestClient) -> None:
    project = _create_project(client)

    resp = client.post(
        f"/api/v1/projects/{project['id']}/targets",
        json={
            "value": "10.0.0.2",
            "target_type": "ip",
            "authorization_confirmed": True,
        },
    )

    assert resp.status_code == 201
    body = resp.json()
    assert body["authorization_confirmed"] is True
    assert body["project_id"] == project["id"]


def test_targets_are_scoped_per_project(client: TestClient) -> None:
    project_a = _create_project(client, "Project A")
    project_b = _create_project(client, "Project B")

    create_resp = client.post(
        f"/api/v1/projects/{project_a['id']}/targets",
        json={
            "value": "10.0.0.3",
            "target_type": "ip",
            "authorization_confirmed": True,
        },
    )
    assert create_resp.status_code == 201

    list_a = client.get(f"/api/v1/projects/{project_a['id']}/targets")
    list_b = client.get(f"/api/v1/projects/{project_b['id']}/targets")

    assert list_a.status_code == 200
    assert list_b.status_code == 200
    assert len(list_a.json()) == 1
    assert list_b.json() == []
