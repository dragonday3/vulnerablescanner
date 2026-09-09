from fastapi.testclient import TestClient


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
