from typing import Any

import pytest
from fastapi.testclient import TestClient


def _create_project(client: TestClient, name: str = "Target Project") -> dict[str, Any]:
    resp = client.post("/api/v1/projects", json={"name": name})
    assert resp.status_code == 201
    return resp.json()


def _create_target(client: TestClient, project_id: str, value: str, target_type: str) -> Any:
    return client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={
            "value": value,
            "target_type": target_type,
            "authorization_confirmed": True,
        },
    )


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


def test_get_target_under_wrong_project_returns_404(client: TestClient) -> None:
    project_a = _create_project(client, "Project A")
    project_b = _create_project(client, "Project B")

    create_resp = client.post(
        f"/api/v1/projects/{project_a['id']}/targets",
        json={
            "value": "10.0.0.4",
            "target_type": "ip",
            "authorization_confirmed": True,
        },
    )
    assert create_resp.status_code == 201
    target = create_resp.json()

    # The target exists, but under project_a — asking for it via project_b's
    # URL must 404, not leak the target across the tenant boundary.
    resp = client.get(f"/api/v1/projects/{project_b['id']}/targets/{target['id']}")

    assert resp.status_code == 404


@pytest.mark.parametrize(
    ("value", "target_type"),
    [
        ("192.168.1.1", "ip"),
        ("::1", "ip"),
        ("2001:db8::1", "ip"),
        ("10.0.0.0/8", "cidr"),
        ("2001:db8::/32", "cidr"),
        ("example.com", "domain"),
        ("sub.example.com", "domain"),
        ("my-host", "hostname"),
        ("host-1.internal", "hostname"),
        # An IP-shaped string is also a syntactically valid hostname - types
        # aren't mutually exclusive in this direction.
        ("192.168.1.1", "hostname"),
    ],
)
def test_create_target_accepts_valid_value_for_type(
    client: TestClient, value: str, target_type: str
) -> None:
    project = _create_project(client)

    resp = _create_target(client, project["id"], value, target_type)

    assert resp.status_code == 201, resp.text
    assert resp.json()["value"] == value


@pytest.mark.parametrize(
    ("value", "target_type"),
    [
        ("not-an-ip", "ip"),
        ("999.999.999.999", "ip"),
        ("10.0.0.1/33", "cidr"),
        ("not-a-network", "cidr"),
        ("-badlabel.com", "domain"),
        ("bad-.com", "domain"),
        ("a" * 64 + ".com", "domain"),  # single label too long (>63 chars)
        # Overall length > 253 even though each individual label (63 chars)
        # is within the per-label limit.
        (".".join(["a" * 63] * 4), "hostname"),
        ("", "hostname"),
    ],
)
def test_create_target_rejects_invalid_value_for_type(
    client: TestClient, value: str, target_type: str
) -> None:
    project = _create_project(client)

    resp = _create_target(client, project["id"], value, target_type)

    assert resp.status_code == 422


@pytest.mark.parametrize(
    ("value", "target_type"),
    [
        # RFC 4007 IPv6 zone IDs: Python's ipaddress module accepts almost
        # any character after "%" (only "%" and "/" excluded), including
        # parens, flags, and Unicode. Scan targets have no legitimate use
        # for a zone ID, so this must be rejected outright for ip and cidr.
        ("fe80::1%eth0", "ip"),
        ("fe80::1%(x)", "ip"),
        ("fe80::1%--help", "ip"),
        ("fe80::1%ééé", "ip"),  # Unicode zone ID (é é é)
        ("fe80::1%" + "a" * 200, "ip"),
        ("fe80::1%eth0/64", "cidr"),
    ],
)
def test_create_target_rejects_ipv6_zone_id(
    client: TestClient, value: str, target_type: str
) -> None:
    project = _create_project(client)

    resp = _create_target(client, project["id"], value, target_type)

    assert resp.status_code == 422, resp.text


@pytest.mark.parametrize("target_type", ["ip", "cidr", "domain", "hostname"])
def test_create_target_rejects_shell_metacharacters_regardless_of_type(
    client: TestClient, target_type: str
) -> None:
    project = _create_project(client)

    resp = _create_target(client, project["id"], "host; rm -rf /", target_type)

    assert resp.status_code == 422


@pytest.mark.parametrize(
    "value",
    [
        "host`whoami`",
        "host$(whoami)",
        "host|cat",
        "host&&ls",
        "host<script>",
        "host'quote",
        'host"quote',
        "host\nnewline",
        "host\x00null",
    ],
)
def test_create_target_rejects_various_shell_metacharacters(client: TestClient, value: str) -> None:
    project = _create_project(client)

    resp = _create_target(client, project["id"], value, "hostname")

    assert resp.status_code == 422


@pytest.mark.parametrize(
    ("value", "target_type"),
    [
        # nmap host-range/list syntax: digits/dots/hyphens only, matches the
        # hostname-label regex character class but is NOT a single
        # parseable IP address. Left unblocked, this reaches
        # NmapPortScanner's argv untouched (target_type isn't CIDR, so the
        # CIDR-only range check in app.workers.tasks never sees it) and
        # nmap's own target-syntax parser expands it into multiple hosts -
        # the exact bug this test guards against (Finding 1).
        ("172.18.0.2-4", "hostname"),
        ("1-254", "hostname"),
        ("10.0.0.1-10.0.0.5", "hostname"),
        ("172.18.0.2-4", "domain"),
        ("1-254", "domain"),
        ("10.0.0.1-10.0.0.5", "domain"),
    ],
)
def test_create_target_rejects_nmap_host_range_syntax(
    client: TestClient, value: str, target_type: str
) -> None:
    project = _create_project(client)

    resp = _create_target(client, project["id"], value, target_type)

    assert resp.status_code == 422, resp.text
