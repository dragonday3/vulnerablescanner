"""Unit tests for `check_exposed_service` (Task 2, PLAN_6.md section 2).

Pure-function module with zero DB/network/Redis dependency -- same
`types.SimpleNamespace` stand-in pattern as `test_confidence.py`/
`test_header_checks.py`, since `check_exposed_service` only reads
`.port`.
"""

from __future__ import annotations

import types

import pytest

from app.modules.misconfiguration.exposed_service_checks import (
    SENSITIVE_PORTS,
    check_exposed_service,
)


def _service(port: int) -> types.SimpleNamespace:
    return types.SimpleNamespace(port=port)


@pytest.mark.parametrize(
    ("port", "label", "severity"), [(p, lbl, sev) for p, (lbl, sev) in SENSITIVE_PORTS.items()]
)
def test_sensitive_port_triggers_exposed_sensitive_service(
    port: int, label: str, severity: str
) -> None:
    candidate = check_exposed_service(_service(port))
    assert candidate is not None
    assert candidate.check_id == "exposed-sensitive-service"
    assert candidate.severity == severity
    assert candidate.evidence["port"] == port
    assert candidate.evidence["label"] == label
    assert candidate.evidence["severity"] == severity
    assert label in candidate.title


@pytest.mark.parametrize("port", [22, 80, 443, 8080, 1, 65535])
def test_non_sensitive_port_returns_none(port: int) -> None:
    assert check_exposed_service(_service(port)) is None


def test_sensitive_ports_table_is_exactly_as_specified() -> None:
    """Locks in PLAN_6.md section 2's exact table -- a drift here (an
    added/removed/relabeled port) should be a deliberate, reviewed change,
    not an accidental edit.
    """
    assert SENSITIVE_PORTS == {
        21: ("FTP", "MEDIUM"),
        23: ("Telnet", "HIGH"),
        445: ("SMB", "MEDIUM"),
        2375: ("Docker Engine API", "CRITICAL"),
        3306: ("MySQL", "MEDIUM"),
        3389: ("RDP", "MEDIUM"),
        5432: ("PostgreSQL", "MEDIUM"),
        5900: ("VNC", "HIGH"),
        6379: ("Redis", "HIGH"),
        9200: ("Elasticsearch", "HIGH"),
        11211: ("Memcached", "HIGH"),
        27017: ("MongoDB", "HIGH"),
    }
