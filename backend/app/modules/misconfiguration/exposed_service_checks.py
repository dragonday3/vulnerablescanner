"""Pure exposed-sensitive-service checks (Phase 6).

Zero new network calls, zero evidence dependency -- a static, curated
port -> (label, severity) table checked against every open `Service`
row's `port`, regardless of which scanner adapter found it. This is "is
a commonly-dangerous-to-expose service's default port open", never "did
I verify it's actually unauthenticated" -- verifying that would mean
connecting and issuing a protocol command, which is exactly the generic
banner-grabbing this project has already ruled out (see PLAN_6.md's
scope limits and Global Constraint 3).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.modules.misconfiguration.checks import MisconfigCandidate

if TYPE_CHECKING:
    from app.models.service import Service

# Curated, deliberately small: ports whose exposure is itself meaningful
# signal regardless of what's actually listening (we never connect to
# verify). Values are (label, severity).
SENSITIVE_PORTS: dict[int, tuple[str, str]] = {
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


def check_exposed_service(service: Service) -> MisconfigCandidate | None:
    """Pure, static lookup by service.port only. Returns None (not an
    empty list -- at most one candidate per service, unlike
    check_headers) when the port isn't in SENSITIVE_PORTS. Never raises.

    check_id is always the single literal string
    "exposed-sensitive-service" (one rule, many possible ports -- the
    port/label/severity live in `evidence`, not in a per-port check_id,
    so `uq_misconfig_service_check` still holds one row per service for
    this rule, since a service only has one port).
    """
    entry = SENSITIVE_PORTS.get(service.port)
    if entry is None:
        return None
    label, severity = entry
    return MisconfigCandidate(
        check_id="exposed-sensitive-service",
        title=f"Exposed {label} service",
        severity=severity,
        description=(
            f"Port {service.port} ({label}) is open and reachable. Services "
            "like this are commonly targeted and, if unauthenticated or "
            "misconfigured, can lead to significant compromise. This check "
            "only flags that the port is open -- no connection is made to "
            "verify whether the service is actually vulnerable."
        ),
        evidence={"port": service.port, "label": label, "severity": severity},
    )
