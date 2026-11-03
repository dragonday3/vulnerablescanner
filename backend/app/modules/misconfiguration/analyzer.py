"""Misconfiguration analyzer orchestration glue (Phase 6, Task 4).

The one place all three Phase 6 check families
(`exposed_service_checks.py`, `header_checks.py`, `tls_inspector.py`)
meet: turns a scan's already-persisted `Service` rows into
`Misconfiguration` rows. Mirrors `vulnerability/correlator.py`'s
per-unit isolation discipline exactly -- one commit per Service, each
Service's own try/except, so one Service's failure (a weird evidence
shape, a DB hiccup) never aborts analysis of the rest of the scan's
services. `backend/app/workers/tasks.py` calls `analyze_services` and
nothing else from this package.
"""

from __future__ import annotations

import logging
import re

from sqlalchemy.orm import Session

from app.models.misconfiguration import Misconfiguration
from app.models.service import Service
from app.modules.misconfiguration.exposed_service_checks import check_exposed_service
from app.modules.misconfiguration.header_checks import check_headers
from app.modules.misconfiguration.tls_inspector import (
    TLS_CANDIDATE_PORTS,
    TlsInspectionResult,
    check_tls_result,
    inspect_tls,
)

logger = logging.getLogger(__name__)

# Deliberately independent of fingerprinting/http_prober.py's own TLS
# heuristic -- see PLAN_6.md's no-touch-other-modules rule / CLAUDE.md's
# discovery/fingerprinting separation principle. Case-insensitive,
# None-safe: a Service with no service_name at all (e.g. a bare
# nmap-discovered port with no -sV match) must never raise here.
_TLS_SERVICE_NAME_RE = re.compile(r"ssl|https|tls", re.IGNORECASE)


def _resolve_tls_candidate_ports(services: list[Service]) -> set[int]:
    """Step 1: `TLS_CANDIDATE_PORTS` unioned with every Service's own port
    whose `service_name` matches /ssl|https|tls/i, then intersected with
    the set of ports this scan's services actually have open. Resolved
    once across ALL of a scan's services, not per-service, so the caller
    can make exactly one `inspect_tls` call for the whole scan. The
    intersection avoids probing closed/irrelevant ports (e.g. the default
    443/4443/8443 candidates when nothing in this scan actually has any
    of them open).
    """
    candidate_ports = set(TLS_CANDIDATE_PORTS)
    for service in services:
        name = service.service_name
        if isinstance(name, str) and _TLS_SERVICE_NAME_RE.search(name):
            candidate_ports.add(service.port)
    open_ports = {service.port for service in services}
    return candidate_ports & open_ports


def analyze_services(db: Session, services: list[Service], target_host: str) -> None:
    """Best-effort: runs the exposed-service, header, and TLS-certificate
    checks for every `services` row and persists the results as
    `Misconfiguration` rows.

    Never raises past this function -- callers (`tasks.py`) rely on that
    the same way they rely on `correlate_services` never raising. Takes
    `services`, never `scan` -- this function structurally cannot mutate
    `scan.status` even by accident, since it has no reference to the
    `Scan` row at all.
    """
    try:
        # Step 1: resolve the TLS candidate port set across ALL services
        # once, then make exactly ONE inspect_tls() call for the whole
        # scan -- avoids redundant repeated handshakes against the same
        # host, one per candidate port rather than one per service.
        candidate_ports = _resolve_tls_candidate_ports(services)
        tls_results: dict[int, TlsInspectionResult] = (
            inspect_tls(target_host, sorted(candidate_ports)) if candidate_ports else {}
        )

        # Steps 2-3: per service, run the applicable check families,
        # build Misconfiguration rows, and commit once per service --
        # inside that service's own try/except (mirroring
        # correlator.py's per-CPE isolation exactly), so one service's
        # failure never aborts analysis of the rest.
        for service in services:
            try:
                candidates = []

                exposed = check_exposed_service(service)
                if exposed is not None:
                    candidates.append(exposed)

                evidence = service.evidence
                if isinstance(evidence, dict) and "headers" in evidence:
                    candidates.extend(check_headers(service))

                if service.port in candidate_ports:
                    # A candidate port with no actual TLS response (refused,
                    # non-TLS, timed out) just means zero TLS candidates for
                    # this service, not an error -- inspect_tls already
                    # omits it from tls_results.
                    tls_result = tls_results.get(service.port)
                    if tls_result is not None:
                        candidates.extend(check_tls_result(tls_result))

                if not candidates:
                    continue

                # uq_misconfig_service_check (Global Constraint 9): one row
                # per (service_id, check_id). No single check family emits
                # the same check_id twice for one service today, but this
                # dedup is enforced here -- the one place all three
                # families meet -- rather than relied upon per-family, so
                # it holds even if that ever changes.
                seen_check_ids: set[str] = set()
                rows = []
                for candidate in candidates:
                    if candidate.check_id in seen_check_ids:
                        logger.warning(
                            "analyze_services: service %s produced a duplicate "
                            "check_id %r, skipping the duplicate "
                            "(uq_misconfig_service_check)",
                            service.id,
                            candidate.check_id,
                        )
                        continue
                    seen_check_ids.add(candidate.check_id)
                    rows.append(
                        Misconfiguration(
                            service_id=service.id,
                            check_id=candidate.check_id,
                            title=candidate.title,
                            severity=candidate.severity,
                            description=candidate.description,
                            evidence=candidate.evidence,
                        )
                    )

                if rows:
                    db.add_all(rows)
                    db.commit()
            except Exception:
                # Per-service isolation (see comment above the try): roll
                # back only this service's uncommitted work and move on to
                # the next service -- do not let one service's failure
                # abort the rest of the scan's analysis.
                db.rollback()
                logger.exception(
                    "analyze_services: analysis failed for service %s, skipping this "
                    "service only",
                    service.id,
                )
                continue
    except Exception:
        # Structural safety net for anything the per-service handling
        # above didn't anticipate (e.g. a failure resolving TLS candidate
        # ports or in the single inspect_tls() call itself). Never raises,
        # never touches anything related to scan.status (this function has
        # no `scan` reference at all, so it structurally cannot).
        db.rollback()
        logger.exception("analyze_services: misconfiguration analysis failed")
