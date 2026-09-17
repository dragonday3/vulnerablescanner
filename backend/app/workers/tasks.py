import logging
import uuid
from datetime import UTC, datetime

from app.core.logging import scan_id_var
from app.db.session import SessionLocal
from app.models.asset import Asset
from app.models.scan import Scan, ScanStatus
from app.models.service import Service
from app.models.target import TargetType
from app.modules.discovery.common_ports import COMMON_PORTS, PORT_NAMES
from app.modules.discovery.interfaces import PortScannerInterface
from app.modules.discovery.native_scanner import NativePortScanner
from app.modules.discovery.nmap_scanner import NmapPortScanner
from app.modules.fingerprinting.http_prober import WEB_PORTS, probe_services
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

# Per PLAN_2.md's discovery-module design notes: a short per-connection
# timeout for the native (asyncio TCP-connect) adapter keeps the default
# scan profile fast/low-noise, while the nmap adapter needs a much larger
# *overall* subprocess timeout since it scans up to 1000 ports in one
# invocation ("a sane overall timeout, e.g. 120s" per the plan).
#
# Re-measured 2026-09-17 (Phase 3, PLAN_3.md #2) after adding `-sV` to the
# nmap invocation, since service/version probing is meaningfully slower than
# a bare `-sT` connect scan. Real top-1000-port `-sV` scans from inside the
# `backend` container against in-network Docker Compose targets observed:
# a single real service (postgres:5432 ~6.5s, backend:8000/uvicorn ~11.4s),
# and a synthetic 11-open-port host (10 bare listeners + the real uvicorn
# service on 8000) at ~11.5s total - worst observed wall-clock was ~11.5s.
# 2-3x headroom on that measurement is under 35s, well below the fixed
# floor the plan calls for, so the floor wins: 180.0s (up from 120.0s).
NATIVE_SCAN_TIMEOUT_SECONDS = 1.5
NMAP_SCAN_TIMEOUT_SECONDS = 180.0

# Error-message column truncation guard (Task 6 brief step 8): a huge
# traceback-derived string must never blow out the `error_message` Text
# column's practical size.
MAX_ERROR_MESSAGE_LENGTH = 2000


@celery_app.task
def ping() -> str:
    """Trivial placeholder task proving the Celery+Redis+worker wiring works.

    The real orchestration task (`run_scan_task`) is built in a later task
    in this plan on top of the plumbing this one verifies.
    """
    return "pong"


@celery_app.task
def run_scan_task(scan_id: str) -> None:
    """Run a single scan end-to-end: discovery only, this phase.

    Opens its own DB session (Global Constraint 9 — Celery tasks never
    share a FastAPI request-scoped session), and commits each status
    transition immediately as it happens (Global Constraint 10) so a
    mid-task crash leaves the DB reflecting the last real transition
    rather than silently stuck at `QUEUED`.
    """
    db = SessionLocal()
    scan_id_token = None
    try:
        # Step 1: load the scan; handle the cancel-before-pickup race and a
        # missing row (e.g. deleted) by returning early, quietly.
        scan = db.get(Scan, uuid.UUID(scan_id))
        if scan is None:
            logger.info("run_scan_task: scan %s not found, skipping", scan_id)
            return
        if scan.status == ScanStatus.CANCELLED:
            logger.info("run_scan_task: scan %s already cancelled, skipping", scan_id)
            return

        # Bind scan_id onto every log line emitted for the rest of this
        # task (JSONFormatter reads scan_id_var) so a failure's
        # logger.exception(...) call below - and any other log line during
        # this scan's run - can be correlated back to the scan. Reset in
        # `finally` since Celery's prefork worker processes are long-lived
        # and handle many tasks in sequence; leaving this set would leak
        # this scan's id into the next task's log lines.
        scan_id_token = scan_id_var.set(str(scan.id))

        # Step 2: RUNNING.
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(UTC)
        db.commit()

        # Step 3: DISCOVERY.
        scan.status = ScanStatus.DISCOVERY
        db.commit()

        # Step 4: CIDR targets are out of scope this phase — fail fast,
        # before any adapter is even selected.
        target = scan.target
        if target.target_type == TargetType.CIDR:
            scan.status = ScanStatus.FAILED
            scan.error_message = "CIDR range scanning is not yet supported"
            scan.completed_at = datetime.now(UTC)
            db.commit()
            return

        # Defense-in-depth: re-check authorization here too, not just at
        # scan-creation time (scan_service.create_scan). This worker process
        # is the one that actually emits network traffic, potentially much
        # later and always in a separate transaction from creation - if
        # authorization is revoked (the Target row's
        # `authorization_confirmed` flipped to False) after a scan was
        # queued but before the worker picks it up, this is the only check
        # standing between that revocation and a scan actually running
        # against a no-longer-authorized target.
        if target.authorization_confirmed is not True:
            scan.status = ScanStatus.FAILED
            scan.error_message = "Target authorization is not confirmed"
            scan.completed_at = datetime.now(UTC)
            db.commit()
            return

        # Steps 5-7: adapter selection, the scan itself, and persisting
        # results are all wrapped in one try/except so any failure —
        # unknown scanner name, a raised scanner exception, a DB error while
        # persisting results — lands the scan in FAILED rather than crashing
        # the worker.
        try:
            scanner_name = scan.config.get("scanner", "native")
            adapter: PortScannerInterface
            if scanner_name == "native":
                adapter = NativePortScanner()
                results = adapter.scan(
                    target.value, COMMON_PORTS, timeout_seconds=NATIVE_SCAN_TIMEOUT_SECONDS
                )
            elif scanner_name == "nmap":
                adapter = NmapPortScanner()
                results = adapter.scan(target.value, [], timeout_seconds=NMAP_SCAN_TIMEOUT_SECONDS)
            else:
                raise ValueError(f"Unknown scanner '{scanner_name}'")

            asset = Asset(
                project_id=scan.project_id,
                target_id=scan.target_id,
                scan_id=scan.id,
                host=target.value,
            )
            services = [
                Service(
                    asset=asset,
                    port=result.port,
                    protocol=result.protocol,
                    state=result.state,
                    service_name=result.service_name or PORT_NAMES.get(result.port),
                    product=result.product,
                    version=result.version,
                    extrainfo=result.extrainfo,
                    fingerprint_source="nmap-sv" if scanner_name == "nmap" else None,
                    evidence=result.raw_evidence,
                )
                for result in results
            ]
            db.add_all([asset, *services])
            db.commit()
        except Exception as exc:
            # A failure that happened mid-flush/commit (e.g. the Asset/
            # Service persistence commit above) leaves the session's
            # transaction invalidated - any further use, including the
            # FAILED-transition commit below, raises PendingRollbackError
            # unless we roll back first. Safe to call unconditionally: a
            # failure from the adapter/dispatch code (no flush attempted)
            # just rolls back an empty transaction.
            db.rollback()
            # Step 8: log the full exception server-side before truncating
            # what goes in the DB column.
            logger.exception("run_scan_task: scan %s failed", scan_id)
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)[:MAX_ERROR_MESSAGE_LENGTH]
            scan.completed_at = datetime.now(UTC)
            db.commit()
            # Explicit return: without this, a discovery failure (correctly
            # committed as FAILED above) would otherwise fall through into
            # the FINGERPRINTING/COMPLETED code below and get incorrectly
            # overwritten, since this except block is no longer the last
            # statement in the function (Phase 3, PLAN_3.md #4).
            return

        # Step 8 (Phase 3): FINGERPRINTING. Committed uniformly for both
        # adapters, even nmap-adapter scans (whose evidence is already
        # complete from the `-sV` pass above) — this keeps the state machine
        # adapter-agnostic for future phases. `services` (built above) are
        # still attached, in-session ORM objects, reused directly below with
        # no re-query needed.
        scan.status = ScanStatus.FINGERPRINTING
        db.commit()

        # Step 9 (Phase 3): native-only HTTP enrichment, a second best-effort
        # pass over the already-persisted Service rows. Its own independent
        # try/except: fingerprinting failures must never fail the scan, so on
        # any exception here we roll back, log, and fall through to
        # COMPLETED regardless — no scan.status mutation, no return.
        try:
            if scanner_name == "native":
                web_ports = [s.port for s in services if s.port in WEB_PORTS]
                if web_ports:
                    probe_results = probe_services(target.value, web_ports)
                    for service in services:
                        probe = probe_results.get(service.port)
                        if probe is None:
                            continue
                        service.product = probe.product
                        service.version = probe.version
                        service.extrainfo = probe.extrainfo
                        service.fingerprint_source = "http"
                        service.evidence = {
                            "scheme": probe.scheme,
                            "status_code": probe.status_code,
                            "server": probe.server_header,
                            "title": probe.title,
                            "headers": probe.headers,
                        }
                    db.commit()
        except Exception:
            db.rollback()
            logger.exception("run_scan_task: scan %s HTTP fingerprinting failed", scan_id)

        # Step 10: unchanged.
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(UTC)
        db.commit()
    finally:
        if scan_id_token is not None:
            scan_id_var.reset(scan_id_token)
        db.close()
