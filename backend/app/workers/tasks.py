import logging
import uuid
from datetime import UTC, datetime

from app.db.session import SessionLocal
from app.models.asset import Asset
from app.models.scan import Scan, ScanStatus
from app.models.service import Service
from app.models.target import TargetType
from app.modules.discovery.common_ports import COMMON_PORTS, PORT_NAMES
from app.modules.discovery.interfaces import PortScannerInterface
from app.modules.discovery.native_scanner import NativePortScanner
from app.modules.discovery.nmap_scanner import NmapPortScanner
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

# Per PLAN_2.md's discovery-module design notes: a short per-connection
# timeout for the native (asyncio TCP-connect) adapter keeps the default
# scan profile fast/low-noise, while the nmap adapter needs a much larger
# *overall* subprocess timeout since it scans up to 1000 ports in one
# invocation ("a sane overall timeout, e.g. 120s" per the plan).
NATIVE_SCAN_TIMEOUT_SECONDS = 1.5
NMAP_SCAN_TIMEOUT_SECONDS = 120.0

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
                    service_name=PORT_NAMES.get(result.port),
                )
                for result in results
            ]
            db.add_all([asset, *services])
            db.commit()

            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(UTC)
            db.commit()
        except Exception as exc:
            # Step 8: log the full exception server-side before truncating
            # what goes in the DB column.
            logger.exception("run_scan_task: scan %s failed", scan_id)
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)[:MAX_ERROR_MESSAGE_LENGTH]
            scan.completed_at = datetime.now(UTC)
            db.commit()
    finally:
        db.close()
