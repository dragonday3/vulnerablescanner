"""Structured (JSON) logging, with a scan_id hook for later phases.

Kept deliberately small: a JSON formatter plus a `configure_logging()`
entry point called once at app startup. Nothing populates `scan_id` yet —
it's the hook Phase 2's background workers will bind via
`scan_id_var.set(...)` once scans actually run in a worker context.
"""

import json
import logging
from contextvars import ContextVar
from datetime import UTC, datetime

from app.core.config import Settings

# Unset for every request/log call until a later phase's background worker
# binds it (e.g. `scan_id_var.set(str(scan.id))` at the start of a Celery
# task). Formatter below reads it defensively so an unset var never raises.
scan_id_var: ContextVar[str | None] = ContextVar("scan_id", default=None)


class JSONFormatter(logging.Formatter):
    """Emits one JSON object per log record."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "scan_id": scan_id_var.get(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging(settings: Settings) -> None:
    """Configure the root logger to emit JSON lines at `settings.LOG_LEVEL`."""
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(settings.LOG_LEVEL)
