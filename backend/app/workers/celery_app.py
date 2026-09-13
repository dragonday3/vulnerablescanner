from celery import Celery

from app.core.config import get_settings
from app.core.logging import configure_logging

# Single entry point for the worker process: registers every model on Base
# before any task touches the ORM, so cross-model relationship() string
# references (e.g. Scan.project, Scan.target) resolve correctly regardless
# of which task module happens to import a model class first. The FastAPI
# process gets this for free via app.main's own equivalent import, but this
# module - not app.main - is the Celery worker's entrypoint
# (`celery -A app.workers.celery_app worker`), so it needs its own copy.
# Aliased (not `import app.db.base`) so it doesn't bind the name `app` in
# this module's namespace, which would otherwise be confusing next to the
# `celery_app` variable below.
from app.db import base as _db_base  # noqa: F401

settings = get_settings()

# Configured here for the same reason app.main configures it for the
# FastAPI process: without this, the worker process's root logger keeps
# Celery's own default (non-JSON) logging setup, so `logger.exception(...)`
# calls in tasks.py - and the scan_id_var correlation they carry - would
# never actually reach the JSON formatter that reads it.
configure_logging(settings)

celery_app = Celery("vulnsight", broker=settings.REDIS_URL, backend=settings.REDIS_URL)
celery_app.autodiscover_tasks(["app.workers"])

# Celery's worker bootstep otherwise hijacks the root logger after this
# module is imported - reinstalling its own default (non-JSON) handler and
# silently discarding the configure_logging() call above, which would make
# scan_id_var correlation (and every other structured log field) vanish
# from real `celery worker` process output despite working in-process
# (e.g. under pytest, or a bare `python -c` import) where nothing hijacks
# the root logger afterward.
celery_app.conf.worker_hijack_root_logger = False
