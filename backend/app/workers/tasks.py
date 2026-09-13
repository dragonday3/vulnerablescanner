from app.workers.celery_app import celery_app


@celery_app.task
def ping() -> str:
    """Trivial placeholder task proving the Celery+Redis+worker wiring works.

    The real orchestration task (`run_scan_task`) is built in a later task
    in this plan on top of the plumbing this one verifies.
    """
    return "pong"
