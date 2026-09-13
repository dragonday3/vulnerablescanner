from celery import Celery

from app.core.config import get_settings

settings = get_settings()
celery_app = Celery("vulnsight", broker=settings.REDIS_URL, backend=settings.REDIS_URL)
celery_app.autodiscover_tasks(["app.workers"])
