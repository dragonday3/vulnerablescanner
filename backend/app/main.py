import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from app.api.routes.health import router as health_router
from app.api.routes.projects import router as projects_router
from app.api.routes.scans import router as scans_router
from app.api.routes.targets import router as targets_router
from app.core.config import get_settings
from app.core.exceptions import NotFoundError, ScanStateError, ValidationConflictError
from app.core.logging import configure_logging

# Single entry point: registers every model on Base before any request
# touches the ORM, so cross-model relationship() string references like
# Project.targets/Project.scans resolve correctly regardless of which module
# happens to import a model class first. Imported as `from app.db import
# base` (not `import app.db.base`) so it doesn't bind the name `app` in this
# module's namespace, which would otherwise shadow the `app = FastAPI()`
# variable below for type checkers.
from app.db import base as _db_base  # noqa: F401

settings = get_settings()

# Configured once at import time (before the exception handlers/routers
# below), so every log emitted through this application's own `logging`
# module — request handling, service-layer logging, etc. — goes through
# the JSON formatter. This does NOT cover uvicorn's own access/error logs:
# uvicorn attaches its own handlers directly to the `uvicorn`/`uvicorn.access`
# loggers with propagate=False, so those bypass the root logger entirely
# and print in uvicorn's default format.
configure_logging(settings)
logger = logging.getLogger(__name__)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(NotFoundError)
    def not_found_error_handler(request: Request, exc: NotFoundError) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={"detail": str(exc), "code": "not_found"},
        )

    @app.exception_handler(ValidationConflictError)
    def validation_conflict_error_handler(
        request: Request, exc: ValidationConflictError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={"detail": str(exc), "code": "conflict"},
        )

    @app.exception_handler(ScanStateError)
    def scan_state_error_handler(request: Request, exc: ScanStateError) -> JSONResponse:
        return JSONResponse(
            status_code=409,
            content={"detail": str(exc), "code": "scan_state_conflict"},
        )

    @app.exception_handler(SQLAlchemyError)
    def sqlalchemy_error_handler(request: Request, exc: SQLAlchemyError) -> JSONResponse:
        # Catch-all for DB-layer errors that escape the service layer (e.g.
        # an IntegrityError from a constraint the Pydantic schema didn't
        # catch). Log the real error server-side only — the client gets a
        # generic message in the same {"detail", "code"} envelope shape as
        # every other handler above, so the error envelope is uniform
        # regardless of error type.
        logger.error("Unhandled database error", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "code": "internal_error"},
        )


register_exception_handlers(app)

app.include_router(health_router, prefix=settings.API_V1_PREFIX)
app.include_router(projects_router, prefix=settings.API_V1_PREFIX)
app.include_router(targets_router, prefix=settings.API_V1_PREFIX)
app.include_router(scans_router, prefix=settings.API_V1_PREFIX)
