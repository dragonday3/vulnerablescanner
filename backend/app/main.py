from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import app.db.base  # noqa: F401  (single entry point: registers every model on Base
# before any request touches the ORM, so cross-model relationship() string
# references like Project.targets/Project.scans resolve correctly regardless
# of which module happens to import a model class first)
from app.api.routes.health import router as health_router
from app.api.routes.projects import router as projects_router
from app.api.routes.targets import router as targets_router
from app.core.config import get_settings
from app.core.exceptions import NotFoundError, ValidationConflictError

settings = get_settings()

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


register_exception_handlers(app)

app.include_router(health_router, prefix=settings.API_V1_PREFIX)
app.include_router(projects_router, prefix=settings.API_V1_PREFIX)
app.include_router(targets_router, prefix=settings.API_V1_PREFIX)
