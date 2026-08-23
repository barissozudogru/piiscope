"""FastAPI application entrypoint.

This module initialises the FastAPI app, registers API routers and sets up
middleware such as CORS.  All routes are prefixed under ``/`` and use
dependencies defined in other modules for authentication and role‑based
access control.  To run the API with uvicorn, use

.. code-block:: bash

    uvicorn api.main:app --host 0.0.0.0 --port 8000

The API exposes OpenAPI documentation at ``/docs`` and ``/redoc``.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from piiscope import __version__

from . import database, models
from .exceptions import BasePrivacyException
from .logging_config import setup_logging
from .middleware import setup_middleware
from .performance import init_connection_pool, init_redis_cache
from .routes import (
    audit_routes,
    auth_routes,
    data_source_routes,
    profile_routes,
    scan_routes,
    webhook_routes,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    setup_logging()
    init_redis_cache()
    init_connection_pool()

    # Ensure tables are created on startup.  In production one should use
    # Alembic migrations, but for a self-contained example we call create_all().
    models.Base.metadata.create_all(bind=database.engine)  # type: ignore[attr-defined]

    # Ensure a default super admin user exists on first startup.
    # DEFAULT_ADMIN_USER and DEFAULT_ADMIN_PASSWORD must be explicitly set via
    # environment variables.  Falling back to hardcoded defaults is not allowed
    # outside of the "test" environment.
    _env = os.getenv("ENVIRONMENT", "production")
    _username = os.getenv("DEFAULT_ADMIN_USER")
    _password = os.getenv("DEFAULT_ADMIN_PASSWORD")

    if not _username or not _password:
        if _env != "test":
            raise RuntimeError(
                "DEFAULT_ADMIN_USER and DEFAULT_ADMIN_PASSWORD must be set via "
                "environment variables before starting the application."
            )
        # In the test environment use safe non-guessable placeholders so the
        # application can still start without real credentials configured.
        _username = _username or "test_admin"
        _password = _password or "Test@dmin1!"

    _db = database.SessionLocal()
    try:
        if _db.query(models.User).count() == 0:
            from .utils import get_password_hash  # noqa: PLC0415

            _user = models.User(
                username=_username,
                password_hash=get_password_hash(_password),
                role=models.RoleEnum.SUPER_ADMIN,
            )
            _db.add(_user)
            _db.commit()
    finally:
        _db.close()

    yield

    # Shutdown
    # Any cleanup code would go here


app = FastAPI(
    title="piiscope API",
    version=__version__,
    description="Detect, score and remediate personal data in files and databases.",
    lifespan=lifespan,
)


@app.get("/health", tags=["health"], include_in_schema=True)
async def health() -> dict[str, str]:
    """Liveness probe used by Docker and load balancers."""
    return {"status": "ok", "version": __version__}


# Global exception handler for our custom exceptions
@app.exception_handler(BasePrivacyException)
async def privacy_exception_handler(request, exc: BasePrivacyException):
    return JSONResponse(
        status_code=400,
        content={"error": exc.message, "details": exc.details, "type": type(exc).__name__},
    )


# Set up security and request middleware
setup_middleware(app)

# Register routers under their respective prefixes
app.include_router(auth_routes.router, prefix="/auth", tags=["auth"])
app.include_router(profile_routes.router, prefix="/profiles", tags=["profiles"])
app.include_router(scan_routes.router, prefix="/scan", tags=["scan"])
app.include_router(audit_routes.router, prefix="/audit", tags=["audit"])
app.include_router(data_source_routes.router, prefix="/data-sources", tags=["data-sources"])
app.include_router(webhook_routes.router, prefix="/webhooks", tags=["webhooks"])
