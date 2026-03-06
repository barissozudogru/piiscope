"""FastAPI application entrypoint.

This module initialises the FastAPI app, registers API routers and sets up
middleware such as CORS.  All routes are prefixed under ``/`` and use
dependencies defined in other modules for authentication and role‑based
access control.  To run the API with uvicorn, use

.. code-block:: bash

    uvicorn gdpr_privacy_app.api.main:app --host 0.0.0.0 --port 8000

The API exposes OpenAPI documentation at ``/docs`` and ``/redoc``.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from . import models
from . import database
from .routes import auth_routes, profile_routes, scan_routes, audit_routes, data_source_routes, webhook_routes
# from .middleware import setup_middleware
# from .logging_config import setup_logging
# from .performance import init_redis_cache, init_connection_pool
# from .exceptions import BasePrivacyException

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    # setup_logging()
    # init_redis_cache()
    # init_connection_pool()

    # Ensure tables are created on startup.  In production one should use
    # Alembic migrations, but for a self-contained example we call create_all().
    models.Base.metadata.create_all(bind=database.engine)  # type: ignore[attr-defined]

    # Ensure a default super admin user exists on first startup.
    # Username/password are read from DEFAULT_ADMIN_USER / DEFAULT_ADMIN_PASSWORD;
    # they fall back to 'admin'/'admin' when those vars are not set.
    _db = database.SessionLocal()
    try:
        if _db.query(models.User).count() == 0:
            _username = os.getenv("DEFAULT_ADMIN_USER", "admin")
            _password = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin")
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
    title="GDPR Privacy Risk Detection API", 
    version="1.0.0",
    description="API for detecting and managing privacy risks in structured data",
    lifespan=lifespan
)

# Global exception handler for our custom exceptions
# @app.exception_handler(BasePrivacyException)
# async def privacy_exception_handler(request, exc: BasePrivacyException):
#     return JSONResponse(
#         status_code=400,
#         content={
#             "error": exc.message,
#             "details": exc.details,
#             "type": type(exc).__name__
#         }
#     )

# Set up middleware
# setup_middleware(app)

# Register routers under their respective prefixes
app.include_router(auth_routes.router, prefix="/auth", tags=["auth"])
app.include_router(profile_routes.router, prefix="/profiles", tags=["profiles"])
app.include_router(scan_routes.router, prefix="/scan", tags=["scan"])
app.include_router(audit_routes.router, prefix="/audit", tags=["audit"])
app.include_router(data_source_routes.router, prefix="/data-sources", tags=["data-sources"])
app.include_router(webhook_routes.router, prefix="/webhooks", tags=["webhooks"])
