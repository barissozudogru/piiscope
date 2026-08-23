"""Server startup checks: import api.main with the required environment.

These tests are skipped when the server extra (fastapi, uvicorn, ...) is
not installed, so the core package test suite works without it.
"""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")
pytest.importorskip("sqlalchemy")
pytest.importorskip("celery")


def _required_env():
    return {
        "DATABASE_URL": "sqlite:///:memory:",
        "REDIS_URL": "redis://localhost:6379/0",
        "JWT_SECRET_KEY": "unit-test-secret-key-" + "x" * 48,
        "ENCRYPTION_KEY": base64.b64encode(b"0" * 32).decode("ascii"),
    }


@pytest.fixture(scope="module")
def api_app():
    """Import api.main with the mandatory settings present."""
    saved = {k: os.environ.get(k) for k in _required_env()}
    os.environ.update(_required_env())
    try:
        import api.main as api_main

        return api_main.app
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class TestAppStartup:
    def test_app_builds_with_routes(self, api_app):
        assert api_app is not None
        assert api_app.title
        # the OpenAPI schema materialises every mounted router
        paths = api_app.openapi().get("paths", {})
        assert len(paths) >= 10
        assert any(path.startswith("/auth") for path in paths)

    def test_middleware_imports_from_starlette(self):
        # api.middleware previously imported BaseHTTPMiddleware from
        # fastapi.middleware.base, which no longer re-exports it
        from starlette.middleware.base import BaseHTTPMiddleware

        from api.middleware import (
            RateLimitMiddleware,
            RequestLoggingMiddleware,
            SecurityHeadersMiddleware,
        )

        for cls in (SecurityHeadersMiddleware, RateLimitMiddleware, RequestLoggingMiddleware):
            assert issubclass(cls, BaseHTTPMiddleware)

    def test_celery_app_importable(self):
        from api.tasks import celery_app

        assert celery_app is not None

    def test_webhook_delete_returns_204_without_body(self, api_app):
        # a 204 response must not carry a body; returning the deleted
        # webhook JSON used to break the response contract
        schema = api_app.openapi()
        operation = schema["paths"]["/webhooks/{webhook_id}"]["delete"]
        responses = operation.get("responses", {})
        assert "204" in responses
        assert "200" not in responses


class TestPasswordHashing:
    def test_hash_and_verify(self):
        pytest.importorskip("bcrypt")
        from api.utils import get_password_hash, verify_password

        hashed = get_password_hash("correct horse battery staple")
        assert hashed != "correct horse battery staple"
        assert hashed.startswith("$2")
        assert verify_password("correct horse battery staple", hashed)
        assert not verify_password("wrong password", hashed)

    def test_verify_rejects_garbage_hash(self):
        pytest.importorskip("bcrypt")
        from api.utils import verify_password

        assert verify_password("anything", "not-a-bcrypt-hash") is False

    def test_uses_bcrypt_directly(self):
        pytest.importorskip("bcrypt")
        import api.utils as utils

        assert not hasattr(utils, "pwd_context"), "passlib CryptContext should be gone"
        assert hasattr(utils, "_BCRYPT_ROUNDS")


class TestApiImportsPiiscope:
    def test_scan_routes_use_package(self):
        import api.routes.scan_routes as scan_routes

        assert "piiscope" in sys.modules
        assert hasattr(scan_routes, "router")

    def test_detection_module_is_gone(self):
        repo = Path(__file__).resolve().parent.parent
        assert not (repo / "api" / "detection").exists()
