"""API route modules.

Import routers here to make them discoverable when included in the FastAPI app.
"""

from . import (  # noqa: F401
    audit_routes,
    auth_routes,
    data_source_routes,
    profile_routes,
    scan_routes,
)
