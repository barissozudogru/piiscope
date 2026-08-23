"""Audit logging helper functions.

This module provides a convenience function for writing entries to the
audit log.  All actions that impact sensitive data or configuration
should call ``log_audit_event`` with the appropriate parameters.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from . import models


def log_audit_event(
    db: Session,
    user_id: int | None,
    action: str,
    target: str | None = None,
    details: Any | None = None,
) -> None:  # noqa: E501
    """Record an event in the audit log.

    Args:
        db: Active database session.
        user_id: ID of the user performing the action (may be ``None`` for
            system actions).
        action: A short string describing the action (e.g. ``"scan_started"``).
        target: Optional string identifying the target object (e.g.
            ``"job:123"`` or ``"profile:42"``).
        details: Arbitrary JSON‑serialisable object with additional
            information about the event.
    """
    entry = models.AuditLog(
        user_id=user_id,
        action=action,
        target=target,
        details=details,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(entry)
    db.flush()
