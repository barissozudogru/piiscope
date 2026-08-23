"""Audit log retrieval endpoints.

The audit log records significant actions performed by users.  Only
administrators may view the logs.  The log is append‑only and cannot
be modified through the API.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from .. import auth, models
from ..database import get_db

router = APIRouter()


@router.get("/logs")
async def list_audit_logs(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
    _: models.User = Depends(
        auth.role_required(models.RoleEnum.ADMIN, models.RoleEnum.SUPER_ADMIN)
    ),  # noqa: E501
):
    """Return a paginated list of audit log entries (admin/superadmin only)."""
    logs = (
        db.query(models.AuditLog)
        .order_by(models.AuditLog.timestamp.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "action": log.action,
            "target": log.target,
            "details": log.details,
            "timestamp": log.timestamp.isoformat(),
        }
        for log in logs
    ]
