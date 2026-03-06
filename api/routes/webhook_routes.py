"""Webhook management endpoints.

Provides CRUD operations for webhook registrations plus a test-delivery
endpoint.  All routes require authentication; ADMIN or SUPER_ADMIN role
is required to create, update or delete webhooks.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session

from .. import auth, models
from ..database import get_db
from ..services.webhook_service import (
    WebhookEvent,
    WebhookRegistration,
    WebhookService,
)

router = APIRouter()

# Module-level singleton for the webhook service.
# In a multi-process deployment this should be backed by a shared store
# (e.g. Redis or the database); for this implementation we use in-memory.
_webhook_service = WebhookService()


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class WebhookCreate(BaseModel):
    url: HttpUrl
    events: List[WebhookEvent]
    secret: Optional[str] = None
    description: str = ""


class WebhookUpdate(BaseModel):
    url: Optional[HttpUrl] = None
    events: Optional[List[WebhookEvent]] = None
    secret: Optional[str] = None
    enabled: Optional[bool] = None
    description: Optional[str] = None


class WebhookOut(BaseModel):
    id: str
    url: str
    events: List[str]
    enabled: bool
    description: str


class WebhookTestOut(BaseModel):
    success: bool
    delivered: int
    failed: int
    details: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reg_to_out(reg: WebhookRegistration) -> WebhookOut:
    return WebhookOut(
        id=reg.id,
        url=str(reg.url),
        events=[e.value for e in reg.events],
        enabled=reg.enabled,
        description=reg.description,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/", response_model=List[WebhookOut])
async def list_webhooks(
    current_user: models.User = Depends(auth.get_current_user),
) -> List[WebhookOut]:
    """List all registered webhooks (admin only)."""
    if current_user.role not in (models.RoleEnum.ADMIN, models.RoleEnum.SUPER_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return [_reg_to_out(r) for r in _webhook_service.list_all()]


@router.post("/", response_model=WebhookOut, status_code=status.HTTP_201_CREATED)
async def create_webhook(
    payload: WebhookCreate,
    current_user: models.User = Depends(
        auth.role_required(models.RoleEnum.ADMIN, models.RoleEnum.SUPER_ADMIN)
    ),
) -> WebhookOut:
    """Register a new webhook endpoint."""
    reg = WebhookRegistration(
        id=str(uuid.uuid4()),
        url=str(payload.url),
        events=payload.events,
        secret=payload.secret,
        description=payload.description,
    )
    _webhook_service.register(reg)
    return _reg_to_out(reg)


@router.get("/{webhook_id}", response_model=WebhookOut)
async def get_webhook(
    webhook_id: str,
    current_user: models.User = Depends(auth.get_current_user),
) -> WebhookOut:
    """Retrieve a specific webhook registration."""
    if current_user.role not in (models.RoleEnum.ADMIN, models.RoleEnum.SUPER_ADMIN):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    reg = _webhook_service.get(webhook_id)
    if not reg:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return _reg_to_out(reg)


@router.patch("/{webhook_id}", response_model=WebhookOut)
async def update_webhook(
    webhook_id: str,
    payload: WebhookUpdate,
    current_user: models.User = Depends(
        auth.role_required(models.RoleEnum.ADMIN, models.RoleEnum.SUPER_ADMIN)
    ),
) -> WebhookOut:
    """Update a webhook registration."""
    reg = _webhook_service.update(
        webhook_id=webhook_id,
        url=str(payload.url) if payload.url else None,
        events=payload.events,
        secret=payload.secret,
        enabled=payload.enabled,
        description=payload.description,
    )
    if not reg:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return _reg_to_out(reg)


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook(
    webhook_id: str,
    current_user: models.User = Depends(
        auth.role_required(models.RoleEnum.ADMIN, models.RoleEnum.SUPER_ADMIN)
    ),
) -> None:
    """Delete a webhook registration."""
    if not _webhook_service.deregister(webhook_id):
        raise HTTPException(status_code=404, detail="Webhook not found")


@router.post("/{webhook_id}/test", response_model=WebhookTestOut)
async def test_webhook(
    webhook_id: str,
    current_user: models.User = Depends(
        auth.role_required(models.RoleEnum.ADMIN, models.RoleEnum.SUPER_ADMIN)
    ),
) -> WebhookTestOut:
    """Send a test ping to a specific webhook endpoint."""
    reg = _webhook_service.get(webhook_id)
    if not reg:
        raise HTTPException(status_code=404, detail="Webhook not found")

    results = _webhook_service.notify(
        event=WebhookEvent.SCAN_COMPLETE,
        scan_id=0,
        data={"test": True, "message": "Test delivery from Data Security Checker"},
    )

    delivered = sum(1 for r in results if r.success)
    failed = len(results) - delivered

    return WebhookTestOut(
        success=all(r.success for r in results),
        delivered=delivered,
        failed=failed,
        details=[
            {
                "webhook_id": r.webhook_id,
                "success": r.success,
                "attempts": r.attempts,
                "status_code": r.status_code,
                "error": r.error,
            }
            for r in results
        ],
    )


# ---------------------------------------------------------------------------
# Expose the singleton so other modules can dispatch events
# ---------------------------------------------------------------------------

def get_webhook_service() -> WebhookService:
    """FastAPI dependency that returns the module-level WebhookService."""
    return _webhook_service
