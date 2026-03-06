"""Webhook notification service.

Webhooks allow external systems to receive real-time notifications when
significant events occur during scanning:

  - scan_complete   : a scan job finished (success or failure)
  - critical_finding: a finding with risk score >= 8 was detected
  - compliance_violation: a DPIA or RoPA event requiring DPO attention

Webhook registrations are managed via CRUD operations and stored in the
``WebhookRegistration`` model.  Each notification delivery is attempted with
exponential back-off (max 5 retries).  Delivery results are logged.

This module only contains the service logic.  The FastAPI router that
exposes the CRUD endpoints lives in ``api/routes/webhook_routes.py``.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------

class WebhookEvent(str, Enum):
    SCAN_COMPLETE = "scan_complete"
    CRITICAL_FINDING = "critical_finding"
    COMPLIANCE_VIOLATION = "compliance_violation"
    SCAN_STARTED = "scan_started"
    SCAN_FAILED = "scan_failed"


# ---------------------------------------------------------------------------
# Webhook registration (in-memory store; callers should persist to DB)
# ---------------------------------------------------------------------------

@dataclass
class WebhookRegistration:
    id: str                          # UUID string
    url: str
    events: List[WebhookEvent]       # events this webhook subscribes to
    secret: Optional[str] = None     # HMAC-SHA256 signing secret
    enabled: bool = True
    description: str = ""
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def subscribes_to(self, event: WebhookEvent) -> bool:
        return self.enabled and event in self.events


# ---------------------------------------------------------------------------
# Delivery result
# ---------------------------------------------------------------------------

@dataclass
class DeliveryResult:
    webhook_id: str
    event: WebhookEvent
    url: str
    success: bool
    attempts: int
    status_code: Optional[int]
    error: Optional[str]
    delivered_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


# ---------------------------------------------------------------------------
# Retry configuration
# ---------------------------------------------------------------------------

_MAX_RETRIES = 5
_BASE_DELAY = 1.0        # seconds
_MAX_DELAY = 60.0        # seconds
_BACKOFF_FACTOR = 2.0
_CONNECT_TIMEOUT = 5     # seconds
_READ_TIMEOUT = 10       # seconds


def _compute_delay(attempt: int) -> float:
    """Exponential back-off with a cap."""
    delay = _BASE_DELAY * (_BACKOFF_FACTOR ** attempt)
    return min(delay, _MAX_DELAY)


# ---------------------------------------------------------------------------
# Payload builder
# ---------------------------------------------------------------------------

def _build_payload(
    event: WebhookEvent,
    scan_id: int,
    data: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "event": event.value,
        "scan_id": scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }


def _sign_payload(secret: str, body: bytes) -> str:
    """Return HMAC-SHA256 signature for the payload bytes."""
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Delivery logic
# ---------------------------------------------------------------------------

def _deliver(
    webhook: WebhookRegistration,
    payload: Dict[str, Any],
) -> DeliveryResult:
    """Deliver ``payload`` to ``webhook.url`` with exponential back-off.

    Uses only stdlib ``urllib`` to avoid introducing an httpx / requests
    dependency in the production code path.  For production usage with
    async support, swap this for an async HTTP client.
    """
    body = json.dumps(payload, default=str).encode("utf-8")
    signature = _sign_payload(webhook.secret, body) if webhook.secret else None

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "DataSecurityChecker-Webhook/1.0",
        "X-Webhook-Event": payload["event"],
        "X-Scan-Id": str(payload["scan_id"]),
    }
    if signature:
        headers["X-Signature-SHA256"] = f"sha256={signature}"

    last_error: Optional[str] = None
    last_status: Optional[int] = None

    for attempt in range(_MAX_RETRIES):
        try:
            req = Request(
                webhook.url,
                data=body,
                headers=headers,
                method="POST",
            )
            with urlopen(req, timeout=_CONNECT_TIMEOUT + _READ_TIMEOUT) as resp:
                last_status = resp.status
                if 200 <= resp.status < 300:
                    logger.info(
                        "Webhook %s delivered event '%s' to %s (attempt %d, status %d)",
                        webhook.id, payload["event"], webhook.url, attempt + 1, resp.status,
                    )
                    return DeliveryResult(
                        webhook_id=webhook.id,
                        event=WebhookEvent(payload["event"]),
                        url=webhook.url,
                        success=True,
                        attempts=attempt + 1,
                        status_code=resp.status,
                        error=None,
                    )
                # Non-2xx: treat as transient failure and retry
                last_error = f"HTTP {resp.status}"
                logger.warning(
                    "Webhook %s delivery attempt %d returned HTTP %d",
                    webhook.id, attempt + 1, resp.status,
                )

        except HTTPError as exc:
            last_status = exc.code
            last_error = f"HTTP {exc.code}: {exc.reason}"
            logger.warning(
                "Webhook %s delivery attempt %d: HTTP error %d",
                webhook.id, attempt + 1, exc.code,
            )
        except URLError as exc:
            last_error = str(exc.reason)
            logger.warning(
                "Webhook %s delivery attempt %d: URL error: %s",
                webhook.id, attempt + 1, exc.reason,
            )
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            logger.warning(
                "Webhook %s delivery attempt %d: unexpected error: %s",
                webhook.id, attempt + 1, exc,
            )

        if attempt < _MAX_RETRIES - 1:
            delay = _compute_delay(attempt)
            logger.debug(
                "Webhook %s: retrying in %.1fs (attempt %d/%d)",
                webhook.id, delay, attempt + 1, _MAX_RETRIES,
            )
            time.sleep(delay)

    logger.error(
        "Webhook %s failed to deliver event '%s' after %d attempts: %s",
        webhook.id, payload["event"], _MAX_RETRIES, last_error,
    )
    return DeliveryResult(
        webhook_id=webhook.id,
        event=WebhookEvent(payload["event"]),
        url=webhook.url,
        success=False,
        attempts=_MAX_RETRIES,
        status_code=last_status,
        error=last_error,
    )


# ---------------------------------------------------------------------------
# Webhook service
# ---------------------------------------------------------------------------

class WebhookService:
    """Manage webhook registrations and dispatch notifications.

    This class operates on an in-memory registry.  The caller is responsible
    for persisting registrations to the database and rehydrating them.
    """

    def __init__(self) -> None:
        self._registry: Dict[str, WebhookRegistration] = {}

    # ------------------------------------------------------------------
    # Registry management
    # ------------------------------------------------------------------

    def register(self, registration: WebhookRegistration) -> WebhookRegistration:
        """Add or replace a webhook registration."""
        self._registry[registration.id] = registration
        logger.info(
            "Webhook registered: id=%s url=%s events=%s",
            registration.id, registration.url,
            [e.value for e in registration.events],
        )
        return registration

    def deregister(self, webhook_id: str) -> bool:
        """Remove a webhook registration. Returns True if it existed."""
        if webhook_id in self._registry:
            del self._registry[webhook_id]
            logger.info("Webhook deregistered: id=%s", webhook_id)
            return True
        return False

    def get(self, webhook_id: str) -> Optional[WebhookRegistration]:
        return self._registry.get(webhook_id)

    def list_all(self) -> List[WebhookRegistration]:
        return list(self._registry.values())

    def update(
        self,
        webhook_id: str,
        url: Optional[str] = None,
        events: Optional[List[WebhookEvent]] = None,
        secret: Optional[str] = None,
        enabled: Optional[bool] = None,
        description: Optional[str] = None,
    ) -> Optional[WebhookRegistration]:
        reg = self._registry.get(webhook_id)
        if reg is None:
            return None
        if url is not None:
            reg.url = url
        if events is not None:
            reg.events = events
        if secret is not None:
            reg.secret = secret
        if enabled is not None:
            reg.enabled = enabled
        if description is not None:
            reg.description = description
        reg.updated_at = datetime.now(timezone.utc)
        logger.info("Webhook updated: id=%s", webhook_id)
        return reg

    # ------------------------------------------------------------------
    # Notification dispatching
    # ------------------------------------------------------------------

    def notify(
        self,
        event: WebhookEvent,
        scan_id: int,
        data: Dict[str, Any],
    ) -> List[DeliveryResult]:
        """Notify all subscribed webhooks of an event.

        Delivery is synchronous.  For high-throughput production environments
        this should be moved to a background task queue (Celery / ARQ).
        """
        payload = _build_payload(event, scan_id, data)
        results: List[DeliveryResult] = []

        for reg in self._registry.values():
            if not reg.subscribes_to(event):
                continue
            result = _deliver(reg, payload)
            results.append(result)

        return results

    def notify_scan_complete(
        self,
        scan_id: int,
        status: str,
        total_findings: int,
        aggregate_risk: float,
    ) -> List[DeliveryResult]:
        return self.notify(
            WebhookEvent.SCAN_COMPLETE,
            scan_id,
            {
                "status": status,
                "total_findings": total_findings,
                "aggregate_risk_score": aggregate_risk,
            },
        )

    def notify_critical_finding(
        self,
        scan_id: int,
        finding_id: Any,
        rule_id: str,
        risk_score: float,
        column_name: str,
    ) -> List[DeliveryResult]:
        return self.notify(
            WebhookEvent.CRITICAL_FINDING,
            scan_id,
            {
                "finding_id": finding_id,
                "rule_id": rule_id,
                "risk_score": risk_score,
                "column_name": column_name,
            },
        )

    def notify_compliance_violation(
        self,
        scan_id: int,
        categories: List[str],
        dpia_required: bool,
    ) -> List[DeliveryResult]:
        return self.notify(
            WebhookEvent.COMPLIANCE_VIOLATION,
            scan_id,
            {
                "categories_detected": categories,
                "dpia_required": dpia_required,
            },
        )

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def dump_registry(self) -> List[Dict[str, Any]]:
        """Serialise all registrations for external persistence."""
        result = []
        for reg in self._registry.values():
            result.append({
                "id": reg.id,
                "url": reg.url,
                "events": [e.value for e in reg.events],
                "secret": reg.secret,
                "enabled": reg.enabled,
                "description": reg.description,
                "created_at": reg.created_at.isoformat(),
                "updated_at": reg.updated_at.isoformat(),
            })
        return result

    def load_registry(self, data: List[Dict[str, Any]]) -> None:
        """Restore registrations from persisted data."""
        for item in data:
            try:
                reg = WebhookRegistration(
                    id=item["id"],
                    url=item["url"],
                    events=[WebhookEvent(e) for e in item.get("events", [])],
                    secret=item.get("secret"),
                    enabled=item.get("enabled", True),
                    description=item.get("description", ""),
                    created_at=datetime.fromisoformat(item["created_at"]),
                    updated_at=datetime.fromisoformat(item["updated_at"]),
                )
                self._registry[reg.id] = reg
            except (KeyError, ValueError) as exc:
                logger.warning("Skipping invalid webhook registration: %s", exc)
