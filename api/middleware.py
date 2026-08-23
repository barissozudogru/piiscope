"""Middleware for the privacy risk detection application.

This module implements security, rate limiting, and monitoring middleware
to protect the application and provide observability.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from .config import settings
from .logging_config import log_performance_metric, log_security_event


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        if settings.enable_security_headers:
            # Prevent clickjacking
            response.headers["X-Frame-Options"] = "DENY"

            # Prevent MIME sniffing
            response.headers["X-Content-Type-Options"] = "nosniff"

            # XSS protection
            response.headers["X-XSS-Protection"] = "1; mode=block"

            # Referrer policy
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

            # Content Security Policy
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "connect-src 'self'; "
                "font-src 'self'; "
                "object-src 'none'; "
                "media-src 'self'; "
                "frame-src 'none'; "
            )

            # Strict Transport Security (HTTPS only)
            if request.url.scheme == "https":
                response.headers["Strict-Transport-Security"] = (
                    "max-age=31536000; includeSubDomains"  # noqa: E501
                )

        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiting middleware.

    Memory is bounded by ``_max_tracked_ips``.  When the table reaches that
    cap, all entries whose sliding window has expired are purged before a new
    IP is inserted.  If the table is still at capacity after the purge (i.e.
    every tracked IP has active recent traffic), the oldest half of entries is
    evicted so the dict never grows without bound.

    A lightweight periodic cleanup runs every ``_cleanup_interval`` seconds so
    that stale IPs from bursty-but-inactive clients are reclaimed even without
    hitting the cap.
    """

    _max_tracked_ips: int = 10_000
    _cleanup_interval: float = 300.0  # 5 minutes

    def __init__(self, app: FastAPI):
        super().__init__(app)
        self.requests: dict = {}  # {client_ip: [(timestamp, count), ...]}
        self.window_size = 60  # 1 minute
        self.max_requests = settings.rate_limit_per_minute
        self._last_cleanup: float = time.time()

    def get_client_ip(self, request: Request) -> str:
        """Get client IP address, handling proxies."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _purge_stale(self, now: float) -> None:
        """Remove all IPs whose sliding window is completely empty."""
        stale = [
            ip
            for ip, entries in self.requests.items()
            if not any(now - ts < self.window_size for ts, _ in entries)
        ]
        for ip in stale:
            del self.requests[ip]

    def _maybe_periodic_cleanup(self, now: float) -> None:
        """Run a full stale-entry sweep on a fixed interval."""
        if now - self._last_cleanup >= self._cleanup_interval:
            self._purge_stale(now)
            self._last_cleanup = now

    def _enforce_cap(self, now: float) -> None:
        """Ensure the tracked-IPs dict stays within ``_max_tracked_ips``."""
        if len(self.requests) < self._max_tracked_ips:
            return
        # First pass: remove genuinely stale entries.
        self._purge_stale(now)
        # Second pass: if still at cap, evict the oldest half by last-seen time.
        if len(self.requests) >= self._max_tracked_ips:
            sorted_ips = sorted(
                self.requests.keys(),
                key=lambda ip: max(ts for ts, _ in self.requests[ip]),
            )
            for ip in sorted_ips[: len(sorted_ips) // 2]:
                del self.requests[ip]

    def is_rate_limited(self, client_ip: str) -> bool:
        """Check if client is rate limited."""
        now = time.time()

        self._maybe_periodic_cleanup(now)

        # Clean old entries for this IP.
        if client_ip in self.requests:
            self.requests[client_ip] = [
                (timestamp, count)
                for timestamp, count in self.requests[client_ip]
                if now - timestamp < self.window_size
            ]

        # Count requests in current window.
        current_requests = sum(count for timestamp, count in self.requests.get(client_ip, []))

        if current_requests >= self.max_requests:
            return True

        # Enforce cap before inserting a new IP.
        if client_ip not in self.requests:
            self._enforce_cap(now)
            self.requests[client_ip] = []
        self.requests[client_ip].append((now, 1))

        return False

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = self.get_client_ip(request)

        if self.is_rate_limited(client_ip):
            log_security_event(
                "Rate limit exceeded", ip_address=client_ip, endpoint=str(request.url)
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many requests"
            )

        return await call_next(request)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log request and response details for monitoring."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        start_time = time.time()
        client_ip = self.get_client_ip(request)

        # Log request
        log_performance_metric(
            "http_request_started",
            1,
            method=request.method,
            path=request.url.path,
            client_ip=client_ip,
            request_id=request_id,
        )

        try:
            response = await call_next(request)

            # Calculate processing time
            processing_time = time.time() - start_time

            # Log response
            log_performance_metric(
                "http_request_duration",
                processing_time,
                unit="seconds",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                client_ip=client_ip,
                request_id=request_id,
            )

            # Add request ID to response headers for debugging
            response.headers["X-Request-ID"] = request_id

            return response

        except Exception as e:
            # Log error
            processing_time = time.time() - start_time
            log_performance_metric(
                "http_request_error",
                1,
                error_type=type(e).__name__,
                method=request.method,
                path=request.url.path,
                processing_time=processing_time,
                client_ip=client_ip,
                request_id=request_id,
            )
            raise

    def get_client_ip(self, request: Request) -> str:
        """Get client IP address, handling proxies."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"


def setup_middleware(app: FastAPI) -> None:
    """Set up all middleware for the application."""

    # CORS middleware (must be first)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Trusted host middleware
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"],  # Configure appropriately for production
    )

    # Session middleware (if needed)
    # app.add_middleware(SessionMiddleware, secret_key=settings.jwt_secret_key)

    # Custom middleware (order matters - last added is executed first)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
