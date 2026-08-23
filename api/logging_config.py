"""Logging configuration for the privacy risk detection application.

This module sets up structured logging with appropriate formatters,
handlers, and security considerations for audit trails.
"""

from __future__ import annotations

import logging
import logging.config
import os
import sys
from typing import Any

from .config import settings


def _resolve_log_dir() -> str | None:
    """Return a writable log directory, or None to log to the console only.

    The directory comes from the LOG_DIR setting (default "logs", relative to
    the working directory). Containers running as a non-root user or read-only
    filesystems must not crash the application at startup because of logging.
    """
    log_dir = getattr(settings, "log_dir", None) or os.environ.get("LOG_DIR", "logs")
    try:
        os.makedirs(log_dir, exist_ok=True)
    except OSError:
        return None
    if not os.access(log_dir, os.W_OK):
        return None
    return log_dir


def setup_logging() -> None:
    """Configure logging for the application."""
    log_dir = _resolve_log_dir()
    log_dir_for_paths = log_dir or "logs"

    log_config: dict[str, Any] = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {
                "format": '{"timestamp": "%(asctime)s", "name": "%(name)s", "level": "%(levelname)s", "message": "%(message)s", "module": "%(module)s", "function": "%(funcName)s", "line": %(lineno)d}',  # noqa: E501
                "datefmt": "%Y-%m-%dT%H:%M:%S%z",
            },
            "standard": {
                "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s (%(filename)s:%(lineno)d)",  # noqa: E501
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
            "detailed": {
                "format": "%(asctime)s [%(levelname)s] %(name)s in %(funcName)s (%(filename)s:%(lineno)d): %(message)s",  # noqa: E501
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": settings.log_level,
                "formatter": settings.log_format,
                "stream": sys.stdout,
            },
            "security": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "WARNING",
                "formatter": "json",
                "filename": os.path.join(log_dir_for_paths, "security.log"),
                "maxBytes": 10485760,  # 10MB
                "backupCount": 5,
                "mode": "a",
            },
            "audit": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "INFO",
                "formatter": "json",
                "filename": os.path.join(log_dir_for_paths, "audit.log"),
                "maxBytes": 10485760,  # 10MB
                "backupCount": 10,
                "mode": "a",
            },
            "performance": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "DEBUG",
                "formatter": "json",
                "filename": os.path.join(log_dir_for_paths, "performance.log"),
                "maxBytes": 10485760,  # 10MB
                "backupCount": 3,
                "mode": "a",
            },
        },
        "loggers": {
            "": {  # Root logger
                "level": settings.log_level,
                "handlers": ["console"],
                "propagate": False,
            },
            "security": {
                "level": "WARNING",
                "handlers": ["security", "console"],
                "propagate": False,
            },
            "audit": {"level": "INFO", "handlers": ["audit", "console"], "propagate": False},
            "performance": {"level": "DEBUG", "handlers": ["performance"], "propagate": False},
            "uvicorn": {"level": "INFO", "handlers": ["console"], "propagate": False},
            "sqlalchemy.engine": {"level": "WARNING", "handlers": ["console"], "propagate": False},
        },
    }

    if log_dir is None:
        # Log directory not writable: drop file handlers, keep console output.
        file_handlers = [n for n, h in log_config["handlers"].items() if "filename" in h]
        for name in file_handlers:
            del log_config["handlers"][name]
        for logger_cfg in log_config["loggers"].values():
            kept = [h for h in logger_cfg["handlers"] if h not in file_handlers]
            logger_cfg["handlers"] = kept or ["console"]

    logging.config.dictConfig(log_config)


class SecurityFilter(logging.Filter):
    """Filter to add security context to log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        # Add security-related metadata
        record.security_event = getattr(record, "security_event", False)
        record.user_id = getattr(record, "user_id", None)
        record.ip_address = getattr(record, "ip_address", None)
        return True


class AuditFilter(logging.Filter):
    """Filter for audit trail logs."""

    def filter(self, record: logging.LogRecord) -> bool:
        # Only log messages that are explicitly marked as audit events
        return getattr(record, "audit_event", False)


def get_security_logger() -> logging.Logger:
    """Get logger for security events."""
    logger = logging.getLogger("security")
    logger.addFilter(SecurityFilter())
    return logger


def get_audit_logger() -> logging.Logger:
    """Get logger for audit trail."""
    logger = logging.getLogger("audit")
    logger.addFilter(AuditFilter())
    return logger


def get_performance_logger() -> logging.Logger:
    """Get logger for performance metrics."""
    return logging.getLogger("performance")


def log_security_event(message: str, user_id: int = None, ip_address: str = None, **kwargs):
    """Log a security-related event."""
    logger = get_security_logger()
    extra = {"security_event": True, "user_id": user_id, "ip_address": ip_address, **kwargs}
    logger.warning(message, extra=extra)


def log_audit_event(
    action: str, user_id: int, target: str = None, details: dict[str, Any] = None, **kwargs
):  # noqa: E501
    """Log an audit trail event."""
    logger = get_audit_logger()
    extra = {
        "audit_event": True,
        "user_id": user_id,
        "action": action,
        "target": target,
        "details": details or {},
        **kwargs,
    }
    logger.info(f"Audit: {action}", extra=extra)


def log_performance_metric(metric_name: str, value: float, unit: str = None, **kwargs):
    """Log a performance metric."""
    logger = get_performance_logger()
    extra = {"metric_name": metric_name, "value": value, "unit": unit, **kwargs}
    logger.debug(f"Performance: {metric_name}={value}{unit or ''}", extra=extra)
