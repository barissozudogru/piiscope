"""Custom exceptions for the privacy risk detection application.

This module defines application-specific exceptions that provide better
error handling and more informative error messages throughout the system.
"""

from __future__ import annotations

from typing import Any


class BasePrivacyException(Exception):
    """Base exception for all privacy detection related errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class AuthenticationError(BasePrivacyException):
    """Raised when authentication fails."""

    pass


class AuthorizationError(BasePrivacyException):
    """Raised when user doesn't have required permissions."""

    pass


class ValidationError(BasePrivacyException):
    """Raised when input validation fails."""

    pass


class FileProcessingError(BasePrivacyException):
    """Raised when file processing fails."""

    pass


class DetectionEngineError(BasePrivacyException):
    """Raised when detection engine encounters an error."""

    pass


class DatabaseError(BasePrivacyException):
    """Raised when database operations fail."""

    pass


class ConfigurationError(BasePrivacyException):
    """Raised when configuration is invalid."""

    pass


class ResourceNotFoundError(BasePrivacyException):
    """Raised when a requested resource is not found."""

    pass


class ConcurrencyError(BasePrivacyException):
    """Raised when concurrent operations conflict."""

    pass


class QuotaExceededError(BasePrivacyException):
    """Raised when resource quotas are exceeded."""

    pass
