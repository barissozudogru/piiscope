"""Exception hierarchy for piiscope.

Every error raised intentionally by the library derives from
:class:`PiiscopeError`, so callers can catch a single type.
"""

from __future__ import annotations


class PiiscopeError(Exception):
    """Base class for all piiscope errors."""


class UnsupportedFormatError(PiiscopeError):
    """Raised when a source has no reader (for example an unknown extension)."""


class FileReadError(PiiscopeError):
    """Raised when a source cannot be read (missing, binary, too large)."""


class RemediationError(PiiscopeError):
    """Raised when a remediation strategy cannot be applied."""
