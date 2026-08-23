"""Data masking and pseudonymisation functions."""

from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import Any

from dateutil import parser


def hash_value(value: Any) -> str:
    """Return a SHA‑256 hash of the input value as a hex string."""
    if value is None:
        return ""
    h = hashlib.sha256()
    h.update(str(value).encode("utf-8"))
    return h.hexdigest()


def null_value(value: Any) -> None:
    """Return None, effectively removing the value."""
    return None


def partial_redact(value: str, left: int = 1, right: int = 1, mask_char: str = "*") -> str:
    """Redact the middle portion of a string, keeping left and right characters.

    If the string is shorter than left+right, it is fully replaced with
    mask characters.
    """
    s = str(value)
    if len(s) <= left + right:
        return mask_char * len(s)
    return s[:left] + (mask_char * (len(s) - left - right)) + s[-right:]


def generalize_numeric(value: Any, bucket_size: int) -> str | None:
    """Generalise a numeric value into a bucket of given size.

    Example: generalize_numeric(27, 10) -> "20-29".
    """
    try:
        num = float(value)
    except (ValueError, TypeError):
        return None
    lower = int(num // bucket_size * bucket_size)
    upper = lower + bucket_size - 1
    return f"{lower}-{upper}"


def date_shift(value: Any, days: int) -> str | None:
    """Shift a date by the given number of days.

    Returns ISO formatted date string or None if parsing fails.
    """
    try:
        dt = parser.parse(str(value))
    except (parser.ParserError, TypeError, ValueError, OverflowError):
        return None
    shifted = dt + timedelta(days=days)
    return shifted.date().isoformat()


def tokenize_value(value: Any, salt: str) -> str:
    """Tokenise a value by hashing it with a salt.

    This produces a pseudonymised value that is consistent across the
    same salt but irreversible without the salt.
    """
    h = hashlib.sha256()
    h.update(str(value).encode("utf-8"))
    h.update(salt.encode("utf-8"))
    return h.hexdigest()
