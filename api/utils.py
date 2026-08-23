"""Utility functions for security, encryption and common helpers."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import UploadFile
from jose import jwt

from .config import settings
from .exceptions import ConfigurationError, ValidationError

# bcrypt cost factor for password hashing
_BCRYPT_ROUNDS = 12


def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt with a strong cost factor."""
    if not password:
        raise ValueError("Password cannot be empty")
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=_BCRYPT_ROUNDS))
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its bcrypt hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except ValueError:
        return False


def generate_secure_random_string(length: int = 32) -> str:
    """Generate a cryptographically secure random string."""
    return secrets.token_urlsafe(length)


def generate_api_key() -> str:
    """Generate a secure API key."""
    return f"pk_{generate_secure_random_string(32)}"


def hash_sensitive_data(data: str, salt: bytes | None = None) -> tuple[str, bytes]:
    """Hash sensitive data with a salt for storage."""
    if salt is None:
        salt = os.urandom(32)

    # Use PBKDF2 for hashing sensitive data
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    hashed = kdf.derive(data.encode("utf-8"))
    return base64.urlsafe_b64encode(hashed).decode("utf-8"), salt


def create_access_token(data: dict[str, Any], expires_delta: timedelta) -> str:
    """Create a JWT access token containing the given data.

    :param data: Dictionary of claims to include in the token.
    :param expires_delta: Token validity period.
    :return: Encoded JWT string.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt


def _get_fernet() -> Fernet:
    """Return a Fernet cipher initialised from settings.encryption_key."""
    try:
        return Fernet(settings.encryption_key.encode())
    except Exception as e:
        raise ConfigurationError(f"Invalid encryption key: {str(e)}") from e


def encrypt_value(value: str) -> str:
    """Encrypt a string value using Fernet and return the token as a string."""
    try:
        fernet = _get_fernet()
        return fernet.encrypt(value.encode()).decode()
    except ConfigurationError:
        raise
    except Exception as e:
        raise ConfigurationError(f"Failed to encrypt value: {str(e)}") from e


def decrypt_value(token: str) -> str:
    """Decrypt a Fernet token and return the original string."""
    try:
        fernet = _get_fernet()
        return fernet.decrypt(token.encode()).decode()
    except ConfigurationError:
        raise
    except Exception as e:
        raise ConfigurationError(f"Failed to decrypt value: {str(e)}") from e


def encrypt_bytes(data: bytes) -> bytes:
    """Encrypt bytes using Fernet.  Returns the Fernet token as bytes."""
    try:
        fernet = _get_fernet()
        return fernet.encrypt(data)
    except ConfigurationError:
        raise
    except Exception as e:
        raise ConfigurationError(f"Failed to encrypt data: {str(e)}") from e


def decrypt_bytes(data: bytes) -> bytes:
    """Decrypt bytes produced by `encrypt_bytes`."""
    try:
        fernet = _get_fernet()
        return fernet.decrypt(data)
    except ConfigurationError:
        raise
    except Exception as e:
        raise ConfigurationError(f"Failed to decrypt data: {str(e)}") from e


def secure_compare(a: str, b: str) -> bool:
    """Timing-safe string comparison."""
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def sanitize_for_log(data: str, max_length: int = 100) -> str:
    """Sanitize data for safe logging (remove sensitive info, truncate)."""
    try:
        from piiscope.detection.regex_patterns import PATTERNS

        # Mapping of pattern keys to log replacements
        # emails, phone numbers, IBANs, card numbers and national ids
        replacements = {
            "email": "[EMAIL]",
            "credit_card": "[CREDIT_CARD]",
            "iban": "[IBAN]",
            "tc_kimlik": "[NATIONAL_ID]",
            "national_id": "[NATIONAL_ID]",
            "us_ssn": "[NATIONAL_ID]",
            "eu_phone": "[PHONE]",
            "us_phone": "[PHONE]",
            "tr_phone": "[PHONE]",
            "tr_phone_strict": "[PHONE]",
        }

        for rule_id, replacement in replacements.items():
            if rule_id in PATTERNS:
                # PATTERNS[rule_id].pattern is a compiled regex
                data = PATTERNS[rule_id].pattern.sub(replacement, data)
    except ImportError:
        pass  # Fallback if piiscope isn't available

    if len(data) > max_length:
        data = data[:max_length] + "..."

    return data


def validate_file_hash(file_path: str, expected_hash: str, algorithm: str = "sha256") -> bool:
    """Validate file integrity using hash comparison."""
    hash_func = getattr(hashlib, algorithm, None)
    if not hash_func:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    hasher = hash_func()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)

    return secure_compare(hasher.hexdigest(), expected_hash)


def read_json_file(path: str) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_json_file(path: str, obj: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


async def stream_upload_to_disk(file: UploadFile, file_path: str, max_bytes: int) -> None:
    """Stream an uploaded file to disk, enforcing a maximum size limit.

    Aborts and removes the partial file if the limit is exceeded.
    """
    received = 0
    with open(file_path, "wb") as out_file:
        chunk_size = 1024 * 1024  # 1 MB chunks
        while True:
            chunk = await file.read(chunk_size)
            if not chunk:
                break
            received += len(chunk)
            if received > max_bytes:
                out_file.close()
                os.remove(file_path)
                raise ValidationError(f"File size exceeds max {max_bytes // (1024 * 1024)} MB")
            out_file.write(chunk)
