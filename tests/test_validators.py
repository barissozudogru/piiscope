import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from api.validators import validate_email, validate_password
from api.exceptions import ValidationError

def test_validate_email_strips_whitespace():
    assert validate_email(" test@example.com ") == "test@example.com"
    assert validate_email("\tuser@domain.co.uk\n") == "user@domain.co.uk"
    
def test_validate_email_invalid():
    with pytest.raises(ValidationError):
        validate_email("invalid-email")


def test_validate_password_valid():
    # Common special characters should be accepted
    assert validate_password("Password_123") == "Password_123"
    assert validate_password("Strong-Pass1") == "Strong-Pass1"
    assert validate_password("Valid123!") == "Valid123!"

def test_validate_password_missing_special():
    with pytest.raises(ValidationError, match="least one special character"):
        validate_password("NoSpecial123")

def test_validate_password_missing_digit():
    with pytest.raises(ValidationError, match="least one digit"):
        validate_password("NoDigit_Here!")
