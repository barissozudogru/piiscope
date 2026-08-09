import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from api.validators import validate_email
from api.exceptions import ValidationError

def test_validate_email_strips_whitespace():
    assert validate_email(" test@example.com ") == "test@example.com"
    assert validate_email("\tuser@domain.co.uk\n") == "user@domain.co.uk"
    
def test_validate_email_invalid():
    with pytest.raises(ValidationError):
        validate_email("invalid-email")
