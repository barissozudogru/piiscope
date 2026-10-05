from __future__ import annotations

import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from piiscope.remediation.masking import (
    date_shift,
    generalize_numeric,
    hash_value,
    null_value,
    partial_redact,
    tokenize_value,
)


def test_partial_redact_basic():
    assert partial_redact("secret", left=1, right=1) == "s****t"
    assert partial_redact("short", left=3, right=3) == "*****"
    assert partial_redact("", left=1, right=1) == ""
    assert partial_redact("a", left=1, right=1) == "*"


def test_partial_redact_zero_and_negative_bounds():
    # right=0 must not leak the unmasked secret
    assert partial_redact("secret123", left=2, right=0) == "se*******"
    assert partial_redact("secret123", left=0, right=2) == "*******23"
    assert partial_redact("secret123", left=0, right=0) == "*********"
    assert partial_redact("secret123", left=-1, right=-1) == "*********"
    assert partial_redact("secret123", left=2, right=-1) == "se*******"


def test_generalize_numeric_valid():
    assert generalize_numeric(27, 10) == "20-29"
    assert generalize_numeric("27", 10) == "20-29"
    assert generalize_numeric(0, 10) == "0-9"


def test_generalize_numeric_non_finite_and_invalid_buckets():
    assert generalize_numeric("nan", 10) is None
    assert generalize_numeric(float("nan"), 10) is None
    assert generalize_numeric("inf", 10) is None
    assert generalize_numeric("-inf", 10) is None
    assert generalize_numeric(math.inf, 10) is None
    assert generalize_numeric(27, 0) is None
    assert generalize_numeric(27, -5) is None
    assert generalize_numeric("not-a-number", 10) is None
    assert generalize_numeric(None, 10) is None


def test_date_shift():
    assert date_shift("2020-01-01", 30) == "2020-01-31"
    assert date_shift("2020-01-01", -1) == "2019-12-31"
    # Out of range days should not raise OverflowError
    assert date_shift("2020-01-01", 3650000) is None
    assert date_shift("not-a-date", 10) is None
    assert date_shift(None, 10) is None


def test_hash_null_and_tokenize():
    assert hash_value(None) == ""
    assert hash_value("secret") == hash_value("secret")
    assert null_value("anything") is None
    token1 = tokenize_value("secret", "salt-a")
    token2 = tokenize_value("secret", "salt-a")
    token3 = tokenize_value("secret", "salt-b")
    assert token1 == token2
    assert token1 != token3
