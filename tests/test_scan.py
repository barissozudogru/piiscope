from __future__ import annotations

import pandas as pd

from piiscope.scan import scan


def test_scan_dataframe_without_sample_rows():
    df = pd.DataFrame({"email": [f"user{i}@example.com" for i in range(20)]})
    result = scan(df)
    assert result.rows == 20
    assert len(result.findings) == 1
    assert result.findings[0].count == 20


def test_scan_dataframe_with_sample_rows():
    df = pd.DataFrame({"email": [f"user{i}@example.com" for i in range(50)]})
    result = scan(df, sample_rows=10)
    assert result.rows == 10
    assert len(result.findings) == 1
    assert result.findings[0].count == 10


def test_scan_dataframe_sample_rows_zero():
    df = pd.DataFrame({"email": [f"user{i}@example.com" for i in range(10)]})
    result = scan(df, sample_rows=0)
    assert result.rows == 0
    assert result.findings == []
    assert result.risk.score == 0


def test_scan_dataframe_sample_rows_negative():
    df = pd.DataFrame({"email": [f"user{i}@example.com" for i in range(10)]})
    result = scan(df, sample_rows=-5)
    assert result.rows == 0
    assert result.findings == []
    assert result.risk.score == 0


def test_scan_dataframe_sample_rows_exceeding_length():
    df = pd.DataFrame({"email": [f"user{i}@example.com" for i in range(5)]})
    result = scan(df, sample_rows=50)
    assert result.rows == 5
    assert result.findings[0].count == 5


def test_scan_dataframe_sample_rows_with_metrics():
    df = pd.DataFrame(
        {
            "age": [20 + (i % 5) for i in range(50)],
            "email": [f"user{i}@example.com" for i in range(50)],
        }
    )
    result = scan(df, sample_rows=10, quasi_identifiers=["age"])
    assert result.rows == 10
    assert result.metrics is not None
    assert result.metrics.k_anonymity is not None
