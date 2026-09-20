"""Round-trip tests: remediating a file must remove its findings."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from piiscope import scan
from piiscope.errors import RemediationError
from piiscope.remediation import apply_strategy, remediate, remediate_frame
from piiscope.remediation.strategies import columns_with_findings

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

# Strategies whose output must scan clean; date-shift honestly shifts dates
# so a date finding survives by design and is tested separately.
CLEAN_STRATEGIES = ("hash", "redact", "null", "generalise", "tokenise")


def _sample_frame() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "name": ["Anna Schmidt", "John Carter"],
            "email": ["anna@example.com", "john@example.org"],
            "phone": ["+49 170 1234567", "(212) 555-0134"],
            "iban": ["DE96724049984426097509", "GB29NWBK60161331926819"],
            "birth_date": ["1985-06-15", "1982-09-30"],
            "credit_card": ["4111111111111111", "5500005555555559"],
            "notes": ["Type 2 diabetes, Metformin", "Back pain follow-up"],
        }
    )


@pytest.mark.parametrize("strategy", CLEAN_STRATEGIES)
def test_round_trip_file_has_zero_findings(strategy, tmp_path):
    source = tmp_path / "in.csv"
    _sample_frame().to_csv(source, index=False)
    out = tmp_path / "out.csv"
    result = remediate(source, out, strategy=strategy, salt="fixed-salt")
    assert result.rows == 2
    assert result.columns_changed
    rescan = scan(out)
    assert rescan.findings == [], (
        f"{strategy} output still triggers detectors: "
        f"{[(f.column, f.detector) for f in rescan.findings]}"
    )


def test_date_shift_changes_dates_but_keeps_them_dates(tmp_path):
    source = tmp_path / "in.csv"
    _sample_frame().to_csv(source, index=False)
    out = tmp_path / "out.csv"
    remediate(source, out, strategy="date-shift", shift_days=30)
    original = pd.read_csv(source)
    shifted = pd.read_csv(out)
    assert not (original["birth_date"] == shifted["birth_date"]).all()
    rescan = scan(out)
    date_findings = [f for f in rescan.findings if f.column == "birth_date"]
    assert date_findings, "shifted dates should still be recognisable as dates"


def test_apply_strategy_on_dataframe():
    frame = _sample_frame()
    changed, _ = apply_strategy(frame, strategy="hash", columns=["email", "iban"])
    assert changed == {"email": 2, "iban": 2}
    assert frame["email"].iloc[0].startswith(tuple("0123456789abcdef"))
    assert "@" not in frame["email"].iloc[0]


def test_apply_strategy_rejects_unknown_column():
    frame = _sample_frame()
    with pytest.raises(RemediationError):
        apply_strategy(frame, strategy="hash", columns=["not-a-column"])


def test_apply_strategy_rejects_unknown_strategy():
    frame = _sample_frame()
    with pytest.raises(RemediationError):
        apply_strategy(frame, strategy="explode", columns=["email"])


def test_tokenise_is_stable_per_salt():
    frame_one = _sample_frame()
    frame_two = _sample_frame()
    apply_strategy(frame_one, strategy="tokenise", columns=["email"], salt="salt-a")
    apply_strategy(frame_two, strategy="tokenise", columns=["email"], salt="salt-a")
    assert frame_one["email"].equals(frame_two["email"])
    frame_other = _sample_frame()
    apply_strategy(frame_other, strategy="tokenise", columns=["email"], salt="salt-b")
    assert not frame_one["email"].equals(frame_other["email"])


def test_redact_shortens_values():
    frame = _sample_frame()
    apply_strategy(frame, strategy="redact", columns=["email"])
    original = _sample_frame()["email"]
    assert (frame["email"].str.len() <= original.str.len()).all()
    assert "@" not in "".join(frame["email"])


def test_null_clears_values():
    frame = _sample_frame()
    apply_strategy(frame, strategy="null", columns=["credit_card"])
    assert frame["credit_card"].eq("").all()


def test_generalise_buckets_numbers_and_years():
    frame = pd.DataFrame({"age": ["34", "67"], "dob": ["1985-06-15", "1955-02-01"]})
    apply_strategy(frame, strategy="generalise", columns=["age", "dob"], bucket_size=10)
    assert frame["age"].tolist() == ["30-39", "60-69"]
    assert frame["dob"].tolist() == ["1985", "1955"]


def test_columns_with_findings_uses_scan():
    source = SAMPLES / "medical_notes.csv"
    columns = columns_with_findings(source)
    assert "email" in columns
    assert "patient_id" not in columns


def test_remediate_frame_scans_when_columns_missing():
    frame = _sample_frame()
    changed, _ = remediate_frame(frame, strategy="hash", salt="s")
    for column in ("name", "email", "phone", "iban", "birth_date", "credit_card"):
        assert column in changed


def test_remediated_output_matches_extension(tmp_path):
    source = tmp_path / "in.csv"
    _sample_frame().to_csv(source, index=False)
    out = tmp_path / "out.jsonl"
    remediate(source, out, strategy="hash", columns=["email"])
    lines = out.read_text().strip().splitlines()
    assert len(lines) == 2
    assert '"email"' in lines[0]


def test_remediate_json_with_null_values(tmp_path):
    source = tmp_path / "in.json"
    source.write_text('[{"email": "test@example.com"}, {"email": null}]')
    out = tmp_path / "out.json"
    result = remediate(source, out, strategy="hash", columns=["email"])
    assert result.columns_changed == {"email": 1}
    frame = pd.read_json(out)
    assert frame["email"].iloc[0] != ""
    assert frame["email"].iloc[1] == ""


def test_remediate_parquet_with_null_values(tmp_path):
    pytest.importorskip("pyarrow")
    source = tmp_path / "in.parquet"
    pd.DataFrame({"email": ["test@example.com", None]}).to_parquet(source)
    out = tmp_path / "out.parquet"
    result = remediate(source, out, strategy="hash", columns=["email"])
    assert result.columns_changed == {"email": 1}
    frame = pd.read_parquet(out)
    assert frame["email"].iloc[0] != ""
    assert frame["email"].iloc[1] == ""


def test_generalise_handles_nan_and_non_finite_values():
    frame = pd.DataFrame({"age": ["25", "nan", "inf", ""]})
    changed, _ = apply_strategy(frame, strategy="generalise", columns=["age"], bucket_size=10)
    assert changed["age"] == 3
    assert frame["age"].iloc[0] == "20-29"
    assert frame["age"].iloc[1] == "n*n"
    assert frame["age"].iloc[2] == "i*f"
    assert frame["age"].iloc[3] == ""
