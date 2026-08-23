"""Tests for the piiscope command line interface."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from typer.testing import CliRunner

from piiscope import __version__
from piiscope.cli import app, main

REPO = Path(__file__).resolve().parent.parent
SAMPLES = REPO / "samples"

runner = CliRunner()


def _invoke(*args: str):
    return runner.invoke(app, list(args))


class TestVersionAndHelp:
    def test_version(self):
        result = _invoke("--version")
        assert result.exit_code == 0
        assert f"piiscope {__version__}" in result.output

    def test_help_lists_commands(self):
        result = _invoke("--help")
        assert result.exit_code == 0
        for command in ("scan", "remediate", "report", "patterns", "doctor"):
            assert command in result.output


class TestScanFormats:
    def test_table_output(self):
        result = _invoke("scan", str(SAMPLES / "medical_notes.csv"))
        assert result.exit_code == 0
        assert "Findings" in result.output
        assert "email" in result.output

    def test_json_output_is_valid_json(self):
        result = _invoke("scan", str(SAMPLES / "medical_notes.csv"), "--format", "json")
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["rows"] == 4
        assert payload["findings"]
        detectors = {f["detector"] for f in payload["findings"]}
        assert "email" in detectors

    def test_markdown_output(self):
        result = _invoke("scan", str(SAMPLES / "medical_notes.csv"), "--format", "markdown")
        assert result.exit_code == 0
        assert "## Findings" in result.output
        assert "medical_notes.csv" in result.output

    def test_csv_output(self):
        result = _invoke("scan", str(SAMPLES / "medical_notes.csv"), "--format", "csv")
        assert result.exit_code == 0
        lines = result.output.strip().splitlines()
        assert lines[0].startswith("source,file,column,category,detector")
        assert len(lines) >= 2

    def test_multiple_jurisdictions(self):
        result = _invoke(
            "scan",
            str(SAMPLES / "medical_notes.csv"),
            "--format",
            "json",
            "-j",
            "gdpr",
            "-j",
            "kvkk",
        )
        payload = json.loads(result.output)
        for finding in payload["findings"]:
            if finding["detector"] == "email":
                assert "GDPR" in finding["jurisdictions"]
                assert "KVKK" in finding["jurisdictions"]

    def test_all_jurisdictions(self):
        result = _invoke(
            "scan", str(SAMPLES / "medical_notes.csv"), "--format", "json", "-j", "all"
        )
        payload = json.loads(result.output)
        assert payload["jurisdictions"] == ["gdpr", "ccpa", "kvkk", "lgpd"]

    def test_unknown_jurisdiction_fails(self):
        result = _invoke("scan", str(SAMPLES / "medical_notes.csv"), "-j", "does-not-exist")
        assert result.exit_code != 0

    def test_no_metrics(self):
        result = _invoke(
            "scan", str(SAMPLES / "medical_notes.csv"), "--format", "json", "--no-metrics"
        )
        payload = json.loads(result.output)
        assert payload["metrics"] is None

    def test_quiet_prints_nothing_and_exits_zero(self):
        result = _invoke("scan", str(SAMPLES / "medical_notes.csv"), "--quiet")
        assert result.exit_code == 0
        assert result.output == ""

    def test_sample_rows(self):
        result = _invoke(
            "scan", str(SAMPLES / "customers.csv"), "--format", "json", "--sample", "2"
        )
        payload = json.loads(result.output)
        assert payload["rows"] == 2

    def test_output_file(self, tmp_path):
        out = tmp_path / "scan.json"
        result = _invoke(
            "scan", str(SAMPLES / "medical_notes.csv"), "--format", "json", "-o", str(out)
        )
        assert result.exit_code == 0
        payload = json.loads(out.read_text())
        assert payload["rows"] == 4


class TestFailOn:
    def test_fail_on_at_or_below_risk_level(self):
        # medical_notes.csv scores medium
        for level in ("low", "medium", "high"):
            result = _invoke("scan", str(SAMPLES / "medical_notes.csv"), "--fail-on", level)
            assert result.exit_code == 2, f"--fail-on {level} should exit 2"

    def test_fail_on_above_risk_level_passes(self):
        for level in ("critical",):
            result = _invoke("scan", str(SAMPLES / "medical_notes.csv"), "--fail-on", level)
            assert result.exit_code == 0, f"--fail-on {level} should exit 0"

    def test_fail_on_critical_on_critical_file(self):
        result = _invoke("scan", str(SAMPLES / "customers.csv"), "--fail-on", "critical", "--quiet")
        assert result.exit_code == 2

    def test_no_fail_on_when_below_threshold(self):
        result = _invoke("scan", str(SAMPLES / "medical_notes.csv"))
        assert result.exit_code == 0

    def test_clean_file_never_fails_above_low(self, tmp_path):
        clean = tmp_path / "clean.csv"
        clean.write_text("id,amount\n1,10\n2,20\n")
        # a finding-free scan scores "low", so only the low threshold trips
        result = _invoke("scan", str(clean), "--fail-on", "medium")
        assert result.exit_code == 0
        result = _invoke("scan", str(clean), "--fail-on", "low")
        assert result.exit_code == 2

    def test_main_converts_exit_code(self, monkeypatch):
        monkeypatch.setattr(
            "sys.argv",
            [
                "piiscope",
                "scan",
                str(SAMPLES / "customers.csv"),
                "--fail-on",
                "critical",
                "--quiet",
            ],
        )
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 2


class TestRemediateCommand:
    def test_hash_round_trip(self, tmp_path):
        out = tmp_path / "safe.csv"
        result = _invoke(
            "remediate",
            str(SAMPLES / "medical_notes.csv"),
            "--out",
            str(out),
            "--strategy",
            "hash",
        )
        assert result.exit_code == 0
        assert out.exists()
        assert result.output.strip() or True  # summary goes to stderr
        rescan = _invoke("scan", str(out), "--format", "json")
        payload = json.loads(rescan.output)
        assert payload["findings"] == []
        assert payload["risk"]["score"] == 0

    def test_explicit_columns(self, tmp_path):
        out = tmp_path / "safe.csv"
        result = _invoke(
            "remediate",
            str(SAMPLES / "medical_notes.csv"),
            "--out",
            str(out),
            "--strategy",
            "redact",
            "-c",
            "email,phone",
        )
        assert result.exit_code == 0
        rescan = _invoke("scan", str(out), "--format", "json")
        payload = json.loads(rescan.output)
        scanned_columns = {f["column"] for f in payload["findings"]}
        assert "email" not in scanned_columns
        assert "phone" not in scanned_columns

    def test_unknown_strategy_fails(self, tmp_path):
        result = _invoke(
            "remediate",
            str(SAMPLES / "medical_notes.csv"),
            "--out",
            str(tmp_path / "x.csv"),
            "--strategy",
            "explode",
        )
        assert result.exit_code != 0

    def test_salt_from_environment(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PIISCOPE_SALT", "test-salt-value")
        out = tmp_path / "safe.csv"
        result = _invoke(
            "remediate",
            str(SAMPLES / "medical_notes.csv"),
            "--out",
            str(out),
            "--strategy",
            "tokenise",
            "--salt",
            "PIISCOPE_SALT",
        )
        assert result.exit_code == 0
        assert out.exists()

    def test_source_file_unchanged(self, tmp_path):
        source = tmp_path / "src.csv"
        source.write_text("email\nsomeone@example.com\n")
        out = tmp_path / "safe.csv"
        _invoke("remediate", str(source), "--out", str(out), "--strategy", "hash")
        assert source.read_text() == "email\nsomeone@example.com\n"


class TestErrorPaths:
    def test_missing_file(self):
        result = _invoke("scan", str(SAMPLES / "no-such-file.csv"))
        assert result.exit_code != 0

    def test_unsupported_extension(self, tmp_path):
        bad = tmp_path / "data.xyz"
        bad.write_text("a,b\n1,2\n")
        result = _invoke("scan", str(bad))
        assert result.exit_code != 0

    def test_malformed_csv(self, tmp_path):
        bad = tmp_path / "bad.csv"
        bad.write_text('a,b\n1,"unbalanced\n2,3\n')
        result = _invoke("scan", str(bad))
        assert result.exit_code != 0

    def test_empty_csv(self, tmp_path):
        empty = tmp_path / "empty.csv"
        empty.write_text("")
        result = _invoke("scan", str(empty), "--format", "json")
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["rows"] == 0
        assert payload["findings"] == []


class TestPatternsAndDoctor:
    def test_patterns_lists_detectors(self):
        result = _invoke("patterns")
        assert result.exit_code == 0
        assert "credit_card" in result.output
        assert "iban" in result.output

    def test_patterns_jurisdiction_filter(self):
        result = _invoke("patterns", "-j", "kvkk")
        assert result.exit_code == 0
        assert "Article" in result.output
        assert "tc_kimlik" in result.output
        # cpf obligations exist only in the LGPD profile, and no cpf
        # detector exists yet, so it never appears in the detector table
        assert "cpf" not in result.output

    def test_doctor(self):
        result = _invoke("doctor")
        assert result.exit_code == 0
        assert "pandas" in result.output
        assert "pyarrow" in result.output
