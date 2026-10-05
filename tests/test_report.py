import json
from pathlib import Path

import pytest

from piiscope.errors import PiiscopeError
from piiscope.report.renderers import render_html, render_json, render_markdown, write_report
from piiscope.report.sarif import render_sarif
from piiscope.scan import Finding, MetricsResult, RiskScore, ScanResult


def test_render_markdown_empty_findings():
    result = ScanResult(
        source="test.csv",
        rows=10,
        columns=2,
        findings=[],
        jurisdictions=["gdpr"],
        scan_time=0.1,
        metrics=None,
        risk=RiskScore(score=0.0, level="low", drivers=[])
    )
    md = render_markdown(result)
    assert "piiscope report" in md
    assert "No personal data findings." in md
    assert "No metrics computed" in md

def test_render_markdown_with_findings_and_metrics():
    result = ScanResult(
        source="data.csv",
        rows=100,
        columns=5,
        findings=[
            Finding(
                column="email",
                category="contact",
                detector="email",
                count=100,
                confidence=1.0,
                severity=0.5,
                samples_redacted=["a***@b.com"],
                jurisdictions=["gdpr"]
            )
        ],
        jurisdictions=["gdpr"],
        scan_time=0.5,
        metrics=MetricsResult(
            quasi_identifiers=["age"],
            sensitive_attribute="health",
            k_anonymity=5,
            l_diversity=2,
            t_closeness=0.5
        ),
        risk=RiskScore(score=50.0, level="high", drivers=["email"])
    )
    md = render_markdown(result)
    assert "| email | contact | email | 100 | 1.00 | gdpr |" in md
    assert "Top drivers:" in md
    assert "- email" in md
    assert "| k-anonymity | 5 |" in md

def test_render_sarif_empty_findings():
    result = ScanResult(
        source="test.csv",
        rows=10,
        columns=2,
        findings=[],
        jurisdictions=["gdpr"],
        scan_time=0.1,
        metrics=None,
        risk=RiskScore(score=0.0, level="low", drivers=[])
    )
    sarif_str = render_sarif([result])
    sarif = json.loads(sarif_str)
    assert sarif["runs"][0]["results"] == []

def test_render_sarif_with_findings():
    result = ScanResult(
        source="data.csv",
        rows=100,
        columns=5,
        findings=[
            Finding(
                column="email",
                category="contact",
                detector="email",
                count=100,
                confidence=1.0,
                severity=0.5,
                samples_redacted=["a***@b.com"],
                jurisdictions=["gdpr"],
                file="data.csv"
            )
        ],
        jurisdictions=["gdpr"],
        scan_time=0.5,
        metrics=None,
        risk=RiskScore(score=50.0, level="high", drivers=["email"])
    )
    sarif_str = render_sarif([result])
    sarif = json.loads(sarif_str)
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["results"][0]["ruleId"] == "email"


def test_render_json():
    result = ScanResult(
        source="test.csv",
        rows=10,
        columns=2,
        findings=[],
        jurisdictions=["gdpr"],
        scan_time=0.1,
        metrics=None,
        risk=RiskScore(score=0.0, level="low", drivers=[]),
    )
    data = json.loads(render_json(result))
    assert data["source"] == "test.csv"
    assert data["rows"] == 10
    assert data["findings"] == []


def test_render_html():
    result = ScanResult(
        source="data.csv",
        rows=50,
        columns=3,
        findings=[
            Finding(
                column="email",
                category="contact",
                detector="email",
                count=5,
                confidence=0.95,
                severity=0.5,
                samples_redacted=["u***@x.com"],
                jurisdictions=["gdpr"],
            )
        ],
        jurisdictions=["gdpr"],
        scan_time=0.25,
        metrics=None,
        risk=RiskScore(score=25.0, level="medium", drivers=["email"]),
    )
    html_text = render_html(result)
    assert "<!DOCTYPE html>" in html_text
    assert "data.csv" in html_text
    assert "email" in html_text
    assert "medium" in html_text


def test_write_report_with_path_and_str(tmp_path):
    result = ScanResult(
        source="data.csv",
        rows=10,
        columns=2,
        findings=[],
        jurisdictions=["gdpr"],
        scan_time=0.1,
        metrics=None,
        risk=RiskScore(score=0.0, level="low", drivers=[]),
    )
    # Using Path object
    out_md = tmp_path / "report.md"
    write_report(result, out_md)
    assert out_md.exists()
    assert "piiscope report" in out_md.read_text()

    # Using str path
    out_html = str(tmp_path / "report.html")
    write_report(result, out_html)
    assert Path(out_html).exists()
    assert "<!DOCTYPE html>" in Path(out_html).read_text()

    out_json = str(tmp_path / "report.json")
    write_report(result, out_json)
    assert Path(out_json).exists()
    assert json.loads(Path(out_json).read_text())["source"] == "data.csv"


def test_write_report_sarif(tmp_path):
    result = ScanResult(
        source="data.csv",
        rows=10,
        columns=2,
        findings=[
            Finding(
                column="email",
                category="contact",
                detector="email",
                count=2,
                confidence=0.9,
                severity=0.5,
                samples_redacted=["e***@example.com"],
                jurisdictions=["gdpr"],
            )
        ],
        jurisdictions=["gdpr"],
        scan_time=0.1,
        metrics=None,
        risk=RiskScore(score=30.0, level="medium", drivers=["email"]),
    )
    out_sarif = tmp_path / "report.sarif"
    write_report(result, out_sarif)
    assert out_sarif.exists()
    payload = json.loads(out_sarif.read_text())
    assert payload["version"] == "2.1.0"
    assert len(payload["runs"][0]["results"]) == 1


def test_write_report_unsupported_extension(tmp_path):
    result = ScanResult(
        source="test.csv",
        rows=10,
        columns=2,
        findings=[],
        jurisdictions=["gdpr"],
        scan_time=0.1,
        metrics=None,
        risk=RiskScore(score=0.0, level="low", drivers=[]),
    )
    with pytest.raises(PiiscopeError, match="use a .json, .md, .html or .sarif extension"):
        write_report(result, tmp_path / "report.xyz")

