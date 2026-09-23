import json

from piiscope.report.renderers import render_markdown
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

