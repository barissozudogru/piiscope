import pandas as pd

from piiscope.scan import scan


def test_dominance_rule():
    df = pd.DataFrame({"credit_card": ["4111111111111111"] * 85 + ["02071234567"] * 3 + [""] * 12})
    res = scan(df, min_coverage=0.15)
    detectors = [f.detector for f in res.findings]
    assert "credit_card" in detectors
    assert "eu_phone" not in detectors


def test_dominance_rule_show_all():
    df = pd.DataFrame({"credit_card": ["4111111111111111"] * 85 + ["02071234567"] * 3 + [""] * 12})
    res = scan(df, min_coverage=0.0)
    detectors = [f.detector for f in res.findings]
    assert "credit_card" in detectors
    assert "eu_phone" in detectors
