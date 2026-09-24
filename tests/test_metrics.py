import os
import sys

import pandas as pd

# Allow importing without a full app installation
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from piiscope.detection.regex_patterns import PATTERNS
from piiscope.metrics.metrics import (
    compute_k_anonymity,
    compute_l_diversity,
    compute_reidentification_risk,
    compute_t_closeness,
)
from piiscope.metrics.risk_scorer import _SENSITIVITY, RiskScorer


def test_k_anonymity():
    df = pd.DataFrame(
        {
            "age": [25, 25, 30, 30, 30],
            "zip": ["12345", "12345", "12345", "67890", "67890"],
            "disease": ["flu", "flu", "flu", "cold", "cold"],
        }
    )
    k = compute_k_anonymity(df, ["age", "zip"])
    assert k == 1


def test_k_anonymity_all_nulls():
    df = pd.DataFrame({"age": [None, None], "zip": [None, None]})
    assert compute_k_anonymity(df, ["age", "zip"]) is None


def test_l_diversity():
    df = pd.DataFrame(
        {
            "age": [25, 25, 30, 30, 30],
            "zip": ["12345", "12345", "12345", "67890", "67890"],
            "disease": ["flu", "flu", "flu", "cold", "cancer"],
        }
    )
    l_div = compute_l_diversity(df, ["age", "zip"], "disease")
    # Expect min number of distinct diseases per quasi group is 1 (for 30,67890)
    assert l_div == 1


def test_l_diversity_all_nulls_qi():
    df = pd.DataFrame({"age": [None, None], "disease": ["flu", "cancer"]})
    assert compute_l_diversity(df, ["age"], "disease") is None


def test_l_diversity_all_nulls_sensitive():
    df = pd.DataFrame({"age": [25, 30], "disease": [None, None]})
    assert compute_l_diversity(df, ["age"], "disease") is None


def test_t_closeness():
    df = pd.DataFrame(
        {
            "age": [25, 25, 30, 30, 30],
            "zip": ["12345", "12345", "12345", "67890", "67890"],
            "disease": ["flu", "flu", "flu", "cold", "cold"],
        }
    )
    t = compute_t_closeness(df, ["age", "zip"], "disease")
    assert 0 <= t <= 1


def test_t_closeness_all_nulls_qi():
    df = pd.DataFrame({"age": [None, None], "disease": ["flu", "cold"]})
    assert compute_t_closeness(df, ["age"], "disease") is None


def test_t_closeness_all_nulls_sensitive():
    df = pd.DataFrame({"age": [25, 30], "disease": [None, None]})
    assert compute_t_closeness(df, ["age"], "disease") is None


def test_reidentification_risk_all_nulls():
    df = pd.DataFrame({"age": [None, None, None], "zip": [None, None, None]})
    risk = compute_reidentification_risk(df, ["age", "zip"])
    assert risk["prosecutor_risk"] is None
    assert risk["journalist_risk"] is None
    assert risk["marketer_risk"] is None
    assert risk["risk_level"] == "unknown"
    assert risk["unique_records"] is None
    assert risk["equivalence_classes"] is None


def test_reidentification_risk_missing_qi():
    df = pd.DataFrame({"age": [25, 30]})
    risk = compute_reidentification_risk(df, ["nonexistent"])
    assert risk["prosecutor_risk"] is None
    assert risk["risk_level"] == "unknown"


def test_every_pattern_has_sensitivity():
    missing = set(PATTERNS.keys()) - set(_SENSITIVITY.keys())
    assert not missing, f"Patterns missing from _SENSITIVITY: {missing}"


def test_risk_scorer_built_in_sensitivities():
    scorer = RiskScorer()
    assert scorer.score_finding("vat_de", 1.0).raw_sensitivity == 0.6
    assert scorer.score_finding("vat_tr", 1.0).raw_sensitivity == 0.15
    assert scorer.score_finding("tr_phone_strict", 1.0).raw_sensitivity == 0.45


def test_risk_scorer_unknown_rule_fallback():
    scorer = RiskScorer()
    assert scorer.score_finding("unregistered_rule_id", 1.0).raw_sensitivity == 0.4


def test_risk_scorer_score_scan_empty():
    scorer = RiskScorer()
    summary = scorer.score_scan(1, [])
    assert summary.scan_id == 1
    assert summary.total_findings == 0
    assert summary.scored_findings == []
    assert summary.aggregate_score == 0.0
    assert summary.max_score == 0.0
    assert summary.critical_count == 0
    assert summary.high_count == 0
    assert summary.medium_count == 0
    assert summary.low_count == 0
    assert summary.top_rule_ids == []


def test_risk_scorer_score_scan_with_findings():
    scorer = RiskScorer(context="database_field", jurisdictions=["gdpr"])
    raw_findings = [
        {"rule_id": "us_ssn", "confidence": 0.95, "record_count": 500},
        {"rule_id": "credit_card", "confidence": 1.0, "record_count": 1500},
        {"rule_id": "email", "confidence": 0.8, "record_count": 50},
        {"rule_id": "url", "confidence": 0.5, "record_count": 5},
    ]
    summary = scorer.score_scan(42, raw_findings)
    assert summary.scan_id == 42
    assert summary.total_findings == 4
    assert len(summary.scored_findings) == 4
    assert summary.max_score == 10.0
    assert summary.aggregate_score > 0.0
    assert (
        summary.critical_count
        + summary.high_count
        + summary.medium_count
        + summary.low_count
        == 4
    )
    assert len(summary.top_rule_ids) == 4
    assert summary.top_rule_ids[0] in ("us_ssn", "credit_card")


def test_risk_scorer_score_scan_default_fields():
    scorer = RiskScorer()
    summary = scorer.score_scan(7, [{"rule_id": "email"}])
    assert summary.total_findings == 1
    assert len(summary.scored_findings) == 1
    fs = summary.scored_findings[0]
    assert fs.rule_id == "email"
    assert fs.confidence == 0.5
    assert fs.volume_weight == 0.05


def test_risk_scorer_compute_trend_empty_history():
    trend = RiskScorer.compute_trend([], 6.5)
    assert trend["direction"] == "stable"
    assert trend["delta"] == 0.0
    assert trend["previous_average"] == 6.5
    assert trend["current_score"] == 6.5


def test_risk_scorer_compute_trend_directions():
    worsening = RiskScorer.compute_trend([4.0, 5.0], 6.5)
    assert worsening["direction"] == "worsening"
    assert worsening["delta"] == 2.0
    assert worsening["previous_average"] == 4.5

    improving = RiskScorer.compute_trend([8.0, 7.0], 5.0)
    assert improving["direction"] == "improving"
    assert improving["delta"] == -2.5
    assert improving["previous_average"] == 7.5

    stable = RiskScorer.compute_trend([5.0, 5.0], 5.02)
    assert stable["direction"] == "stable"
    assert stable["delta"] == 0.02
    assert stable["previous_average"] == 5.0

