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

