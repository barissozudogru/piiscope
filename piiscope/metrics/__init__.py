"""Privacy risk metrics: k-anonymity, l-diversity, t-closeness and risk scoring."""

from piiscope.metrics.metrics import (
    compute_k_anonymity,
    compute_l_diversity,
    compute_reidentification_risk,
    compute_t_closeness,
    estimate_dp_epsilon,
    generate_privacy_impact_assessment,
    get_masking_recommendations,
)
from piiscope.metrics.risk_scorer import (
    CONTEXT_MULTIPLIERS,
    FindingScore,
    RiskScorer,
    ScanRiskSummary,
)

__all__ = [
    "CONTEXT_MULTIPLIERS",
    "FindingScore",
    "RiskScorer",
    "ScanRiskSummary",
    "compute_k_anonymity",
    "compute_l_diversity",
    "compute_reidentification_risk",
    "compute_t_closeness",
    "estimate_dp_epsilon",
    "generate_privacy_impact_assessment",
    "get_masking_recommendations",
]
