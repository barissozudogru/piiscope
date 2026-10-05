"""Anonymisation and privacy risk metrics.

This module provides functions to compute:
  - k-anonymity
  - l-diversity
  - t-closeness
  - re-identification risk score
  - differential privacy epsilon estimation
  - data masking recommendations per PII type
  - privacy impact assessment summary
  - data retention suggestions based on PII categories found

Note: k/l/t metrics operate on a full pandas.DataFrame. For datasets
larger than memory, compute aggregated counts in the worker and call
metrics on sampled data or incrementally.
"""

from __future__ import annotations

import math
from typing import Any

import pandas as pd

# ---------------------------------------------------------------------------
# k-anonymity
# ---------------------------------------------------------------------------


def compute_k_anonymity(df: pd.DataFrame, quasi_identifiers: list[str]) -> int | None:
    """Return k-anonymity: the minimum equivalence class size.

    k-anonymity is defined as the size of the smallest equivalence class
    when grouping by the quasi-identifier columns.

    Returns None if df is empty, no quasi-identifiers are provided, or
    if every row contains a null value in at least one quasi-identifier.
    """
    if df.empty or not quasi_identifiers:
        return None
    available = [c for c in quasi_identifiers if c in df.columns]
    if not available:
        return None
    group_sizes = df.groupby(available).size()
    if group_sizes.empty:
        # every row has a null in at least one key, so no class survives
        return None
    return int(group_sizes.min())


# ---------------------------------------------------------------------------
# l-diversity
# ---------------------------------------------------------------------------


def compute_l_diversity(
    df: pd.DataFrame, quasi_identifiers: list[str], sensitive_attr: str
) -> int | None:
    """Return l-diversity: minimum number of distinct sensitive values per class.

    A higher l indicates more diversity and therefore lower re-identification
    risk via attribute disclosure.
    """
    if df.empty or not quasi_identifiers or sensitive_attr not in df.columns:
        return None
    available = [c for c in quasi_identifiers if c in df.columns]
    if not available:
        return None
    if df[sensitive_attr].dropna().empty:
        return None
    l_values = df.groupby(available)[sensitive_attr].nunique(dropna=True)
    if l_values.empty:
        return None
    return int(l_values.min())


# ---------------------------------------------------------------------------
# t-closeness
# ---------------------------------------------------------------------------


def compute_t_closeness(
    df: pd.DataFrame, quasi_identifiers: list[str], sensitive_attr: str
) -> float | None:
    """Return t-closeness: maximum total variation distance across classes.

    Compares the distribution of the sensitive attribute within each
    equivalence class against the overall distribution. Smaller values
    indicate better anonymisation.

    Uses total variation distance (half the L1 distance between distributions).
    """
    if df.empty or not quasi_identifiers or sensitive_attr not in df.columns:
        return None
    available = [c for c in quasi_identifiers if c in df.columns]
    if not available:
        return None

    overall_dist = df[sensitive_attr].value_counts(normalize=True).to_dict()
    if not overall_dist:
        return None

    group_sizes = df.groupby(available).size()
    if group_sizes.empty:
        return None

    max_tv = 0.0
    for _, group in df.groupby(available):
        class_dist = group[sensitive_attr].value_counts(normalize=True)
        keys = set(overall_dist.keys()).union(class_dist.index)
        tv = sum(abs(overall_dist.get(k, 0.0) - class_dist.get(k, 0.0)) for k in keys)
        tv *= 0.5  # total variation distance = half L1
        if tv > max_tv:
            max_tv = float(tv)
    return max_tv


# ---------------------------------------------------------------------------
# Re-identification risk scoring
# ---------------------------------------------------------------------------


def compute_reidentification_risk(
    df: pd.DataFrame,
    quasi_identifiers: list[str],
) -> dict[str, Any]:
    """Estimate re-identification risk for the dataset.

    Returns a dict with:
      - prosecutor_risk  : max probability any individual can be singled out
                           (1 / min equivalence class size)
      - journalist_risk  : average probability across records
      - marketer_risk    : proportion of records in equivalence classes of size 1
      - risk_level       : "low" / "medium" / "high" / "critical"
      - unique_records   : count of records in a class of size 1
      - equivalence_classes: total number of distinct equivalence classes
    """
    if df.empty or not quasi_identifiers:
        return {
            "prosecutor_risk": None,
            "journalist_risk": None,
            "marketer_risk": None,
            "risk_level": "unknown",
            "unique_records": None,
            "equivalence_classes": None,
        }

    available = [c for c in quasi_identifiers if c in df.columns]
    if not available:
        return {
            "prosecutor_risk": None,
            "journalist_risk": None,
            "marketer_risk": None,
            "risk_level": "unknown",
            "unique_records": None,
            "equivalence_classes": None,
        }

    group_sizes = df.groupby(available).size()
    if group_sizes.empty:
        return {
            "prosecutor_risk": None,
            "journalist_risk": None,
            "marketer_risk": None,
            "risk_level": "unknown",
            "unique_records": None,
            "equivalence_classes": None,
        }

    n_total = len(df)
    n_classes = len(group_sizes)
    min_size = int(group_sizes.min())
    unique_records = int((group_sizes == 1).sum())

    prosecutor_risk = round(1.0 / min_size, 4) if min_size > 0 else 1.0
    journalist_risk = round(float((1.0 / group_sizes).mul(group_sizes).sum() / n_total), 4)
    marketer_risk = round(unique_records / n_total, 4) if n_total > 0 else 0.0

    # Risk classification
    if prosecutor_risk >= 0.5:
        risk_level = "critical"
    elif prosecutor_risk >= 0.2:
        risk_level = "high"
    elif prosecutor_risk >= 0.05:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "prosecutor_risk": prosecutor_risk,
        "journalist_risk": journalist_risk,
        "marketer_risk": marketer_risk,
        "risk_level": risk_level,
        "unique_records": unique_records,
        "equivalence_classes": n_classes,
    }


# ---------------------------------------------------------------------------
# Differential privacy epsilon estimation
# ---------------------------------------------------------------------------


def estimate_dp_epsilon(
    df: pd.DataFrame,
    sensitive_columns: list[str],
    *,
    noise_mechanism: str = "laplace",
    sensitivity: float = 1.0,
) -> dict[str, Any]:
    """Estimate the effective epsilon if Laplace or Gaussian noise were added.

    This is a THEORETICAL estimation - it does NOT add noise to the data.
    It answers: "what epsilon would be needed to make this column
    differentially private at the observed value range?"

    For a numeric column with range R and sensitivity s, the Laplace
    mechanism requires epsilon = s / noise_scale.  We estimate the
    noise_scale needed to achieve a signal-to-noise ratio of ~10.

    Returns per-column epsilon estimates and an overall risk summary.
    """
    results: dict[str, Any] = {"columns": {}, "mechanism": noise_mechanism}
    for col in sensitive_columns:
        if col not in df.columns:
            results["columns"][col] = {"epsilon": None, "reason": "column not found"}
            continue
        col_data = pd.to_numeric(df[col], errors="coerce").dropna()
        if col_data.empty:
            results["columns"][col] = {
                "epsilon": None,
                "reason": "no numeric values; consider randomised response",
            }
            continue
        col_range = float(col_data.max() - col_data.min())
        if col_range == 0:
            results["columns"][col] = {
                "epsilon": None,
                "reason": "constant column; no privacy risk from noise",
            }
            continue
        # Noise scale needed for SNR=10: noise_scale = range / 10
        noise_scale = col_range / 10.0
        if noise_mechanism == "laplace":
            # epsilon = sensitivity / noise_scale
            epsilon = round(sensitivity / noise_scale, 4)
        elif noise_mechanism == "gaussian":
            # Approximate: epsilon ≈ sqrt(2 * ln(1.25/delta)) * sensitivity / noise_scale
            delta = 1e-5
            epsilon = round(math.sqrt(2 * math.log(1.25 / delta)) * sensitivity / noise_scale, 4)
        else:
            epsilon = None
        results["columns"][col] = {
            "epsilon": epsilon,
            "value_range": col_range,
            "noise_scale_needed": round(noise_scale, 4),
            "interpretation": _dp_epsilon_label(epsilon) if epsilon else "n/a",
        }
    return results


def _dp_epsilon_label(epsilon: float | None) -> str:
    if epsilon is None:
        return "n/a"
    if epsilon < 0.1:
        return "strong privacy"
    if epsilon < 1.0:
        return "moderate privacy"
    if epsilon < 10.0:
        return "weak privacy"
    return "negligible privacy"


# ---------------------------------------------------------------------------
# Masking recommendations per PII category
# ---------------------------------------------------------------------------

_MASKING_RECOMMENDATIONS: dict[str, dict[str, Any]] = {
    "financial": {
        "primary": "tokenize",
        "alternatives": ["hash", "redact"],
        "retention_days": 90,
        "rationale": "Financial identifiers must not be stored in plaintext; "
        "tokenisation preserves referential integrity.",
        "gdpr_article": "Article 25 (Data Protection by Design)",
        "kvkk_article": "Article 12",
        "ccpa_section": "Section 1798.100",
    },
    "national_id": {
        "primary": "hash",
        "alternatives": ["null", "tokenize"],
        "retention_days": 30,
        "rationale": "National identifiers are high-risk direct identifiers; "
        "hash or remove after processing.",
        "gdpr_article": "Article 9 (Special Categories)",
        "kvkk_article": "Article 6",
        "ccpa_section": "Section 1798.140(o)(1)(A)",
    },
    "health": {
        "primary": "null",
        "alternatives": ["hash", "redact"],
        "retention_days": 7,
        "rationale": "Health data is a special category under GDPR Art. 9; "
        "minimal retention, explicit consent required.",
        "gdpr_article": "Article 9(2)",
        "kvkk_article": "Article 6(3)",
        "ccpa_section": "Section 1798.140(b)",
    },
    "contact": {
        "primary": "redact",
        "alternatives": ["hash", "tokenize"],
        "retention_days": 180,
        "rationale": "Contact information enables direct identification; "
        "redact or hash after the retention window.",
        "gdpr_article": "Article 5(1)(e) (Storage Limitation)",
        "kvkk_article": "Article 7",
        "ccpa_section": "Section 1798.100(a)",
    },
    "demographic": {
        "primary": "generalize",
        "alternatives": ["date_shift", "null"],
        "retention_days": 365,
        "rationale": "Demographic data can act as a quasi-identifier; "
        "generalisation reduces re-identification risk.",
        "gdpr_article": "Article 5(1)(c) (Data Minimisation)",
        "kvkk_article": "Article 4",
        "ccpa_section": None,
    },
    "name": {
        "primary": "redact",
        "alternatives": ["hash", "tokenize"],
        "retention_days": 180,
        "rationale": "Personal names directly identify individuals; "
        "redact or pseudonymise to prevent identification.",
        "gdpr_article": "Article 4(1), Article 5(1)(e)",
        "kvkk_article": "Article 3, Article 4",
        "ccpa_section": "Section 1798.140(v)(1)(A)",
    },
    "network": {
        "primary": "hash",
        "alternatives": ["redact", "generalize"],
        "retention_days": 90,
        "rationale": "IP addresses are personal data in the EU (CJEU C-582/14); "
        "hash or truncate to /24 to reduce linkability.",
        "gdpr_article": "Recital 30; Article 4(1)",
        "kvkk_article": "Article 3",
        "ccpa_section": None,
    },
    "custom": {
        "primary": "redact",
        "alternatives": ["hash"],
        "retention_days": 90,
        "rationale": "Custom pattern - apply organisation-specific retention policy.",
        "gdpr_article": None,
        "kvkk_article": None,
        "ccpa_section": None,
    },
    "other": {
        "primary": "redact",
        "alternatives": ["hash"],
        "retention_days": 365,
        "rationale": "Apply standard data minimisation principle.",
        "gdpr_article": "Article 5(1)(c)",
        "kvkk_article": "Article 4",
        "ccpa_section": None,
    },
}


def get_masking_recommendations(pii_categories: set[str]) -> dict[str, Any]:
    """Return masking recommendations for the given set of PII categories.

    pii_categories should be a set of strings from PatternDefinition.pii_category
    (e.g. {"financial", "contact", "health"}).

    Returns a dict keyed by category with recommendation details.
    """
    result: dict[str, Any] = {}
    for category in pii_categories:
        rec = _MASKING_RECOMMENDATIONS.get(category, _MASKING_RECOMMENDATIONS["other"])
        result[category] = rec.copy()
    return result


# ---------------------------------------------------------------------------
# Privacy impact assessment (PIA) summary
# ---------------------------------------------------------------------------


def generate_privacy_impact_assessment(
    findings_summary: dict[str, Any],
    k_anonymity: int | None,
    l_diversity: int | None,
    t_closeness: float | None,
    reidentification_risk: dict[str, Any] | None,
) -> dict[str, Any]:
    """Generate a structured Privacy Impact Assessment (PIA) summary.

    findings_summary should have at minimum:
      - total_findings: int
      - pii_categories: list of PII category strings
      - highest_severity: float (0-1)
      - rules_triggered: list of rule_id strings

    Returns a dict suitable for serialisation as JSON or inclusion in reports.
    """
    pii_cats = set(findings_summary.get("pii_categories", []))
    total = findings_summary.get("total_findings", 0)
    highest_sev = findings_summary.get("highest_severity", 0.0)
    rules = findings_summary.get("rules_triggered", [])

    # Overall risk score: weighted combination of metrics
    risk_score = _compute_overall_risk_score(
        total_findings=total,
        highest_severity=highest_sev,
        k_anonymity=k_anonymity,
        reidentification_risk=reidentification_risk,
    )

    # Compliance gaps
    gaps = _identify_compliance_gaps(pii_cats, k_anonymity, l_diversity, t_closeness)

    # Recommendations
    masking_recs = get_masking_recommendations(pii_cats)
    retention_recs = {cat: rec["retention_days"] for cat, rec in masking_recs.items()}

    # Jurisdiction mapping
    jurisdiction_flags = _jurisdiction_flags(pii_cats, rules)

    return {
        "overall_risk_score": round(risk_score, 3),
        "risk_level": _risk_score_label(risk_score),
        "pii_categories_found": sorted(pii_cats),
        "total_findings": total,
        "highest_severity": round(highest_sev, 3),
        "k_anonymity": k_anonymity,
        "l_diversity": l_diversity,
        "t_closeness": round(t_closeness, 4) if t_closeness is not None else None,
        "reidentification_risk": reidentification_risk,
        "compliance_gaps": gaps,
        "masking_recommendations": masking_recs,
        "retention_recommendations_days": retention_recs,
        "jurisdiction_applicability": jurisdiction_flags,
        "rules_triggered": rules,
    }


def _compute_overall_risk_score(
    total_findings: int,
    highest_severity: float,
    k_anonymity: int | None,
    reidentification_risk: dict[str, Any] | None,
) -> float:
    """Produce a 0-1 risk score from available signals."""
    score = 0.0

    # Severity contribution (40%)
    score += highest_severity * 0.4

    # Finding volume contribution (20%): capped at 100 findings
    volume_signal = min(total_findings / 100.0, 1.0)
    score += volume_signal * 0.2

    # k-anonymity contribution (25%)
    if k_anonymity is not None:
        # k=1 → full risk, k=5 → moderate, k>=10 → low
        k_risk = max(0.0, 1.0 - (k_anonymity - 1) / 9.0)
        score += k_risk * 0.25

    # Re-identification risk contribution (15%)
    if reidentification_risk and reidentification_risk.get("prosecutor_risk") is not None:
        score += float(reidentification_risk["prosecutor_risk"]) * 0.15

    return min(1.0, score)


def _risk_score_label(score: float) -> str:
    if score >= 0.75:
        return "critical"
    if score >= 0.5:
        return "high"
    if score >= 0.25:
        return "medium"
    return "low"


def _identify_compliance_gaps(
    pii_cats: set[str],
    k_anonymity: int | None,
    l_diversity: int | None,
    t_closeness: float | None,
) -> list[dict[str, str]]:
    """Identify specific compliance gaps based on PII categories and metrics."""
    gaps = []

    if "health" in pii_cats:
        gaps.append(
            {
                "framework": "GDPR",
                "article": "Art. 9",
                "gap": "Special category health data detected; explicit consent or "
                "Art. 9(2) basis required before processing.",
                "severity": "critical",
            }
        )
        gaps.append(
            {
                "framework": "KVKK",
                "article": "Art. 6",
                "gap": "Sensitive personal data (health) requires explicit consent "
                "and is subject to stricter processing conditions.",
                "severity": "critical",
            }
        )

    if "national_id" in pii_cats:
        gaps.append(
            {
                "framework": "GDPR",
                "article": "Art. 87",
                "gap": "National identification numbers require a specific legal basis "
                "and technical safeguards.",
                "severity": "high",
            }
        )

    if "financial" in pii_cats:
        gaps.append(
            {
                "framework": "PCI-DSS",
                "article": "Requirement 3",
                "gap": "Cardholder data (PAN/IBAN) must not be stored unless necessary; "
                "use tokenisation or truncation.",
                "severity": "critical",
            }
        )

    if k_anonymity is not None and k_anonymity < 5:
        gaps.append(
            {
                "framework": "GDPR / KVKK",
                "article": "Art. 25 / Art. 12",
                "gap": f"k-anonymity is {k_anonymity} (below recommended threshold of 5). "
                "The dataset can re-identify individuals. Apply generalisation or "
                "suppression to quasi-identifiers.",
                "severity": "high" if k_anonymity < 3 else "medium",
            }
        )

    if l_diversity is not None and l_diversity < 3:
        gaps.append(
            {
                "framework": "GDPR",
                "article": "Art. 5(1)(f)",
                "gap": f"l-diversity is {l_diversity} (below recommended threshold of 3). "
                "Attribute disclosure is possible. Increase diversity of sensitive "
                "values within equivalence classes.",
                "severity": "medium",
            }
        )

    if t_closeness is not None and t_closeness > 0.2:
        gaps.append(
            {
                "framework": "GDPR",
                "article": "Art. 5(1)(c)",
                "gap": f"t-closeness is {t_closeness:.3f} (above recommended threshold of 0.2). "
                "Sensitive attribute distribution differs significantly between "
                "equivalence classes and the overall dataset.",
                "severity": "medium",
            }
        )

    return gaps


def _jurisdiction_flags(pii_cats: set[str], rules_triggered: list[str]) -> dict[str, bool]:
    """Return which privacy frameworks are likely applicable."""
    has_financial = "financial" in pii_cats
    has_health = "health" in pii_cats
    has_tc_kimlik = "tc_kimlik" in rules_triggered
    has_us_ssn = "us_ssn" in rules_triggered
    has_any_pii = bool(pii_cats - {"other"})

    return {
        "GDPR": has_any_pii,
        "KVKK": has_tc_kimlik or has_any_pii,
        "CCPA": has_us_ssn or has_any_pii,
        "LGPD": has_any_pii,
        "PCI_DSS": has_financial,
        "HIPAA": has_health,
    }
