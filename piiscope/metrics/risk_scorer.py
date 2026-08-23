"""Risk scoring engine for findings produced by the detection engine.

Each finding is scored on a 1-10 scale that accounts for:
  - Data type sensitivity (national IDs, SSNs score highest)
  - Volume of exposed records relative to a reference ceiling
  - Context in which the data was found (database field vs log vs API response)
  - Jurisdiction-specific regulatory weight

Aggregate scores are computed per scan and stored so that trend analysis
can track risk movement across successive scans of the same data source.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sensitivity weights per rule_id (0.0 - 1.0, will be scaled to 1-10)
# ---------------------------------------------------------------------------
# Higher = more sensitive. Anchored on widely accepted severity hierarchies:
#   SSN / national ID / medical = 0.9-1.0 (very high)
#   Financial (credit card, IBAN) = 0.7-0.8 (high)
#   Contact (phone, email) = 0.3-0.5 (medium-low)
#   Network / metadata = 0.1-0.3 (low)
_SENSITIVITY: dict[str, float] = {
    "us_ssn": 1.0,
    "tc_kimlik": 1.0,
    "medical_record": 1.0,
    "passport": 0.9,
    "national_id": 0.9,
    "credit_card": 0.85,
    "iban": 0.8,
    "vat": 0.6,
    "swift_bic": 0.7,
    "eu_phone": 0.45,
    "us_phone": 0.45,
    "tr_phone": 0.45,
    "email": 0.4,
    "given_name": 0.3,
    "surname": 0.3,
    "medical_condition": 0.9,
    "ner_person": 0.3,
    "hospital_name": 0.9,
    "drug_name": 0.9,
    "date": 0.2,
    "ipv4_address": 0.25,
    "ipv6_address": 0.25,
    "url": 0.1,
    # Multi-country passports
    "passport_tr": 0.9,
    "passport_de": 0.9,
    "passport_uk": 0.9,
    # Turkish IBAN
    "iban_tr": 0.8,
}

# Default sensitivity for unknown rule IDs
_DEFAULT_SENSITIVITY = 0.4

# ---------------------------------------------------------------------------
# Context multipliers
# ---------------------------------------------------------------------------
# The context in which data is found modifies the raw sensitivity score.
# A database column containing a raw SSN is more alarming than the same
# value appearing inside a plaintext log file because logs may already be
# treated as non-production artefacts.  API response exposure is the most
# critical context because it implies the data is traversing a network
# boundary.
CONTEXT_MULTIPLIERS: dict[str, float] = {
    "database_field": 1.0,  # baseline
    "api_response": 1.3,  # network-traversing, highest risk
    "log_file": 0.7,  # may be internal/redacted
    "report": 0.9,  # structured but may be shared
    "config_file": 1.1,  # often overlooked, should not contain PII
    "flat_file": 0.85,  # CSVs / Parquet shared for analytics
    "unknown": 1.0,
}

# ---------------------------------------------------------------------------
# Jurisdiction bonus (additive to the base score before capping at 10)
# ---------------------------------------------------------------------------
# Data subject to strict regulations adds a regulatory weight to ensure
# compliance-driven organisations surface those findings at the top.
_JURISDICTION_BONUS: dict[str, float] = {
    "gdpr": 0.5,
    "ccpa": 0.4,
    "hipaa": 0.6,
    "kvkk": 0.4,
    "pdpl": 0.4,  # Turkish KVKK / PDPL
    "lgpd": 0.5,
}

# Volume brackets (number of affected records → weight 0.0-1.0)
_VOLUME_BRACKETS: list[tuple[int, float]] = [
    (1, 0.05),
    (10, 0.15),
    (100, 0.35),
    (1_000, 0.55),
    (10_000, 0.70),
    (100_000, 0.85),
    (1_000_000, 1.0),
]


def _volume_weight(record_count: int) -> float:
    """Map a record count to a weight in [0.05, 1.0]."""
    for threshold, weight in reversed(_VOLUME_BRACKETS):
        if record_count >= threshold:
            return weight
    return _VOLUME_BRACKETS[0][1]


@dataclass
class FindingScore:
    """Score breakdown for a single finding."""

    rule_id: str
    raw_sensitivity: float
    context_multiplier: float
    volume_weight: float
    jurisdiction_bonus: float
    final_score: float  # 1-10
    confidence: float  # from the detection engine


@dataclass
class ScanRiskSummary:
    """Aggregate risk summary for an entire scan."""

    scan_id: int
    total_findings: int
    scored_findings: list[FindingScore]
    aggregate_score: float  # 1-10; weighted average
    max_score: float  # highest individual score
    critical_count: int  # findings with score >= 8
    high_count: int  # findings with score >= 6
    medium_count: int  # findings with score >= 3
    low_count: int  # findings with score < 3
    top_rule_ids: list[str]  # top-5 most risky rule IDs
    computed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class RiskScorer:
    """Score findings and produce aggregate scan risk summaries.

    Parameters
    ----------
    context:
        The context in which the data was found.  Must be one of the keys in
        CONTEXT_MULTIPLIERS; defaults to ``"unknown"``.
    jurisdictions:
        A list of applicable jurisdictions (e.g. ``["gdpr", "hipaa"]``).
        Jurisdiction bonuses are additive.
    """

    def __init__(
        self,
        *,
        context: str = "unknown",
        jurisdictions: list[str] | None = None,
    ) -> None:
        self.context = context if context in CONTEXT_MULTIPLIERS else "unknown"
        self.context_mult = CONTEXT_MULTIPLIERS[self.context]
        self.jurisdictions = [j.lower() for j in (jurisdictions or [])]
        self.jurisdiction_bonus = sum(_JURISDICTION_BONUS.get(j, 0.0) for j in self.jurisdictions)

    # ------------------------------------------------------------------
    # Single finding
    # ------------------------------------------------------------------

    def score_finding(
        self,
        rule_id: str,
        confidence: float,
        record_count: int = 1,
    ) -> FindingScore:
        """Compute a 1-10 risk score for an individual finding.

        The formula is::

            raw   = sensitivity * context_multiplier * confidence
            score = clamp(raw * 10 + jurisdiction_bonus + volume_shift, 1, 10)

        where ``volume_shift`` adds up to 1.5 points for large volumes.
        """
        sensitivity = _SENSITIVITY.get(rule_id, _DEFAULT_SENSITIVITY)
        volume_w = _volume_weight(record_count)
        volume_shift = volume_w * 1.5

        raw = sensitivity * self.context_mult * confidence
        raw_score = raw * 10.0 + self.jurisdiction_bonus + volume_shift
        final = max(1.0, min(10.0, round(raw_score, 2)))

        return FindingScore(
            rule_id=rule_id,
            raw_sensitivity=sensitivity,
            context_multiplier=self.context_mult,
            volume_weight=volume_w,
            jurisdiction_bonus=self.jurisdiction_bonus,
            final_score=final,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Bulk scoring for a scan
    # ------------------------------------------------------------------

    def score_scan(
        self,
        scan_id: int,
        findings: list[dict[str, Any]],
    ) -> ScanRiskSummary:
        """Score all findings for a scan and return a risk summary.

        Parameters
        ----------
        scan_id:
            The database primary key of the scan job.
        findings:
            A list of finding dicts (at minimum: rule_id, confidence).
            Optionally: record_count (defaults to 1).
        """
        if not findings:
            return ScanRiskSummary(
                scan_id=scan_id,
                total_findings=0,
                scored_findings=[],
                aggregate_score=0.0,
                max_score=0.0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                top_rule_ids=[],
            )

        scored: list[FindingScore] = []
        rule_score_totals: dict[str, float] = {}

        for f in findings:
            rule_id = f.get("rule_id", "unknown")
            confidence = float(f.get("confidence", 0.5))
            record_count = int(f.get("record_count", 1))
            fs = self.score_finding(rule_id, confidence, record_count)
            scored.append(fs)
            rule_score_totals[rule_id] = rule_score_totals.get(rule_id, 0.0) + fs.final_score

        scores = [s.final_score for s in scored]
        aggregate = round(sum(scores) / len(scores), 2)
        max_score = round(max(scores), 2)

        critical = sum(1 for s in scores if s >= 8.0)
        high = sum(1 for s in scores if 6.0 <= s < 8.0)
        medium = sum(1 for s in scores if 3.0 <= s < 6.0)
        low = sum(1 for s in scores if s < 3.0)

        # Top-5 rule IDs by cumulative score
        top_rules = sorted(rule_score_totals, key=lambda x: rule_score_totals[x], reverse=True)[:5]

        logger.info(
            "Scored scan %d: %d findings, aggregate=%.2f, max=%.2f, "
            "critical=%d, high=%d, medium=%d, low=%d",
            scan_id,
            len(findings),
            aggregate,
            max_score,
            critical,
            high,
            medium,
            low,
        )

        return ScanRiskSummary(
            scan_id=scan_id,
            total_findings=len(findings),
            scored_findings=scored,
            aggregate_score=aggregate,
            max_score=max_score,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            top_rule_ids=top_rules,
        )

    # ------------------------------------------------------------------
    # Trend helpers
    # ------------------------------------------------------------------

    @staticmethod
    def compute_trend(
        previous_scores: list[float],
        current_score: float,
    ) -> dict[str, Any]:
        """Compare current aggregate score against historical scores.

        Returns a dict with::

            {
                "direction": "improving" | "worsening" | "stable",
                "delta": <float>,            # current - previous average
                "previous_average": <float>,
                "current_score": <float>,
            }
        """
        if not previous_scores:
            return {
                "direction": "stable",
                "delta": 0.0,
                "previous_average": current_score,
                "current_score": current_score,
            }

        prev_avg = sum(previous_scores) / len(previous_scores)
        delta = round(current_score - prev_avg, 3)

        if abs(delta) < 0.05:
            direction = "stable"
        elif delta > 0:
            direction = "worsening"
        else:
            direction = "improving"

        return {
            "direction": direction,
            "delta": delta,
            "previous_average": round(prev_avg, 3),
            "current_score": current_score,
        }
