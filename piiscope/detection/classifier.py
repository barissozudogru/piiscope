"""Data classification taxonomy for findings.

Findings are mapped to standardised data classification levels:

  PII        - Personally Identifiable Information (GDPR Art. 4)
  PHI        - Protected Health Information (HIPAA)
  PCI        - Payment Card Industry data (PCI-DSS)
  Confidential - Sensitive business or government data
  Internal   - Non-public but not regulated
  Public     - Freely available or low-sensitivity

Classification levels are ordinal: PII > PHI > PCI > Confidential > Internal > Public.

Custom classification rules can be appended via CustomClassifier instances and
passed to DataClassifier at construction time.  Findings from a scan are
aggregated into a data inventory that lists every data category present.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Taxonomy
# ---------------------------------------------------------------------------


class DataCategory:
    PII = "PII"
    PHI = "PHI"
    PCI = "PCI"
    CONFIDENTIAL = "Confidential"
    INTERNAL = "Internal"
    PUBLIC = "Public"

    # Ordinal rank (higher = more sensitive)
    RANK: dict[str, int] = {
        PHI: 6,
        PCI: 5,
        PII: 4,
        CONFIDENTIAL: 3,
        INTERNAL: 2,
        PUBLIC: 1,
    }

    @classmethod
    def highest(cls, categories: list[str]) -> str:
        """Return the most sensitive category from a list."""
        if not categories:
            return cls.PUBLIC
        return max(categories, key=lambda c: cls.RANK.get(c, 0))


# ---------------------------------------------------------------------------
# Built-in rule -> category mapping
# ---------------------------------------------------------------------------
# Each rule_id maps to a (primary_category, sub_labels) pair.
# sub_labels are informational tags that appear in the inventory.


@dataclass
class ClassificationResult:
    primary_category: str
    sub_labels: list[str]
    description: str


_RULE_CLASSIFICATIONS: dict[str, ClassificationResult] = {
    # PII - national identifiers
    "us_ssn": ClassificationResult(
        DataCategory.PII, ["national_id", "us_ssn"], "US Social Security Number"
    ),
    "tc_kimlik": ClassificationResult(
        DataCategory.PII, ["national_id", "tc_kimlik"], "Turkish TC identity number"
    ),
    "national_id": ClassificationResult(
        DataCategory.PII, ["national_id", "de_id"], "German national ID"
    ),
    "passport": ClassificationResult(
        DataCategory.PII, ["national_id", "passport"], "Passport number (generic)"
    ),
    "passport_tr": ClassificationResult(
        DataCategory.PII, ["national_id", "passport", "tr"], "Turkish passport"
    ),
    "passport_de": ClassificationResult(
        DataCategory.PII, ["national_id", "passport", "de"], "German passport"
    ),
    "passport_uk": ClassificationResult(
        DataCategory.PII, ["national_id", "passport", "uk"], "UK passport"
    ),
    # PII - contact information
    "email": ClassificationResult(DataCategory.PII, ["contact", "email"], "Email address"),
    "eu_phone": ClassificationResult(
        DataCategory.PII, ["contact", "phone", "eu"], "European phone number"
    ),
    "us_phone": ClassificationResult(
        DataCategory.PII, ["contact", "phone", "us"], "US/Canada phone number"
    ),
    "tr_phone": ClassificationResult(
        DataCategory.PII, ["contact", "phone", "tr"], "Turkish phone number"
    ),
    # PII - demographic
    "given_name": ClassificationResult(DataCategory.PII, ["demographic", "name"], "Personal name"),
    "ner_person": ClassificationResult(DataCategory.PII, ["demographic", "name"], "Person (NER)"),
    "date": ClassificationResult(
        DataCategory.PII, ["demographic", "date_of_birth"], "Date (potentially DOB)"
    ),
    # PHI - health information
    "medical_record": ClassificationResult(
        DataCategory.PHI, ["health", "mrn"], "Medical record number"
    ),
    "hospital_name": ClassificationResult(
        DataCategory.PHI, ["health", "facility"], "Hospital name"
    ),
    "drug_name": ClassificationResult(
        DataCategory.PHI, ["health", "medication"], "Drug/medication name"
    ),
    "ner_org": ClassificationResult(
        DataCategory.CONFIDENTIAL, ["organization"], "Organization name (NER)"
    ),
    # PCI - payment data
    "credit_card": ClassificationResult(
        DataCategory.PCI, ["payment", "credit_card", "pan"], "Credit card PAN"
    ),
    "iban": ClassificationResult(DataCategory.PCI, ["payment", "iban"], "IBAN bank account"),
    "iban_tr": ClassificationResult(DataCategory.PCI, ["payment", "iban", "tr"], "Turkish IBAN"),
    "swift_bic": ClassificationResult(
        DataCategory.PCI, ["payment", "swift", "bic"], "SWIFT/BIC code"
    ),
    "vat": ClassificationResult(DataCategory.CONFIDENTIAL, ["financial", "vat"], "EU VAT number"),
    # Internal / network
    "ipv4_address": ClassificationResult(
        DataCategory.INTERNAL, ["network", "ipv4"], "IPv4 address"
    ),
    "ipv6_address": ClassificationResult(
        DataCategory.INTERNAL, ["network", "ipv6"], "IPv6 address"
    ),
    "url": ClassificationResult(DataCategory.INTERNAL, ["network", "url"], "URL"),
}

_DEFAULT_CLASSIFICATION = ClassificationResult(
    DataCategory.INTERNAL, ["unclassified"], "Unclassified data type"
)


# ---------------------------------------------------------------------------
# Custom classification rule
# ---------------------------------------------------------------------------


@dataclass
class CustomClassificationRule:
    """User-defined mapping from a rule_id (or pii_category) to a classification."""

    matches_rule_id: str | None = None  # exact rule_id match
    matches_pii_category: str | None = None  # pii_category string match
    primary_category: str = DataCategory.CONFIDENTIAL
    sub_labels: list[str] = field(default_factory=list)
    description: str = "Custom classification"


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


@dataclass
class ClassifiedFinding:
    """A finding annotated with its classification."""

    finding_id: Any
    rule_id: str
    column_name: str
    primary_category: str
    sub_labels: list[str]
    description: str
    confidence: float
    severity: float


@dataclass
class DataInventoryEntry:
    """One row in the data inventory summary."""

    category: str
    sub_labels: set[str]
    rule_ids: set[str]
    finding_count: int
    column_names: set[str]


class DataClassifier:
    """Classify scan findings into the data taxonomy.

    Parameters
    ----------
    custom_rules:
        Additional classification rules that override or supplement the
        built-in mapping.  Custom rules are evaluated before built-ins.
    """

    def __init__(
        self,
        custom_rules: list[CustomClassificationRule] | None = None,
    ) -> None:
        self._custom_rules = custom_rules or []

    # ------------------------------------------------------------------

    def classify_finding(
        self,
        rule_id: str,
        pii_category: str = "",
        finding_id: Any = None,
        column_name: str = "",
        confidence: float = 0.5,
        severity: float = 0.5,
    ) -> ClassifiedFinding:
        """Return a ClassifiedFinding for a single finding."""
        # 1. Try custom rules first (rule_id → pii_category fallback)
        for rule in self._custom_rules:
            if rule.matches_rule_id and rule.matches_rule_id != rule_id:
                continue
            if rule.matches_pii_category and rule.matches_pii_category != pii_category:
                continue
            return ClassifiedFinding(
                finding_id=finding_id,
                rule_id=rule_id,
                column_name=column_name,
                primary_category=rule.primary_category,
                sub_labels=list(rule.sub_labels),
                description=rule.description,
                confidence=confidence,
                severity=severity,
            )

        # 2. Built-in mapping
        result = _RULE_CLASSIFICATIONS.get(rule_id, _DEFAULT_CLASSIFICATION)

        return ClassifiedFinding(
            finding_id=finding_id,
            rule_id=rule_id,
            column_name=column_name,
            primary_category=result.primary_category,
            sub_labels=list(result.sub_labels),
            description=result.description,
            confidence=confidence,
            severity=severity,
        )

    def classify_scan(
        self,
        findings: list[dict[str, Any]],
    ) -> list[ClassifiedFinding]:
        """Classify all findings from a scan."""
        classified = []
        for f in findings:
            cf = self.classify_finding(
                rule_id=f.get("rule_id", "unknown"),
                pii_category=f.get("pii_category", ""),
                finding_id=f.get("id"),
                column_name=f.get("column_name", ""),
                confidence=float(f.get("confidence", 0.5)),
                severity=float(f.get("severity", 0.5)),
            )
            classified.append(cf)
        return classified

    def build_inventory(
        self,
        classified_findings: list[ClassifiedFinding],
    ) -> list[DataInventoryEntry]:
        """Aggregate classified findings into a data inventory.

        The inventory lists every data category found, the sub-labels
        within that category, which rule_ids were triggered, how many
        findings belong to the category, and which columns were involved.
        """
        inventory: dict[str, DataInventoryEntry] = {}

        for cf in classified_findings:
            cat = cf.primary_category
            if cat not in inventory:
                inventory[cat] = DataInventoryEntry(
                    category=cat,
                    sub_labels=set(),
                    rule_ids=set(),
                    finding_count=0,
                    column_names=set(),
                )
            entry = inventory[cat]
            entry.sub_labels.update(cf.sub_labels)
            entry.rule_ids.add(cf.rule_id)
            entry.finding_count += 1
            if cf.column_name:
                entry.column_names.add(cf.column_name)

        # Return sorted by sensitivity rank (most sensitive first)
        return sorted(
            inventory.values(),
            key=lambda e: DataCategory.RANK.get(e.category, 0),
            reverse=True,
        )

    def inventory_to_dict(
        self,
        inventory: list[DataInventoryEntry],
    ) -> list[dict[str, Any]]:
        """Serialise inventory entries to plain dicts for JSON output."""
        return [
            {
                "category": e.category,
                "sub_labels": sorted(e.sub_labels),
                "rule_ids": sorted(e.rule_ids),
                "finding_count": e.finding_count,
                "column_names": sorted(e.column_names),
            }
            for e in inventory
        ]
