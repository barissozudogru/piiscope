"""Tests for data classification taxonomy and DataClassifier."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from piiscope.detection.classifier import (
    _RULE_CLASSIFICATIONS,
    CustomClassificationRule,
    DataCategory,
    DataClassifier,
)
from piiscope.detection.regex_patterns import PATTERNS


def test_every_pattern_has_classification():
    missing = set(PATTERNS.keys()) - set(_RULE_CLASSIFICATIONS.keys())
    assert not missing, f"Patterns missing from _RULE_CLASSIFICATIONS: {missing}"


def test_data_category_highest():
    assert DataCategory.highest([]) == DataCategory.PUBLIC
    expected = DataCategory.INTERNAL
    assert DataCategory.highest([DataCategory.PUBLIC, DataCategory.INTERNAL]) == expected
    assert DataCategory.highest([DataCategory.PII, DataCategory.PCI]) == DataCategory.PCI
    assert DataCategory.highest([DataCategory.PCI, DataCategory.PHI]) == DataCategory.PHI


def test_classify_builtin_rules():
    classifier = DataClassifier()

    # Demographic / names
    surname_cf = classifier.classify_finding("surname")
    assert surname_cf.primary_category == DataCategory.PII
    assert "name" in surname_cf.sub_labels

    given_cf = classifier.classify_finding("given_name")
    assert given_cf.primary_category == DataCategory.PII

    # Health / PHI
    med_cf = classifier.classify_finding("medical_condition")
    assert med_cf.primary_category == DataCategory.PHI
    assert "condition" in med_cf.sub_labels

    drug_cf = classifier.classify_finding("drug_name")
    assert drug_cf.primary_category == DataCategory.PHI

    hosp_cf = classifier.classify_finding("hospital_name")
    assert hosp_cf.primary_category == DataCategory.PHI

    # Contact
    phone_cf = classifier.classify_finding("tr_phone_strict")
    assert phone_cf.primary_category == DataCategory.PII
    assert "phone" in phone_cf.sub_labels

    # Financial / VAT
    vat_de_cf = classifier.classify_finding("vat_de")
    assert vat_de_cf.primary_category == DataCategory.CONFIDENTIAL
    assert "vat" in vat_de_cf.sub_labels

    vat_tr_cf = classifier.classify_finding("vat_tr")
    assert vat_tr_cf.primary_category == DataCategory.CONFIDENTIAL


def test_classify_custom_rule_id_override():
    rule = CustomClassificationRule(
        matches_rule_id="email",
        primary_category=DataCategory.CONFIDENTIAL,
        sub_labels=["custom_email"],
        description="Company internal email",
    )
    classifier = DataClassifier(custom_rules=[rule])
    cf = classifier.classify_finding("email")
    assert cf.primary_category == DataCategory.CONFIDENTIAL
    assert cf.sub_labels == ["custom_email"]
    assert cf.description == "Company internal email"


def test_classify_custom_rule_category_override():
    rule = CustomClassificationRule(
        matches_pii_category="custom_health",
        primary_category=DataCategory.PHI,
        sub_labels=["health", "custom"],
        description="Custom health match",
    )
    classifier = DataClassifier(custom_rules=[rule])
    cf = classifier.classify_finding("some_custom_detector", pii_category="custom_health")
    assert cf.primary_category == DataCategory.PHI
    assert cf.sub_labels == ["health", "custom"]


def test_classify_category_fallback():
    classifier = DataClassifier()
    # Unregistered detector ID with known pii_category
    cf = classifier.classify_finding("lab_result_detector", pii_category="health")
    assert cf.primary_category == DataCategory.PHI
    assert "health" in cf.sub_labels

    cf_contact = classifier.classify_finding("slack_handle", pii_category="contact")
    assert cf_contact.primary_category == DataCategory.PII


def test_classify_unknown_rule_and_category_defaults():
    classifier = DataClassifier()
    cf = classifier.classify_finding("totally_unknown_rule", pii_category="unknown_category")
    assert cf.primary_category == DataCategory.INTERNAL
    assert cf.sub_labels == ["unclassified"]


def test_classify_scan_and_build_inventory():
    classifier = DataClassifier()
    raw_findings = [
        {
            "rule_id": "medical_condition",
            "column_name": "diagnosis",
            "confidence": 0.8,
            "severity": 0.9,
        },
        {"rule_id": "surname", "column_name": "last_name", "confidence": 0.9, "severity": 0.5},
        {"rule_id": "credit_card", "column_name": "cc_num", "confidence": 1.0, "severity": 0.85},
        {"rule_id": "ipv4_address", "column_name": "src_ip", "confidence": 0.9, "severity": 0.4},
    ]
    classified = classifier.classify_scan(raw_findings)
    assert len(classified) == 4

    inventory = classifier.build_inventory(classified)
    # Order must be ranked: PHI > PCI > PII > Internal
    categories = [entry.category for entry in inventory]
    expected_categories = [
        DataCategory.PHI,
        DataCategory.PCI,
        DataCategory.PII,
        DataCategory.INTERNAL,
    ]
    assert categories == expected_categories

    inventory_dict = classifier.inventory_to_dict(inventory)
    assert len(inventory_dict) == 4
    phi_entry = inventory_dict[0]
    assert phi_entry["category"] == DataCategory.PHI
    assert phi_entry["finding_count"] == 1
    assert "diagnosis" in phi_entry["column_names"]
    assert "medical_condition" in phi_entry["rule_ids"]
