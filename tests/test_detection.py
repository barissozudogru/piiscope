"""Tests for improved PII detection: checksums, context-awareness, new patterns."""

from __future__ import annotations

import os
import sys

# Allow importing without a full app installation
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pandas as pd

from piiscope.detection.engine import DetectionEngine
from piiscope.detection.regex_patterns import PATTERNS, build_custom_patterns
from piiscope.detection.validators import (
    column_name_context_boost,
    iban_check,
    is_private_ip,
    is_valid_ipv4,
    luhn_check,
    tc_kimlik_check,
)
from piiscope.metrics.metrics import (
    compute_k_anonymity,
    compute_l_diversity,
    compute_reidentification_risk,
    compute_t_closeness,
    estimate_dp_epsilon,
    generate_privacy_impact_assessment,
    get_masking_recommendations,
)

# ============================================================================
# Luhn algorithm tests
# ============================================================================


class TestLuhnCheck:
    def test_valid_visa(self):
        assert luhn_check("4111111111111111") is True

    def test_valid_mastercard(self):
        assert luhn_check("5500005555555559") is True

    def test_valid_amex(self):
        assert luhn_check("378282246310005") is True

    def test_valid_with_spaces(self):
        assert luhn_check("4111 1111 1111 1111") is True

    def test_valid_with_hyphens(self):
        assert luhn_check("4111-1111-1111-1111") is True

    def test_invalid_card(self):
        assert luhn_check("4111111111111112") is False

    def test_too_short(self):
        assert luhn_check("4111111111") is False

    def test_all_zeros(self):
        # 0000000000000000 passes Luhn mathematically (sum=0, 0%10=0)
        # Real detection relies on card prefix patterns eliminating this
        assert luhn_check("0000000000000000") is True

    def test_random_number_is_not_card(self):
        # This should fail Luhn in almost all cases
        assert luhn_check("1234567890123456") is False

    def test_price_like_number_fails(self):
        # "EUR 1,299.99" should not match after stripping non-digits
        # 129999 is only 6 digits → fails length check
        assert luhn_check("129999") is False


# ============================================================================
# IBAN validation tests
# ============================================================================


class TestIBANCheck:
    def test_valid_german_iban(self):
        assert iban_check("DE89370400440532013000") is True

    def test_valid_turkish_iban(self):
        assert iban_check("TR330006100519786457841326") is True

    def test_valid_gb_iban(self):
        assert iban_check("GB29NWBK60161331926819") is True

    def test_invalid_checksum(self):
        # Change a digit in the checksum position
        assert iban_check("DE00370400440532013000") is False

    def test_wrong_length_for_country(self):
        # DE IBANs are 22 chars; this is 20
        assert iban_check("DE8937040044053201") is False

    def test_random_alpha_string(self):
        assert iban_check("ABCDEFGHIJKLMNOPQRSTUV") is False

    def test_with_spaces(self):
        # Spaces should be stripped before validation
        assert iban_check("DE89 3704 0044 0532 0130 00") is True


# ============================================================================
# TC Kimlik validation tests
# ============================================================================


class TestTCKimlikCheck:
    def test_valid_tc_kimlik(self):
        # A well-known valid TC Kimlik test number
        assert tc_kimlik_check("10000000146") is True

    def test_first_digit_zero_is_invalid(self):
        assert tc_kimlik_check("00000000146") is False

    def test_wrong_length(self):
        assert tc_kimlik_check("1234567890") is False

    def test_invalid_checksum(self):
        assert tc_kimlik_check("10000000147") is False

    def test_all_same_digit(self):
        # 11111111110 satisfies both checksum rules mathematically
        # Real protection relies on official registry checks outside scope of local validation
        assert tc_kimlik_check("11111111110") is True


# ============================================================================
# IPv4 tests
# ============================================================================


class TestIPv4:
    def test_valid_public_ip(self):
        assert is_valid_ipv4("8.8.8.8") is True

    def test_private_10_range(self):
        assert is_private_ip("10.0.0.1") is True

    def test_private_192_168(self):
        assert is_private_ip("192.168.1.100") is True

    def test_private_172_16(self):
        assert is_private_ip("172.16.5.5") is True

    def test_loopback(self):
        assert is_private_ip("127.0.0.1") is True

    def test_public_ip_not_private(self):
        assert is_private_ip("8.8.8.8") is False

    def test_invalid_octet(self):
        assert is_valid_ipv4("256.1.1.1") is False

    def test_too_few_octets(self):
        assert is_valid_ipv4("192.168.1") is False


# ============================================================================
# Context-aware confidence tests
# ============================================================================


class TestColumnNameContext:
    def test_email_in_email_column_boosts(self):
        mult = column_name_context_boost("email", "email")
        assert mult > 1.0

    def test_email_in_description_column_downgrades(self):
        mult = column_name_context_boost("description", "email")
        assert mult < 1.0

    def test_name_in_name_column_boosts(self):
        mult = column_name_context_boost("full_name", "given_name")
        assert mult > 1.0

    def test_name_in_product_column_downgrades(self):
        mult = column_name_context_boost("product", "given_name")
        assert mult < 1.0

    def test_credit_card_in_card_column_boosts(self):
        mult = column_name_context_boost("credit_card_number", "credit_card")
        assert mult > 1.0

    def test_credit_card_in_order_id_column_downgrades(self):
        mult = column_name_context_boost("order_id", "credit_card")
        assert mult < 1.0

    def test_phone_in_phone_column_boosts(self):
        mult = column_name_context_boost("phone_number", "eu_phone")
        assert mult > 1.0

    def test_neutral_column_returns_one(self):
        mult = column_name_context_boost("data", "email")
        assert mult == 1.0


# ============================================================================
# Regex pattern tests
# ============================================================================


class TestPatterns:
    def test_email_matches(self):
        assert PATTERNS["email"].pattern.search("user@example.com")

    def test_email_no_false_positive_on_plain_text(self):
        assert not PATTERNS["email"].pattern.search("not an email address")

    def test_us_ssn_pattern(self):
        assert PATTERNS["us_ssn"].pattern.search("123-45-6789")

    def test_us_ssn_rejects_all_zeros(self):
        # 000-xx-xxxx is invalid
        assert not PATTERNS["us_ssn"].pattern.search("000-45-6789")

    def test_ipv4_matches_valid(self):
        assert PATTERNS["ipv4_address"].pattern.search("192.168.1.1")

    def test_ipv6_matches_full(self):
        assert PATTERNS["ipv6_address"].pattern.search("2001:0db8:85a3:0000:0000:8a2e:0370:7334")

    def test_medical_record_matches(self):
        assert PATTERNS["medical_record"].pattern.search("MRN: 1234567")

    def test_tr_phone_matches(self):
        assert PATTERNS["tr_phone"].pattern.search("+90 532 123 4567")

    def test_us_phone_matches(self):
        assert PATTERNS["us_phone"].pattern.search("(212) 555-1234")

    def test_vat_matches_known_eu(self):
        assert PATTERNS["vat"].pattern.search("DE123456789")

    def test_vat_does_not_match_non_eu_prefix(self):
        # "XX" is not a valid EU VAT prefix in our pattern
        assert not PATTERNS["vat"].pattern.search("XX12345678")


# ============================================================================
# Custom pattern support tests
# ============================================================================


class TestCustomPatterns:
    def test_build_custom_pattern_basic(self):
        custom_defs = [
            {
                "id": "employee_id",
                "pattern": r"\bEMP[0-9]{5}\b",
                "description": "Employee ID",
                "severity": 0.6,
            }
        ]
        result = build_custom_patterns(custom_defs)
        assert "employee_id" in result
        assert result["employee_id"].pattern.search("EMP12345")

    def test_invalid_regex_is_skipped(self, capsys):
        custom_defs = [
            {"id": "bad", "pattern": r"[invalid(", "description": "Bad", "severity": 0.5}
        ]
        result = build_custom_patterns(custom_defs)
        assert "bad" not in result

    def test_missing_id_is_skipped(self):
        custom_defs = [{"pattern": r"\bEMP[0-9]{5}\b", "description": "No ID", "severity": 0.5}]
        result = build_custom_patterns(custom_defs)
        assert len(result) == 0

    def test_severity_clamped_to_range(self):
        custom_defs = [
            {"id": "test", "pattern": r"\bTEST\b", "description": "Test", "severity": 5.0}
        ]
        result = build_custom_patterns(custom_defs)
        assert result["test"].severity == 1.0


# ============================================================================
# Detection engine tests
# ============================================================================


class TestDetectionEngine:
    def setup_method(self):
        self.engine = DetectionEngine({})

    def test_detects_valid_visa_card(self):
        findings = self.engine.detect_cell("4111111111111111", "payment")
        rule_ids = [f.rule_id for f in findings]
        assert "credit_card" in rule_ids

    def test_rejects_invalid_credit_card(self):
        # Fails Luhn
        findings = self.engine.detect_cell("4111111111111112", "payment")
        rule_ids = [f.rule_id for f in findings]
        assert "credit_card" not in rule_ids

    def test_detects_valid_iban(self):
        findings = self.engine.detect_cell("DE89370400440532013000", "account")
        rule_ids = [f.rule_id for f in findings]
        assert "iban" in rule_ids

    def test_rejects_invalid_iban(self):
        findings = self.engine.detect_cell("DE00370400440532013000", "account")
        rule_ids = [f.rule_id for f in findings]
        assert "iban" not in rule_ids

    def test_detects_email(self):
        findings = self.engine.detect_cell("alice@example.com", "email")
        rule_ids = [f.rule_id for f in findings]
        assert "email" in rule_ids

    def test_detects_ipv4(self):
        findings = self.engine.detect_cell("8.8.8.8", "server_ip")
        rule_ids = [f.rule_id for f in findings]
        assert "ipv4_address" in rule_ids

    def test_private_ip_lower_confidence(self):
        findings = self.engine.detect_cell("192.168.1.1", "source_ip")
        ip_findings = [f for f in findings if f.rule_id == "ipv4_address"]
        assert len(ip_findings) > 0
        # Private IPs get reduced confidence
        assert ip_findings[0].confidence < 0.8

    def test_public_ip_standard_confidence(self):
        findings = self.engine.detect_cell("8.8.8.8", "source_ip")
        ip_findings = [f for f in findings if f.rule_id == "ipv4_address"]
        assert len(ip_findings) > 0
        assert ip_findings[0].confidence >= 0.8

    def test_tc_kimlik_valid(self):
        findings = self.engine.detect_cell("10000000146", "tc_no")
        rule_ids = [f.rule_id for f in findings]
        assert "tc_kimlik" in rule_ids

    def test_tc_kimlik_invalid_rejected(self):
        findings = self.engine.detect_cell("10000000147", "tc_no")
        rule_ids = [f.rule_id for f in findings]
        assert "tc_kimlik" not in rule_ids

    def test_suppression_rule_removes_finding(self):
        engine_with_suppression = DetectionEngine(
            {"suppression_rules": [{"rule_id": "email", "column_name": "contact"}]}
        )
        findings = engine_with_suppression.detect_cell("alice@example.com", "contact")
        rule_ids = [f.rule_id for f in findings]
        assert "email" not in rule_ids

    def test_suppression_only_affects_matching_column(self):
        engine_with_suppression = DetectionEngine(
            {"suppression_rules": [{"rule_id": "email", "column_name": "contact"}]}
        )
        # "email" column is NOT suppressed, only "contact"
        findings = engine_with_suppression.detect_cell("alice@example.com", "email")
        rule_ids = [f.rule_id for f in findings]
        assert "email" in rule_ids

    def test_custom_patterns_loaded_from_profile(self):
        engine_custom = DetectionEngine(
            {
                "custom_patterns": [
                    {
                        "id": "employee_id",
                        "pattern": r"\bEMP[0-9]{5}\b",
                        "description": "Employee ID",
                        "severity": 0.6,
                    }
                ]
            }
        )
        findings = engine_custom.detect_cell("EMP12345", "staff_id")
        rule_ids = [f.rule_id for f in findings]
        assert "employee_id" in rule_ids

    def test_name_in_name_column_higher_confidence(self):
        engine = DetectionEngine({})
        findings_name = engine.detect_cell("john", "full_name")
        findings_desc = engine.detect_cell("john", "description")
        name_conf = next((f.confidence for f in findings_name if f.rule_id == "given_name"), 0)
        desc_conf = next((f.confidence for f in findings_desc if f.rule_id == "given_name"), 0)
        # Name column should have higher or equal confidence
        assert name_conf >= desc_conf

    def test_empty_cell_returns_no_findings(self):
        findings = self.engine.detect_cell("", "name")
        assert findings == []

    def test_scan_row_sets_record_index(self):
        row = {"email": "test@example.com", "name": "John"}
        findings = self.engine.scan_row(row, 42)
        for f in findings:
            assert f.record_index == 42


# ============================================================================
# Privacy metrics tests
# ============================================================================


class TestPrivacyMetrics:
    def _sample_df(self):
        return pd.DataFrame(
            {
                "age": ["25", "25", "30", "30", "30"],
                "zip": ["12345", "12345", "12345", "67890", "67890"],
                "disease": ["flu", "flu", "flu", "cold", "cancer"],
            }
        )

    def test_k_anonymity(self):
        df = self._sample_df()
        k = compute_k_anonymity(df, ["age", "zip"])
        assert k == 1  # (30, 67890) has 2, (30, 12345) has 1, (25, 12345) has 2

    def test_k_anonymity_empty_df(self):
        assert compute_k_anonymity(pd.DataFrame(), ["age"]) is None

    def test_k_anonymity_missing_column(self):
        df = self._sample_df()
        # Non-existent column is ignored; result uses available columns
        k = compute_k_anonymity(df, ["age", "nonexistent"])
        assert k is not None  # should still compute on "age" alone

    def test_l_diversity(self):
        df = self._sample_df()
        l_div = compute_l_diversity(df, ["age", "zip"], "disease")
        # (30, 67890) has cold+cancer = 2 distinct; (30, 12345) has 1; (25, 12345) has 1
        assert l_div == 1

    def test_l_diversity_missing_sensitive_attr(self):
        df = self._sample_df()
        assert compute_l_diversity(df, ["age"], "nonexistent") is None

    def test_t_closeness_range(self):
        df = self._sample_df()
        t = compute_t_closeness(df, ["age", "zip"], "disease")
        assert t is not None
        assert 0.0 <= t <= 1.0

    def test_reidentification_risk_unique_records(self):
        df = pd.DataFrame(
            {
                "age": ["25", "30", "35", "40"],
                "zip": ["10001", "10002", "10003", "10004"],
            }
        )
        risk = compute_reidentification_risk(df, ["age", "zip"])
        # All records are unique → prosecutor_risk = 1.0
        assert risk["prosecutor_risk"] == 1.0
        assert risk["unique_records"] == 4
        assert risk["risk_level"] == "critical"

    def test_reidentification_risk_large_groups(self):
        df = pd.DataFrame(
            {
                "age": ["25"] * 100,
                "zip": ["10001"] * 100,
            }
        )
        risk = compute_reidentification_risk(df, ["age", "zip"])
        # All 100 records in one group → risk = 0.01
        assert risk["prosecutor_risk"] == 0.01
        assert risk["risk_level"] == "low"

    def test_reidentification_risk_empty(self):
        risk = compute_reidentification_risk(pd.DataFrame(), [])
        assert risk["prosecutor_risk"] is None
        assert risk["risk_level"] == "unknown"


# ============================================================================
# Differential privacy estimation tests
# ============================================================================


class TestDPEpsilon:
    def test_numeric_column_returns_epsilon(self):
        df = pd.DataFrame({"age": [20, 30, 40, 50, 60]})
        result = estimate_dp_epsilon(df, ["age"])
        assert "age" in result["columns"]
        assert result["columns"]["age"]["epsilon"] is not None
        assert result["columns"]["age"]["epsilon"] > 0

    def test_missing_column(self):
        df = pd.DataFrame({"age": [20, 30]})
        result = estimate_dp_epsilon(df, ["salary"])
        assert result["columns"]["salary"]["epsilon"] is None
        assert "not found" in result["columns"]["salary"]["reason"]

    def test_constant_column(self):
        df = pd.DataFrame({"age": [25, 25, 25]})
        result = estimate_dp_epsilon(df, ["age"])
        assert result["columns"]["age"]["epsilon"] is None

    def test_gaussian_mechanism(self):
        df = pd.DataFrame({"salary": [30000, 50000, 70000, 90000]})
        result = estimate_dp_epsilon(df, ["salary"], noise_mechanism="gaussian")
        assert result["mechanism"] == "gaussian"
        assert result["columns"]["salary"]["epsilon"] is not None


# ============================================================================
# Masking recommendations tests
# ============================================================================


class TestMaskingRecommendations:
    def test_financial_category(self):
        recs = get_masking_recommendations({"financial"})
        assert "financial" in recs
        assert recs["financial"]["primary"] == "tokenize"

    def test_health_category_requires_null_or_hash(self):
        recs = get_masking_recommendations({"health"})
        assert recs["health"]["primary"] in ("null", "hash", "redact")

    def test_multiple_categories(self):
        recs = get_masking_recommendations({"financial", "contact", "health"})
        assert len(recs) == 3

    def test_unknown_category_falls_back_to_other(self):
        recs = get_masking_recommendations({"totally_unknown_category"})
        # Unknown categories fall back to "other" recommendations
        assert len(recs) > 0


# ============================================================================
# Privacy Impact Assessment tests
# ============================================================================


class TestPIA:
    def test_pia_structure(self):
        pia = generate_privacy_impact_assessment(
            findings_summary={
                "total_findings": 50,
                "pii_categories": ["financial", "contact"],
                "highest_severity": 0.8,
                "rules_triggered": ["credit_card", "email"],
            },
            k_anonymity=2,
            l_diversity=1,
            t_closeness=0.35,
            reidentification_risk={
                "prosecutor_risk": 0.5,
                "journalist_risk": 0.4,
                "marketer_risk": 0.3,
                "risk_level": "critical",
                "unique_records": 5,
                "equivalence_classes": 10,
            },
        )
        assert "overall_risk_score" in pia
        assert "risk_level" in pia
        assert "compliance_gaps" in pia
        assert "masking_recommendations" in pia
        assert "jurisdiction_applicability" in pia
        assert "retention_recommendations_days" in pia

    def test_pia_detects_health_gap(self):
        pia = generate_privacy_impact_assessment(
            findings_summary={
                "total_findings": 10,
                "pii_categories": ["health"],
                "highest_severity": 0.9,
                "rules_triggered": ["medical_record"],
            },
            k_anonymity=5,
            l_diversity=3,
            t_closeness=0.1,
            reidentification_risk=None,
        )
        gap_frameworks = [g["framework"] for g in pia["compliance_gaps"]]
        assert any("GDPR" in f for f in gap_frameworks)
        assert any("KVKK" in f for f in gap_frameworks)

    def test_pia_risk_score_increases_with_severity(self):
        pia_low = generate_privacy_impact_assessment(
            findings_summary={
                "total_findings": 1,
                "pii_categories": ["other"],
                "highest_severity": 0.1,
                "rules_triggered": [],
            },
            k_anonymity=20,
            l_diversity=5,
            t_closeness=0.05,
            reidentification_risk=None,
        )
        pia_high = generate_privacy_impact_assessment(
            findings_summary={
                "total_findings": 200,
                "pii_categories": ["financial", "health", "national_id"],
                "highest_severity": 0.95,
                "rules_triggered": ["credit_card", "medical_record", "tc_kimlik"],
            },
            k_anonymity=1,
            l_diversity=1,
            t_closeness=0.5,
            reidentification_risk={
                "prosecutor_risk": 1.0,
                "journalist_risk": 0.9,
                "marketer_risk": 0.8,
                "risk_level": "critical",
                "unique_records": 200,
                "equivalence_classes": 200,
            },
        )
        assert pia_high["overall_risk_score"] > pia_low["overall_risk_score"]

    def test_jurisdiction_flags_kvkk_for_tc_kimlik(self):
        pia = generate_privacy_impact_assessment(
            findings_summary={
                "total_findings": 5,
                "pii_categories": ["national_id"],
                "highest_severity": 0.9,
                "rules_triggered": ["tc_kimlik"],
            },
            k_anonymity=None,
            l_diversity=None,
            t_closeness=None,
            reidentification_risk=None,
        )
        assert pia["jurisdiction_applicability"]["KVKK"] is True

    def test_jurisdiction_flags_pci_for_financial(self):
        pia = generate_privacy_impact_assessment(
            findings_summary={
                "total_findings": 3,
                "pii_categories": ["financial"],
                "highest_severity": 0.8,
                "rules_triggered": ["credit_card"],
            },
            k_anonymity=None,
            l_diversity=None,
            t_closeness=None,
            reidentification_risk=None,
        )
        assert pia["jurisdiction_applicability"]["PCI_DSS"] is True
