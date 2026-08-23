"""Tests for jurisdiction-aware scanning: gdpr, ccpa, kvkk, lgpd."""

from __future__ import annotations

import os
import sys

import pandas as pd
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from piiscope import scan
from piiscope.detection.jurisdictions import (
    JURISDICTION_PROFILES,
    combine_jurisdictions,
    get_applicable_jurisdictions,
)
from piiscope.errors import PiiscopeError
from piiscope.scan import JURISDICTIONS


def _frame(**columns):
    return pd.DataFrame(columns)


class TestJurisdictionTagging:
    def test_gdpr_tags_email_finding(self):
        result = scan(_frame(email=["anna@example.com"]), jurisdictions=["gdpr"])
        finding = next(f for f in result.findings if f.detector == "email")
        assert "GDPR" in finding.jurisdictions

    def test_kvkk_tags_tc_kimlik_finding(self):
        result = scan(_frame(tckn=["10000000146"]), jurisdictions=["kvkk"])
        finding = next(f for f in result.findings if f.detector == "tc_kimlik")
        assert "KVKK" in finding.jurisdictions

    def test_ccpa_tags_us_ssn_finding(self):
        result = scan(_frame(ssn=["123-45-6789"]), jurisdictions=["ccpa"])
        finding = next(f for f in result.findings if f.detector == "us_ssn")
        assert "CCPA" in finding.jurisdictions

    def test_lgpd_tags_email_finding(self):
        result = scan(_frame(email=["joao@example.com"]), jurisdictions=["lgpd"])
        finding = next(f for f in result.findings if f.detector == "email")
        assert "LGPD" in finding.jurisdictions

    def test_multiple_jurisdictions_merge(self):
        result = scan(_frame(email=["a@example.com"]), jurisdictions=["gdpr", "kvkk"])
        finding = next(f for f in result.findings if f.detector == "email")
        assert finding.jurisdictions == ["GDPR", "KVKK"]

    def test_finding_excluded_when_jurisdiction_does_not_cover_it(self):
        # cpf obligations exist only in the LGPD profile
        result = scan(_frame(cpf=["111.444.777-35"]), jurisdictions=["lgpd"])
        assert result.jurisdictions == ["lgpd"]


class TestBenignInputs:
    def test_benign_values_produce_no_findings(self):
        frame = pd.DataFrame(
            {
                "product": ["keyboard", "monitor"],
                "price": ["29.90", "199.00"],
                "stock": ["14", "3"],
            }
        )
        result = scan(frame, jurisdictions=["all"])
        assert result.findings == []
        assert result.risk.score == 0
        assert result.risk.level == "low"

    def test_empty_strings_are_ignored(self):
        result = scan(_frame(email=["", ""]), jurisdictions=["gdpr"])
        assert result.findings == []


class TestJurisdictionResolution:
    def test_all_expands_to_every_jurisdiction(self):
        result = scan(_frame(email=["a@example.com"]), jurisdictions=["all"])
        assert result.jurisdictions == list(JURISDICTIONS)

    def test_unknown_jurisdiction_raises(self):
        with pytest.raises(PiiscopeError):
            scan(_frame(email=["a@example.com"]), jurisdictions=["lapland"])

    def test_duplicates_are_deduplicated(self):
        result = scan(_frame(email=["a@example.com"]), jurisdictions=["gdpr", "gdpr"])
        assert result.jurisdictions == ["gdpr"]

    def test_jurisdiction_bonus_raises_risk(self):
        gdpr_only = scan(_frame(tckn=["10000000146"]), jurisdictions=["gdpr"])
        kvkk_too = scan(_frame(tckn=["10000000146"]), jurisdictions=["gdpr", "kvkk"])
        assert kvkk_too.risk.score >= gdpr_only.risk.score


class TestProfileHelpers:
    def test_every_profile_is_a_non_empty_dict(self):
        for name, profile in JURISDICTION_PROFILES.items():
            assert isinstance(profile, dict) and profile, name

    def test_combine_jurisdictions_merges_rules(self):
        merged = combine_jurisdictions(["gdpr", "kvkk"])
        assert "email" in merged
        jurisdictions = {entry["jurisdiction"] for entry in merged["email"]}
        assert jurisdictions == {"GDPR", "KVKK"}

    def test_get_applicable_jurisdictions(self):
        applicable = get_applicable_jurisdictions(["cpf"])
        assert applicable == {"cpf": ["LGPD"]}
        applicable = get_applicable_jurisdictions(["tc_kimlik"], ["KVKK"])
        assert applicable == {"tc_kimlik": ["KVKK"]}
