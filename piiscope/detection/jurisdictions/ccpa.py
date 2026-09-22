"""CCPA (California Consumer Privacy Act) compliance profile.

Regulation: California Civil Code §§ 1798.100 - 1798.199 (CCPA 2018),
amended by CPRA 2020 (effective January 1 2023).
Territorial scope: for-profit businesses that collect personal information
of California residents exceeding specified thresholds.

Key CCPA categories of personal information (§ 1798.140(v)):
  A. Identifiers (name, email, IP address, etc.)
  B. Customer records information
  C. Protected characteristics under California / federal law
  D. Commercial information
  E. Biometric information
  F. Internet / electronic network activity
  G. Geolocation data
  H. Sensory data
  I. Professional / employment-related information
  J. Education information
  K. Inferences drawn from above categories
  L. Sensitive personal information (CPRA addition)

Sensitive personal information (§ 1798.121):
  - SSN, driver's license, state ID, passport number
  - Account log-in + credentials
  - Financial account + routing / card numbers
  - Precise geolocation
  - Race, ethnic origin, religion, union membership
  - Contents of mail, email, text messages
  - Genetic data
  - Biometric information
  - Health / sex life / sexual orientation
"""

from __future__ import annotations

from typing import Any

PROFILE: dict[str, dict[str, Any]] = {
    "ner_cardinal": {
        "status": "optional",
        "severity": 0.5,
        "article": "General",
        "obligation": ("Standard obligation"),
        "legal_basis": ["legitimate_interest"],
        "max_fine": "standard",
    },
    "ner_date": {
        "status": "optional",
        "severity": 0.5,
        "article": "General",
        "obligation": ("Standard obligation"),
        "legal_basis": ["legitimate_interest"],
        "max_fine": "standard",
    },
    "ner_loc": {
        "status": "optional",
        "severity": 0.5,
        "article": "General",
        "obligation": ("Standard obligation"),
        "legal_basis": ["legitimate_interest"],
        "max_fine": "standard",
    },
    "ner_org": {
        "status": "optional",
        "severity": 0.5,
        "article": "General",
        "obligation": ("Standard obligation"),
        "legal_basis": ["legitimate_interest"],
        "max_fine": "standard",
    },
    "ner_gpe": {
        "status": "optional",
        "severity": 0.5,
        "article": "General",
        "obligation": ("Standard obligation"),
        "legal_basis": ["legitimate_interest"],
        "max_fine": "standard",
    },
    "ner_person": {
        "status": "optional",
        "severity": 0.5,
        "article": "General",
        "obligation": ("Standard obligation"),
        "legal_basis": ["legitimate_interest"],
        "max_fine": "standard",
    },
    "url": {
        "status": "optional",
        "severity": 0.5,
        "article": "General",
        "obligation": ("Standard obligation"),
        "legal_basis": ["legitimate_interest"],
        "max_fine": "standard",
    },
    "vat_tr": {
        "status": "optional",
        "severity": 0.5,
        "article": "General",
        "obligation": ("Standard obligation"),
        "legal_basis": ["legitimate_interest"],
        "max_fine": "standard",
    },
    "vat_de": {
        "status": "optional",
        "severity": 0.5,
        "article": "General",
        "obligation": ("Standard obligation"),
        "legal_basis": ["legitimate_interest"],
        "max_fine": "standard",
    },
    "tr_phone_strict": {
        "status": "optional",
        "severity": 0.5,
        "article": "General",
        "obligation": ("Standard obligation"),
        "legal_basis": ["legitimate_interest"],
        "max_fine": "standard",
    },
    "iban_tr": {
        "status": "optional",
        "severity": 0.5,
        "article": "General",
        "obligation": ("Standard obligation"),
        "legal_basis": ["legitimate_interest"],
        "max_fine": "standard",
    },
    "passport_uk": {
        "status": "optional",
        "severity": 0.5,
        "article": "General",
        "obligation": ("Standard obligation"),
        "legal_basis": ["legitimate_interest"],
        "max_fine": "standard",
    },
    "passport_de": {
        "status": "optional",
        "severity": 0.5,
        "article": "General",
        "obligation": ("Standard obligation"),
        "legal_basis": ["legitimate_interest"],
        "max_fine": "standard",
    },
    "passport_tr": {
        "status": "optional",
        "severity": 0.5,
        "article": "General",
        "obligation": ("Standard obligation"),
        "legal_basis": ["legitimate_interest"],
        "max_fine": "standard",
    },
    "swift_bic": {
        "status": "optional",
        "severity": 0.5,
        "article": "General",
        "obligation": ("Standard obligation"),
        "legal_basis": ["legitimate_interest"],
        "max_fine": "standard",
    },
    "medical_condition": {
        "status": "optional",
        "severity": 0.5,
        "article": "General",
        "obligation": ("Standard obligation"),
        "legal_basis": ["legitimate_interest"],
        "max_fine": "standard",
    },
    "surname": {
        "status": "optional",
        "severity": 0.5,
        "article": "General",
        "obligation": ("Standard obligation"),
        "legal_basis": ["legitimate_interest"],
        "max_fine": "standard",
    },
    # ------------------------------------------------------------------
    # Category A - Identifiers  (§ 1798.140(v)(A))
    # ------------------------------------------------------------------
    "email": {
        "status": "required",
        "severity": 0.5,
        "article": "§ 1798.140(v)(A) - Identifier",
        "obligation": (
            "Email addresses are identifiers under CCPA. Businesses must "
            "disclose collection in privacy notice, honour deletion / opt-out "
            "requests, and implement reasonable security."
        ),
        "consumer_rights": ["know", "delete", "opt_out_of_sale"],
        "is_sensitive": False,
    },
    "given_name": {
        "status": "required",
        "severity": 0.4,
        "article": "§ 1798.140(v)(A) - Identifier",
        "obligation": (
            "Names are identifiers. Disclose in privacy notice; honour consumer rights requests."
        ),
        "consumer_rights": ["know", "delete", "opt_out_of_sale"],
        "is_sensitive": False,
    },
    "ipv4_address": {
        "status": "required",
        "severity": 0.4,
        "article": "§ 1798.140(v)(A) - Identifier (IP address)",
        "obligation": (
            "IP addresses are explicitly listed as identifiers under CCPA. "
            "Disclose collection and provide opt-out mechanism for sale/sharing."
        ),
        "consumer_rights": ["know", "delete", "opt_out_of_sale"],
        "is_sensitive": False,
    },
    "ipv6_address": {
        "status": "required",
        "severity": 0.4,
        "article": "§ 1798.140(v)(A) - Identifier (IP address)",
        "obligation": (
            "IPv6 addresses are identifiers under CCPA. Apply same obligations as IPv4."
        ),
        "consumer_rights": ["know", "delete", "opt_out_of_sale"],
        "is_sensitive": False,
    },
    # ------------------------------------------------------------------
    # Contact information
    # ------------------------------------------------------------------
    "us_phone": {
        "status": "required",
        "severity": 0.5,
        "article": "§ 1798.140(v)(A) - Identifier",
        "obligation": (
            "Phone numbers are identifiers. Disclose collection in privacy "
            "notice; honour deletion and opt-out requests."
        ),
        "consumer_rights": ["know", "delete", "opt_out_of_sale"],
        "is_sensitive": False,
    },
    "eu_phone": {
        "status": "optional",
        "severity": 0.4,
        "article": "§ 1798.140(v)(A)",
        "obligation": (
            "Non-US phone numbers are still identifiers if they relate to California residents."
        ),
        "consumer_rights": ["know", "delete"],
        "is_sensitive": False,
    },
    "tr_phone": {
        "status": "optional",
        "severity": 0.4,
        "article": "§ 1798.140(v)(A)",
        "obligation": (
            "Non-US phone numbers are still identifiers if they relate to California residents."
        ),
        "consumer_rights": ["know", "delete"],
        "is_sensitive": False,
    },
    # ------------------------------------------------------------------
    # Category L - Sensitive personal information  (CPRA § 1798.121)
    # ------------------------------------------------------------------
    "us_ssn": {
        "status": "required",
        "severity": 1.0,
        "article": "§ 1798.121(a) - Sensitive PI (SSN)",
        "obligation": (
            "SSNs are sensitive personal information under CPRA. Businesses "
            "must disclose use, limit processing to disclosed purposes, and "
            "provide the right to limit use / disclosure."
        ),
        "consumer_rights": ["know", "delete", "opt_out_of_sale", "limit_use"],
        "is_sensitive": True,
    },
    "passport": {
        "status": "required",
        "severity": 0.9,
        "article": "§ 1798.121(a) - Sensitive PI (government ID)",
        "obligation": (
            "Passport numbers are sensitive personal information. Apply "
            "CPRA use-limitation requirements."
        ),
        "consumer_rights": ["know", "delete", "opt_out_of_sale", "limit_use"],
        "is_sensitive": True,
    },
    "national_id": {
        "status": "required",
        "severity": 0.9,
        "article": "§ 1798.121(a) - Sensitive PI (government ID)",
        "obligation": (
            "National / government ID numbers are sensitive PI. "
            "Apply CPRA use-limitation obligations."
        ),
        "consumer_rights": ["know", "delete", "limit_use"],
        "is_sensitive": True,
    },
    "tc_kimlik": {
        "status": "required",
        "severity": 0.9,
        "article": "§ 1798.121(a) - Sensitive PI (government ID)",
        "obligation": (
            "National / government ID numbers are sensitive PI. "
            "Apply CPRA use-limitation obligations."
        ),
        "consumer_rights": ["know", "delete", "limit_use"],
        "is_sensitive": True,
    },
    # ------------------------------------------------------------------
    # Financial account numbers  (§ 1798.121(a))
    # ------------------------------------------------------------------
    "credit_card": {
        "status": "required",
        "severity": 0.9,
        "article": "§ 1798.121(a) - Sensitive PI (financial account + credentials)",
        "obligation": (
            "Credit card numbers combined with access credentials are sensitive "
            "PI under CPRA. Limit use to disclosed purposes; provide right to "
            "limit. Also implicate § 1798.150 (data breach liability)."
        ),
        "consumer_rights": ["know", "delete", "limit_use"],
        "is_sensitive": True,
    },
    "iban": {
        "status": "required",
        "severity": 0.8,
        "article": "§ 1798.121(a) - Sensitive PI (financial account)",
        "obligation": (
            "Bank account numbers (IBAN) are sensitive PI under CPRA. "
            "Limit collection and processing to necessary business purposes."
        ),
        "consumer_rights": ["know", "delete", "limit_use"],
        "is_sensitive": True,
    },
    # ------------------------------------------------------------------
    # Health data  (§ 1798.121(a) - health and medical conditions)
    # ------------------------------------------------------------------
    "medical_record": {
        "status": "required",
        "severity": 1.0,
        "article": "§ 1798.121(a) - Sensitive PI (health condition / medical history)",
        "obligation": (
            "Medical records are sensitive PI. Processing must be limited to "
            "disclosed purposes; consumers have the right to limit use and "
            "disclosure."
        ),
        "consumer_rights": ["know", "delete", "opt_out_of_sale", "limit_use"],
        "is_sensitive": True,
    },
    "drug_name": {
        "status": "required",
        "severity": 0.8,
        "article": "§ 1798.121(a) - Sensitive PI (health condition)",
        "obligation": (
            "Drug / medication names in association with individuals reveal "
            "health conditions and are sensitive PI under CPRA."
        ),
        "consumer_rights": ["know", "delete", "limit_use"],
        "is_sensitive": True,
    },
    "hospital_name": {
        "status": "optional",
        "severity": 0.6,
        "article": "§ 1798.121(a) - potentially health-related",
        "obligation": (
            "Hospital names in context may reveal health information. "
            "Review whether they qualify as sensitive PI."
        ),
        "consumer_rights": ["know", "delete"],
        "is_sensitive": False,
    },
    # ------------------------------------------------------------------
    # Demographic / quasi-identifiers
    # ------------------------------------------------------------------
    "date": {
        "status": "optional",
        "severity": 0.3,
        "article": "§ 1798.140(v)(A) - potentially an identifier",
        "obligation": (
            "Dates of birth are identifiers and contribute to re-identification. "
            "Disclose if collected; include in deletion requests."
        ),
        "consumer_rights": ["know", "delete"],
        "is_sensitive": False,
    },
    "vat": {
        "status": "optional",
        "severity": 0.2,
        "article": "§ 1798.140(v)(A)",
        "obligation": (
            "VAT numbers of California sole traders are personal information. "
            "Include in privacy notice if collected."
        ),
        "consumer_rights": ["know", "delete"],
        "is_sensitive": False,
    },
}
