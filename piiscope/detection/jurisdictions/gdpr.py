"""GDPR (General Data Protection Regulation) compliance profile.

Regulation: EU 2016/679 (GDPR), effective May 25 2018.
Territorial scope: applies to processing of EU/EEA data subjects' personal data.

Each entry maps a detection rule_id to:
  - status      : "required" means this data type is explicitly regulated;
                  "optional" means it may be relevant depending on context.
  - severity    : 0.0 - 1.0; reflects the category's risk under GDPR.
                  1.0 is reserved for Special Category data (Art. 9) and
                  criminal convictions (Art. 10).
  - article     : the primary GDPR article governing this data type.
  - obligation  : the core compliance obligation.
  - legal_basis : the required lawful basis options for processing.
  - max_fine    : maximum GDPR fine tier applicable ("standard" = 2% global
                  turnover; "higher" = 4% global turnover).
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
    # Basic personal identifiers  (Art. 4(1) - personal data definition)
    # ------------------------------------------------------------------
    "email": {
        "status": "required",
        "severity": 0.5,
        "article": "Art. 4(1), Art. 5(1)(c)",
        "obligation": (
            "Email addresses are personal data under Art. 4(1). Apply data "
            "minimisation (Art. 5(1)(c)) and storage limitation (Art. 5(1)(e))."
        ),
        "legal_basis": ["consent", "contract", "legitimate_interest"],
        "max_fine": "standard",
    },
    "given_name": {
        "status": "required",
        "severity": 0.4,
        "article": "Art. 4(1), Art. 5(1)(c)",
        "obligation": (
            "Names are personal data. Minimise collection and apply appropriate retention limits."
        ),
        "legal_basis": ["consent", "contract", "legitimate_interest"],
        "max_fine": "standard",
    },
    # ------------------------------------------------------------------
    # Contact information
    # ------------------------------------------------------------------
    "eu_phone": {
        "status": "required",
        "severity": 0.5,
        "article": "Art. 4(1), Art. 5(1)(c)",
        "obligation": ("Phone numbers are personal data. Document purpose and retention."),
        "legal_basis": ["consent", "contract", "legitimate_interest"],
        "max_fine": "standard",
    },
    "us_phone": {
        "status": "optional",
        "severity": 0.4,
        "article": "Art. 4(1)",
        "obligation": (
            "US phone numbers may relate to EU data subjects. Apply GDPR if subject is EU-based."
        ),
        "legal_basis": ["consent", "contract"],
        "max_fine": "standard",
    },
    "tr_phone": {
        "status": "required",
        "severity": 0.5,
        "article": "Art. 4(1)",
        "obligation": "Phone numbers are personal data. Document purpose and retention.",
        "legal_basis": ["consent", "contract", "legitimate_interest"],
        "max_fine": "standard",
    },
    # ------------------------------------------------------------------
    # Financial data
    # ------------------------------------------------------------------
    "credit_card": {
        "status": "required",
        "severity": 0.8,
        "article": "Art. 25 (Data Protection by Design); Art. 32",
        "obligation": (
            "Credit card numbers are personal financial data. Tokenise or "
            "truncate; avoid storing PAN in plaintext. Ensure appropriate "
            "technical measures (Art. 32)."
        ),
        "legal_basis": ["contract", "legal_obligation"],
        "max_fine": "higher",
    },
    "iban": {
        "status": "required",
        "severity": 0.7,
        "article": "Art. 25; Art. 32",
        "obligation": (
            "IBAN is a financial identifier linked to an individual. "
            "Encrypt at rest and in transit; apply strict access controls."
        ),
        "legal_basis": ["contract", "legal_obligation"],
        "max_fine": "higher",
    },
    # ------------------------------------------------------------------
    # National identifiers  (Art. 87)
    # ------------------------------------------------------------------
    "us_ssn": {
        "status": "optional",
        "severity": 0.9,
        "article": "Art. 87",
        "obligation": (
            "Member States may set conditions for national ID processing "
            "(Art. 87). US SSNs of EU data subjects must be protected "
            "under standard GDPR requirements."
        ),
        "legal_basis": ["legal_obligation", "public_interest"],
        "max_fine": "higher",
    },
    "national_id": {
        "status": "required",
        "severity": 0.9,
        "article": "Art. 87",
        "obligation": (
            "National ID numbers require a legal basis and appropriate "
            "safeguards under member-state law implementing Art. 87."
        ),
        "legal_basis": ["legal_obligation", "public_interest"],
        "max_fine": "higher",
    },
    "tc_kimlik": {
        "status": "optional",
        "severity": 0.9,
        "article": "Art. 87",
        "obligation": (
            "Turkish national ID of EU data subjects triggers GDPR if "
            "processed by EU establishments or targeting EU subjects."
        ),
        "legal_basis": ["legal_obligation"],
        "max_fine": "higher",
    },
    # ------------------------------------------------------------------
    # Special categories  (Art. 9 - highest protection level)
    # ------------------------------------------------------------------
    "medical_record": {
        "status": "required",
        "severity": 1.0,
        "article": "Art. 9(1)",
        "obligation": (
            "Health data is a Special Category under Art. 9(1). Processing "
            "is prohibited unless one of the Art. 9(2) exceptions applies "
            "(explicit consent, vital interests, healthcare purposes, etc.)."
        ),
        "legal_basis": ["explicit_consent", "vital_interests", "healthcare"],
        "max_fine": "higher",
    },
    "drug_name": {
        "status": "required",
        "severity": 0.9,
        "article": "Art. 9(1) - health data",
        "obligation": (
            "Drug names in the context of individuals constitute health data "
            "(Special Category). Apply Art. 9 restrictions."
        ),
        "legal_basis": ["explicit_consent", "healthcare"],
        "max_fine": "higher",
    },
    "hospital_name": {
        "status": "optional",
        "severity": 0.7,
        "article": "Art. 9(1) - potentially health-related",
        "obligation": (
            "Hospital names in context may reveal health information and "
            "constitute health data under Art. 9(1)."
        ),
        "legal_basis": ["explicit_consent", "healthcare"],
        "max_fine": "higher",
    },
    # ------------------------------------------------------------------
    # Passport / travel documents
    # ------------------------------------------------------------------
    "passport": {
        "status": "required",
        "severity": 0.8,
        "article": "Art. 9(2)(g) if biometric; Art. 87",
        "obligation": (
            "Passport numbers are national identifiers. Biometric data in "
            "passports is Special Category. Collect only when strictly necessary."
        ),
        "legal_basis": ["legal_obligation", "public_interest"],
        "max_fine": "higher",
    },
    # ------------------------------------------------------------------
    # Network / technical identifiers  (Recital 30)
    # ------------------------------------------------------------------
    "ipv4_address": {
        "status": "required",
        "severity": 0.4,
        "article": "Art. 4(1); Recital 30",
        "obligation": (
            "IP addresses are personal data when they can be linked to an "
            "individual (CJEU C-582/14). Anonymise or hash after retention "
            "period; document processing purpose."
        ),
        "legal_basis": ["legitimate_interest", "legal_obligation"],
        "max_fine": "standard",
    },
    "ipv6_address": {
        "status": "required",
        "severity": 0.5,
        "article": "Art. 4(1); Recital 30",
        "obligation": (
            "IPv6 addresses are more individually identifying than IPv4. "
            "Apply the same protections as IPv4 addresses."
        ),
        "legal_basis": ["legitimate_interest", "legal_obligation"],
        "max_fine": "standard",
    },
    # ------------------------------------------------------------------
    # Demographic data
    # ------------------------------------------------------------------
    "date": {
        "status": "optional",
        "severity": 0.3,
        "article": "Art. 5(1)(c)",
        "obligation": (
            "Dates (especially date of birth) contribute to re-identification "
            "risk. Apply data minimisation and generalise where possible."
        ),
        "legal_basis": ["consent", "contract", "legitimate_interest"],
        "max_fine": "standard",
    },
    # ------------------------------------------------------------------
    # Financial VAT numbers
    # ------------------------------------------------------------------
    "vat": {
        "status": "optional",
        "severity": 0.3,
        "article": "Art. 4(1)",
        "obligation": (
            "VAT numbers typically identify legal entities rather than "
            "natural persons; however, sole traders are natural persons and "
            "their VAT number is personal data."
        ),
        "legal_basis": ["legal_obligation", "contract"],
        "max_fine": "standard",
    },
}
