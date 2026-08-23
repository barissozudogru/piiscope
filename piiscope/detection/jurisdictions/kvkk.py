"""KVKK (Kisisel Verilerin Korunmasi Kanunu) compliance profile.

Regulation: Law No. 6698 on the Protection of Personal Data (KVKK),
published April 7 2016, entry into force October 7 2016 (Turkey).
Turkish Data Protection Authority: KVKK (Kisisel Verileri Koruma Kurumu).

Structure mirrors GDPR closely but with Turkish-specific elements:
  - Art. 3  : Definitions (personal data, sensitive data, data controller, etc.)
  - Art. 4  : Processing principles (lawfulness, purpose limitation, etc.)
  - Art. 5  : Legal basis for processing ordinary personal data
  - Art. 6  : Special categories of personal data (sensitive data) - stricter rules
  - Art. 7  : Deletion, destruction or anonymisation
  - Art. 8  : Transfer of personal data within Turkey
  - Art. 9  : Transfer of personal data abroad
  - Art. 11 : Rights of data subjects
  - Art. 12 : Obligation to ensure data security

TC Kimlik (Turkish national identity number) is a notable KVKK-specific requirement.
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
    # Ordinary personal data  (Art. 3, Art. 5)
    # ------------------------------------------------------------------
    "email": {
        "status": "required",
        "severity": 0.5,
        "article": "Art. 3(1)(d), Art. 4, Art. 5",
        "obligation": (
            "Email addresses are personal data under KVKK. Processing requires "
            "a legal basis (Art. 5). Data must be accurate, proportionate, and "
            "retained only as long as necessary (Art. 4)."
        ),
        "legal_basis": [
            "explicit_consent",
            "contract",
            "legal_obligation",
            "vital_interests",
            "legitimate_interest",
        ],
        "kvkk_board_decision": None,
    },
    "given_name": {
        "status": "required",
        "severity": 0.4,
        "article": "Art. 3(1)(d), Art. 4",
        "obligation": (
            "Names are personal data. Must be collected for specified, explicit "
            "and legitimate purposes."
        ),
        "legal_basis": ["explicit_consent", "contract"],
        "kvkk_board_decision": None,
    },
    "eu_phone": {
        "status": "required",
        "severity": 0.5,
        "article": "Art. 3(1)(d), Art. 5",
        "obligation": (
            "Phone numbers are personal data under KVKK. Processing requires a legal basis."
        ),
        "legal_basis": ["explicit_consent", "contract"],
        "kvkk_board_decision": None,
    },
    "tr_phone": {
        "status": "required",
        "severity": 0.5,
        "article": "Art. 3(1)(d), Art. 5",
        "obligation": (
            "Turkish phone numbers are personal data. A legal basis is required "
            "for all processing activities."
        ),
        "legal_basis": ["explicit_consent", "contract", "legitimate_interest"],
        "kvkk_board_decision": None,
    },
    "us_phone": {
        "status": "optional",
        "severity": 0.3,
        "article": "Art. 3(1)(d)",
        "obligation": (
            "If the data subject is in Turkey, all contact data including "
            "foreign phone numbers is covered by KVKK."
        ),
        "legal_basis": ["explicit_consent", "contract"],
        "kvkk_board_decision": None,
    },
    # ------------------------------------------------------------------
    # TC Kimlik (Turkish national identity number)  - special focus
    # KVKK Board has issued guidance on TC Kimlik processing
    # ------------------------------------------------------------------
    "tc_kimlik": {
        "status": "required",
        "severity": 1.0,
        "article": "Art. 6(1) - Sensitive personal data",
        "obligation": (
            "TC Kimlik numbers are treated as sensitive personal data in "
            "practice by the KVKK Board. Processing requires explicit consent "
            "or a specific legal basis. The Board has sanctioned organisations "
            "for unnecessary TC Kimlik collection. Minimise collection strictly."
        ),
        "legal_basis": ["explicit_consent", "legal_obligation"],
        "kvkk_board_decision": "KVKK Board decisions 2019/365, 2020/315",
    },
    "national_id": {
        "status": "required",
        "severity": 0.9,
        "article": "Art. 6(1)",
        "obligation": (
            "Non-Turkish national ID numbers of Turkish residents are personal "
            "data and require a legal basis for processing."
        ),
        "legal_basis": ["explicit_consent", "legal_obligation"],
        "kvkk_board_decision": None,
    },
    # ------------------------------------------------------------------
    # Financial data  (Art. 12 - security obligation)
    # ------------------------------------------------------------------
    "credit_card": {
        "status": "required",
        "severity": 0.8,
        "article": "Art. 12",
        "obligation": (
            "Credit card numbers require appropriate technical and administrative "
            "security measures under Art. 12. Tokenisation and encryption are "
            "expected; unnecessary retention is prohibited."
        ),
        "legal_basis": ["contract", "legal_obligation"],
        "kvkk_board_decision": None,
    },
    "iban": {
        "status": "required",
        "severity": 0.7,
        "article": "Art. 12",
        "obligation": (
            "Bank account / IBAN numbers require technical security under "
            "Art. 12. Document retention period and processing purpose."
        ),
        "legal_basis": ["contract", "legal_obligation"],
        "kvkk_board_decision": None,
    },
    # ------------------------------------------------------------------
    # Special categories  (Art. 6) - most sensitive under KVKK
    # Includes: race, ethnic origin, political opinion, philosophical belief,
    # religion, sect, other beliefs, appearance/dress, association/foundation/
    # union membership, health data, sexual life, criminal convictions/security
    # measures, biometric and genetic data.
    # ------------------------------------------------------------------
    "medical_record": {
        "status": "required",
        "severity": 1.0,
        "article": "Art. 6(1) - Health data (sensitive personal data)",
        "obligation": (
            "Health data is a special category under Art. 6(1). Processing is "
            "prohibited without explicit consent or unless carried out by "
            "authorised health professionals under Art. 6(3). Notify the KVKK "
            "Board of any data breach involving health data."
        ),
        "legal_basis": ["explicit_consent", "healthcare_professional"],
        "kvkk_board_decision": "KVKK Board Guideline on Health Data 2019",
    },
    "drug_name": {
        "status": "required",
        "severity": 0.9,
        "article": "Art. 6(1) - Health data",
        "obligation": (
            "Drug/medication names associated with individuals constitute "
            "health data under Art. 6(1). Process only with explicit consent "
            "or authorised healthcare basis."
        ),
        "legal_basis": ["explicit_consent", "healthcare_professional"],
        "kvkk_board_decision": None,
    },
    "hospital_name": {
        "status": "optional",
        "severity": 0.6,
        "article": "Art. 6(1) - potentially health data",
        "obligation": (
            "Hospital names linked to individuals may reveal health conditions "
            "and qualify as sensitive data under Art. 6(1)."
        ),
        "legal_basis": ["explicit_consent"],
        "kvkk_board_decision": None,
    },
    # ------------------------------------------------------------------
    # Passport / travel documents
    # ------------------------------------------------------------------
    "passport": {
        "status": "required",
        "severity": 0.8,
        "article": "Art. 3(1)(d), Art. 6(1) if biometric",
        "obligation": (
            "Passport numbers are personal data. If biometric data (fingerprint, "
            "photo) is included, it is sensitive data under Art. 6(1)."
        ),
        "legal_basis": ["legal_obligation", "explicit_consent"],
        "kvkk_board_decision": None,
    },
    # ------------------------------------------------------------------
    # Network identifiers
    # ------------------------------------------------------------------
    "ipv4_address": {
        "status": "required",
        "severity": 0.4,
        "article": "Art. 3(1)(d)",
        "obligation": (
            "IP addresses are personal data under KVKK when they can be "
            "used to identify an individual. Document purpose; apply data "
            "minimisation per Art. 4."
        ),
        "legal_basis": ["legitimate_interest", "legal_obligation"],
        "kvkk_board_decision": None,
    },
    "ipv6_address": {
        "status": "required",
        "severity": 0.4,
        "article": "Art. 3(1)(d)",
        "obligation": ("IPv6 addresses are personal data. Apply same protections as IPv4."),
        "legal_basis": ["legitimate_interest", "legal_obligation"],
        "kvkk_board_decision": None,
    },
    # ------------------------------------------------------------------
    # Demographic
    # ------------------------------------------------------------------
    "date": {
        "status": "optional",
        "severity": 0.3,
        "article": "Art. 3(1)(d), Art. 4",
        "obligation": (
            "Date of birth is personal data. Minimise collection and document "
            "retention periods per Art. 7."
        ),
        "legal_basis": ["explicit_consent", "contract"],
        "kvkk_board_decision": None,
    },
    # ------------------------------------------------------------------
    # US SSN  (optional - only for cross-border data flows)
    # ------------------------------------------------------------------
    "us_ssn": {
        "status": "optional",
        "severity": 0.7,
        "article": "Art. 3(1)(d); Art. 9 for cross-border transfer",
        "obligation": (
            "US SSNs are personal data. If transferred from Turkey, Art. 9 "
            "(international transfer rules) applies."
        ),
        "legal_basis": ["explicit_consent", "legal_obligation"],
        "kvkk_board_decision": None,
    },
    # ------------------------------------------------------------------
    # Financial VAT
    # ------------------------------------------------------------------
    "vat": {
        "status": "optional",
        "severity": 0.2,
        "article": "Art. 3(1)(d)",
        "obligation": (
            "VAT numbers of Turkish sole traders are personal data. "
            "Include in processing records if collected."
        ),
        "legal_basis": ["legal_obligation", "contract"],
        "kvkk_board_decision": None,
    },
}
