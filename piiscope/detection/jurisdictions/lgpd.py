"""LGPD (Lei Geral de Protecao de Dados) compliance profile.

Regulation: Lei 13.709/2018 (LGPD), effective September 18 2020.
Territorial scope: applies to processing of personal data collected in
Brazil, or processing carried out in Brazil, or where the purpose of
processing is to offer goods/services to data subjects located in Brazil.
Brazilian Data Protection Authority: ANPD (Autoridade Nacional de
Protecao de Dados).

Key LGPD articles referenced here:
  - Art. 5   : Definitions (personal data, sensitive data, data subject, etc.)
  - Art. 6   : Processing principles (purpose, adequacy, necessity, etc.)
  - Art. 7   : Legal bases for processing ordinary personal data
  - Art. 11  : Legal bases for processing sensitive personal data
  - Art. 12  : Anonymisation
  - Art. 18  : Rights of data subjects
  - Art. 46  : Security measures for personal data processing
  - Art. 50  : Data processing governance
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
    # Basic personal identifiers  (Art. 5(I) - personal data definition)
    # ------------------------------------------------------------------
    "email": {
        "status": "required",
        "severity": 0.5,
        "article": "Art. 5(I), Art. 6(III)",
        "obligation": (
            "Email addresses are personal data under Art. 5(I). Processing "
            "must comply with the necessity principle (Art. 6(III)) and "
            "requires a legal basis from Art. 7."
        ),
        "legal_basis": ["consent", "contract", "legitimate_interest", "legal_obligation"],
        "data_subject_rights": ["access", "correction", "deletion", "portability", "opt_out"],
    },
    "given_name": {
        "status": "required",
        "severity": 0.4,
        "article": "Art. 5(I), Art. 6(III)",
        "obligation": (
            "Names are personal data. Collect only what is adequate, relevant "
            "and necessary for the stated purpose (Art. 6(III))."
        ),
        "legal_basis": ["consent", "contract", "legitimate_interest"],
        "data_subject_rights": ["access", "correction", "deletion"],
    },
    # ------------------------------------------------------------------
    # Brazilian national identifier - CPF  (Art. 5(I); high sensitivity)
    # Cadastro de Pessoas Fisicas - Brazilian individual taxpayer registry
    # ------------------------------------------------------------------
    "cpf": {
        "status": "required",
        "severity": 0.9,
        "article": "Art. 5(I), Art. 46",
        "obligation": (
            "CPF numbers are personal data uniquely identifying Brazilian "
            "natural persons. Apply strict access controls and encryption "
            "per Art. 46. Collect only with a valid legal basis; document "
            "the purpose. Unnecessary retention is prohibited."
        ),
        "legal_basis": ["consent", "legal_obligation", "contract"],
        "data_subject_rights": ["access", "correction", "deletion", "portability"],
    },
    # ------------------------------------------------------------------
    # Contact information
    # ------------------------------------------------------------------
    "eu_phone": {
        "status": "optional",
        "severity": 0.4,
        "article": "Art. 5(I)",
        "obligation": (
            "Non-Brazilian phone numbers are personal data when they relate "
            "to Brazilian data subjects. Apply Art. 7 legal basis requirements."
        ),
        "legal_basis": ["consent", "contract"],
        "data_subject_rights": ["access", "deletion"],
    },
    "us_phone": {
        "status": "optional",
        "severity": 0.4,
        "article": "Art. 5(I)",
        "obligation": (
            "US phone numbers are personal data when they relate to "
            "Brazilian data subjects. Apply Art. 7 legal basis requirements."
        ),
        "legal_basis": ["consent", "contract"],
        "data_subject_rights": ["access", "deletion"],
    },
    "tr_phone": {
        "status": "optional",
        "severity": 0.3,
        "article": "Art. 5(I)",
        "obligation": (
            "Foreign phone numbers are personal data when associated with Brazilian data subjects."
        ),
        "legal_basis": ["consent", "contract"],
        "data_subject_rights": ["access", "deletion"],
    },
    # ------------------------------------------------------------------
    # Financial data  (Art. 46 - security obligation)
    # ------------------------------------------------------------------
    "credit_card": {
        "status": "required",
        "severity": 0.8,
        "article": "Art. 46",
        "obligation": (
            "Credit card numbers require appropriate technical and "
            "organisational security measures under Art. 46. Tokenise or "
            "truncate; avoid storing PAN in plaintext. Report breaches to "
            "ANPD under Art. 48."
        ),
        "legal_basis": ["contract", "legal_obligation"],
        "data_subject_rights": ["access", "deletion", "portability"],
    },
    "iban": {
        "status": "required",
        "severity": 0.7,
        "article": "Art. 46",
        "obligation": (
            "Bank account numbers require security measures per Art. 46. "
            "Document purpose and retention period; apply encryption at rest."
        ),
        "legal_basis": ["contract", "legal_obligation"],
        "data_subject_rights": ["access", "deletion"],
    },
    # ------------------------------------------------------------------
    # National identifiers  (Art. 5(II) - sensitive personal data if
    # racial/ethnic origin; Art. 5(I) for general national IDs)
    # ------------------------------------------------------------------
    "us_ssn": {
        "status": "optional",
        "severity": 0.8,
        "article": "Art. 5(I); Art. 33 for cross-border transfer",
        "obligation": (
            "US SSNs of Brazilian data subjects are personal data. "
            "Cross-border transfers require adequate protection under "
            "Art. 33-36."
        ),
        "legal_basis": ["consent", "legal_obligation"],
        "data_subject_rights": ["access", "deletion"],
    },
    "national_id": {
        "status": "required",
        "severity": 0.8,
        "article": "Art. 5(I), Art. 46",
        "obligation": (
            "National ID numbers are personal data requiring a legal basis "
            "and adequate security measures under Art. 46."
        ),
        "legal_basis": ["legal_obligation", "consent"],
        "data_subject_rights": ["access", "correction", "deletion"],
    },
    # ------------------------------------------------------------------
    # Sensitive personal data  (Art. 5(II), Art. 11)
    # Categories: racial/ethnic origin, religious belief, political
    # opinion, union membership, health/sex life data, genetic/biometric
    # data when used to identify a natural person.
    # ------------------------------------------------------------------
    "medical_record": {
        "status": "required",
        "severity": 1.0,
        "article": "Art. 5(II) - health data; Art. 11",
        "obligation": (
            "Health data is sensitive personal data under Art. 5(II). "
            "Processing is only permitted under one of the Art. 11 bases "
            "(explicit consent, healthcare, protection of life, etc.). "
            "Implement enhanced security; report breaches to ANPD (Art. 48)."
        ),
        "legal_basis": ["explicit_consent", "healthcare", "vital_interests", "legal_obligation"],
        "data_subject_rights": ["access", "correction", "deletion", "portability", "opt_out"],
    },
    "drug_name": {
        "status": "required",
        "severity": 0.9,
        "article": "Art. 5(II) - health data; Art. 11",
        "obligation": (
            "Drug/medication names in the context of an individual constitute "
            "health data (sensitive personal data) under Art. 5(II). Apply "
            "Art. 11 restrictions."
        ),
        "legal_basis": ["explicit_consent", "healthcare"],
        "data_subject_rights": ["access", "deletion", "opt_out"],
    },
    "hospital_name": {
        "status": "optional",
        "severity": 0.6,
        "article": "Art. 5(II) - potentially health data",
        "obligation": (
            "Hospital names linked to an individual may reveal health "
            "information and qualify as sensitive personal data under "
            "Art. 5(II)."
        ),
        "legal_basis": ["explicit_consent", "healthcare"],
        "data_subject_rights": ["access", "deletion"],
    },
    # ------------------------------------------------------------------
    # Passport / travel documents
    # ------------------------------------------------------------------
    "passport": {
        "status": "required",
        "severity": 0.8,
        "article": "Art. 5(I), Art. 46",
        "obligation": (
            "Passport numbers are personal data. Collect only when strictly "
            "necessary; apply security measures per Art. 46. May qualify as "
            "biometric data (sensitive) if biometric template is stored."
        ),
        "legal_basis": ["legal_obligation", "consent"],
        "data_subject_rights": ["access", "correction", "deletion"],
    },
    # ------------------------------------------------------------------
    # Network / technical identifiers  (Art. 5(I))
    # ------------------------------------------------------------------
    "ipv4_address": {
        "status": "required",
        "severity": 0.4,
        "article": "Art. 5(I)",
        "obligation": (
            "IP addresses are personal data when they can be linked to an "
            "individual. Document processing purpose; anonymise after the "
            "required retention period."
        ),
        "legal_basis": ["legitimate_interest", "legal_obligation"],
        "data_subject_rights": ["access", "deletion"],
    },
    "ipv6_address": {
        "status": "required",
        "severity": 0.5,
        "article": "Art. 5(I)",
        "obligation": (
            "IPv6 addresses are more individually identifying than IPv4. "
            "Apply the same protections as IPv4 addresses."
        ),
        "legal_basis": ["legitimate_interest", "legal_obligation"],
        "data_subject_rights": ["access", "deletion"],
    },
    # ------------------------------------------------------------------
    # Demographic data
    # ------------------------------------------------------------------
    "date": {
        "status": "optional",
        "severity": 0.3,
        "article": "Art. 6(III)",
        "obligation": (
            "Dates (especially date of birth) contribute to re-identification "
            "risk. Apply data minimisation and collect only what is necessary "
            "(Art. 6(III))."
        ),
        "legal_basis": ["consent", "contract", "legitimate_interest"],
        "data_subject_rights": ["access", "correction", "deletion"],
    },
    # ------------------------------------------------------------------
    # Financial VAT / CNPJ numbers
    # ------------------------------------------------------------------
    "vat": {
        "status": "optional",
        "severity": 0.2,
        "article": "Art. 5(I)",
        "obligation": (
            "Brazilian CPF/CNPJ numbers of individual business owners are "
            "personal data. Include in privacy notice if collected."
        ),
        "legal_basis": ["legal_obligation", "contract"],
        "data_subject_rights": ["access", "deletion"],
    },
}
