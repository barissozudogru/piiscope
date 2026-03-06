"""Regular expression patterns for detecting sensitive information.

Patterns are organised by a key (rule ID) and include the compiled
regular expression, a description and a severity weight.  The
severities map roughly to the impact of exposure: high values for
medical identifiers or national IDs, medium for general personal
information, and low for less sensitive fields.

Each PatternDefinition optionally carries:
  - requires_checksum: set to True when the match MUST be further
    validated by a checksum function before being emitted as a Finding.
  - pii_category: broad category label used for masking recommendations
    and compliance mapping.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, Optional, Pattern

_logger = logging.getLogger(__name__)


class PatternDefinition:
    def __init__(
        self,
        pattern: str,
        description: str,
        severity: float,
        *,
        requires_checksum: bool = False,
        pii_category: str = "other",
        case_sensitive: bool = False,
    ):
        flags = 0 if case_sensitive else re.IGNORECASE
        self.pattern: Pattern[str] = re.compile(pattern, flags)
        self.description = description
        self.severity = severity
        self.requires_checksum = requires_checksum
        self.pii_category = pii_category


# ---------------------------------------------------------------------------
# Core built-in patterns
# ---------------------------------------------------------------------------
# Design principles applied here:
#   - Credit cards: regex narrows to plausible formats; Luhn algorithm is
#     run as a second pass (requires_checksum=True) to eliminate false positives.
#   - IBAN: regex enforces country-code + check-digits + BBAN format;
#     MOD-97 checksum is run as a second pass.
#   - TC Kimlik: exact 11-digit regex plus algorithmic checksum second pass.
#   - Phone: separate patterns per region with stricter bounds; the EU
#     pattern is kept broad but bounded to prevent matching arbitrary numbers.
#   - IP: IPv4 with octet range enforcement; IPv6 handled by a dedicated
#     pattern with the standard colon-hex notation.
#   - IBAN/VAT overlap: VAT is kept but tightened to known EU prefix lengths
#     so it no longer masks every uppercase letter + digit sequence.
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, PatternDefinition] = {
    # ------------------------------------------------------------------
    # Email addresses
    # ------------------------------------------------------------------
    "email": PatternDefinition(
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
        "Email address",
        0.3,
        pii_category="contact",
    ),

    # ------------------------------------------------------------------
    # Credit card numbers
    #
    # Accepts the four major card formats:
    #   Visa:            4[0-9]{12}(?:[0-9]{3})?
    #   Mastercard:      5[1-5][0-9]{14} | 2[2-7][0-9]{14}
    #   Amex:            3[47][0-9]{13}
    #   Discover:        6(?:011|5[0-9]{2})[0-9]{12}
    # All separated by optional spaces or hyphens in groups of 4.
    # Luhn checksum validation is mandatory (requires_checksum=True).
    # ------------------------------------------------------------------
    "credit_card": PatternDefinition(
        r"\b(?:"
        r"4[0-9]{3}(?:[ \-]?[0-9]{4}){3}"           # Visa (16 digits)
        r"|4[0-9]{3}(?:[ \-]?[0-9]{4}){2}[ \-]?[0-9]{3}"  # Visa (13 digits)
        r"|5[1-5][0-9]{2}(?:[ \-]?[0-9]{4}){3}"     # Mastercard
        r"|2[2-7][0-9]{2}(?:[ \-]?[0-9]{4}){3}"     # Mastercard 2-series
        r"|3[47][0-9]{2}[ \-]?[0-9]{6}[ \-]?[0-9]{5}"  # Amex
        r"|6(?:011|5[0-9]{2})(?:[ \-]?[0-9]{4}){3}" # Discover
        r")\b",
        "Credit card number",
        0.8,
        requires_checksum=True,
        pii_category="financial",
    ),

    # ------------------------------------------------------------------
    # IBAN
    # Format: 2-letter country code + 2 check digits + BBAN (11-30 chars)
    # MOD-97 checksum is mandatory (requires_checksum=True).
    # ------------------------------------------------------------------
    "iban": PatternDefinition(
        r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b",
        "IBAN (bank account number)",
        0.7,
        requires_checksum=True,
        pii_category="financial",
    ),

    # ------------------------------------------------------------------
    # Turkish TC Kimlik (national identity number)
    # Exactly 11 digits, first digit non-zero.
    # Algorithmic checksum validation is mandatory.
    # ------------------------------------------------------------------
    "tc_kimlik": PatternDefinition(
        r"\b[1-9][0-9]{10}\b",
        "Turkish TC Kimlik national identity number",
        0.9,
        requires_checksum=True,
        pii_category="national_id",
    ),

    # ------------------------------------------------------------------
    # German national ID / Passport (Personalausweis)
    # Alphanumeric, 9 chars, restricted character set.
    # ------------------------------------------------------------------
    "national_id": PatternDefinition(
        r"\b[CFGHJKLMNPRTVWXYZ][CFGHJKLMNPRTVWXYZ0-9]{8}\b",
        "German National ID / Passport",
        0.9,
        pii_category="national_id",
    ),

    # ------------------------------------------------------------------
    # Phone numbers
    #
    # Three separate patterns for different regions to reduce false positives:
    #   eu_phone     - European international (+CC ...) or local formats
    #   us_phone     - North American NANP format
    #   tr_phone     - Turkish mobile/landline
    # ------------------------------------------------------------------
    "eu_phone": PatternDefinition(
        r"\b(?:\+(?:3[0-9]|4[0-9]|5[0-9]|7[0-9]|8[0-9]|9[0-9])[0-9 \-\.]{6,15}"
        r"|0[1-9][0-9 \-\.]{7,13})\b",
        "European telephone number",
        0.4,
        pii_category="contact",
    ),
    "us_phone": PatternDefinition(
        r"(?:^|[\s,;])(?:\+1[ \-\.])?"
        r"(?:\([2-9][0-9]{2}\)|[2-9][0-9]{2})"
        r"[ \-\.]?[2-9][0-9]{2}"
        r"[ \-\.]?[0-9]{4}(?=\b|$)",
        "US/Canada telephone number (NANP)",
        0.4,
        pii_category="contact",
    ),
    "tr_phone": PatternDefinition(
        r"\b(?:\+90[ \-]?)?0?[0-9]{3}[ \-]?[0-9]{3}[ \-]?[0-9]{2}[ \-]?[0-9]{2}\b",
        "Turkish telephone number",
        0.4,
        pii_category="contact",
    ),

    # ------------------------------------------------------------------
    # IP addresses
    #
    # IPv4: each octet bounded to 0-255 via explicit range alternatives.
    # IPv6: full address, compressed forms, and mixed notation.
    # ------------------------------------------------------------------
    "ipv4_address": PatternDefinition(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        "IPv4 address",
        0.4,
        pii_category="network",
    ),
    "ipv6_address": PatternDefinition(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
        r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
        r"|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
        r"|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"
        r"|\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b"
        r"|\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b"
        r"|\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b"
        r"|\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b"
        r"|\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b",
        "IPv6 address",
        0.4,
        pii_category="network",
    ),

    # ------------------------------------------------------------------
    # VAT number (EU format: 2-letter country code + 8-12 digits/uppercase)
    # Compiled case-sensitively so that "DEpression" (lowercase letters
    # after the country prefix) does NOT match.
    # ------------------------------------------------------------------
    "vat": PatternDefinition(
        r"\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|GB|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)"
        r"[0-9A-Z]{8,12}\b",
        "EU VAT number",
        0.6,
        pii_category="financial",
        case_sensitive=True,
    ),

    # ------------------------------------------------------------------
    # URL (basic - low severity, mostly useful as context clue)
    # ------------------------------------------------------------------
    "url": PatternDefinition(
        r"\bhttps?://[\w.\-]+(?:\.[\w.\-]+)*(?::\d+)?(?:/[\w./?%&=\-]*)?\b",
        "URL",
        0.2,
        pii_category="other",
    ),

    # ------------------------------------------------------------------
    # Date of birth or other dates
    # ------------------------------------------------------------------
    "date": PatternDefinition(
        r"\b(?:\d{1,2}[.\/\-]){2}\d{2,4}\b|\b\d{4}-\d{2}-\d{2}\b",
        "Date",
        0.2,
        pii_category="demographic",
    ),

    # ------------------------------------------------------------------
    # Social Security Number (US SSN)
    # Format: XXX-XX-XXXX; restricted first and second groups.
    # ------------------------------------------------------------------
    "us_ssn": PatternDefinition(
        r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
        "US Social Security Number (SSN)",
        0.9,
        pii_category="national_id",
    ),

    # ------------------------------------------------------------------
    # Passport number (generic; matches common formats)
    # ------------------------------------------------------------------
    "passport": PatternDefinition(
        r"\b[A-Z]{1,2}[0-9]{6,9}\b",
        "Passport number (generic)",
        0.8,
        pii_category="national_id",
    ),

    # ------------------------------------------------------------------
    # Health / medical record identifiers
    # ------------------------------------------------------------------
    "medical_record": PatternDefinition(
        r"\b(?:MRN|MR|PT|PAT)[:\-\s]{0,2}[0-9]{5,12}\b",
        "Medical record number",
        0.9,
        pii_category="health",
    ),

    # ------------------------------------------------------------------
    # SWIFT / BIC codes
    # Format: 4-letter bank code + 2-letter country + 2 location + optional 3 branch
    # Validated case-sensitively to avoid collisions with common words.
    # ------------------------------------------------------------------
    "swift_bic": PatternDefinition(
        r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
        "SWIFT / BIC code",
        0.7,
        pii_category="financial",
        case_sensitive=True,
    ),

    # ------------------------------------------------------------------
    # Passport numbers – country-specific patterns
    #
    # Turkish passport: letter T followed by 8 digits (T + 8 digits = 9 chars)
    # German passport: letters + digits, same charset as national_id but
    #                  explicitly annotated as passport context
    # UK passport: two letters + six digits (standard MRP format)
    # ------------------------------------------------------------------
    "passport_tr": PatternDefinition(
        r"\bT[0-9]{8}\b",
        "Turkish passport number",
        0.9,
        pii_category="national_id",
        case_sensitive=True,
    ),
    "passport_de": PatternDefinition(
        r"\b[CFGHJKLMNPRTVWXYZ][CFGHJKLMNPRTVWXYZ0-9]{8}\b",
        "German passport number",
        0.85,
        pii_category="national_id",
        case_sensitive=True,
    ),
    "passport_uk": PatternDefinition(
        r"\b[A-Z]{2}[0-9]{6}\b",
        "UK passport number",
        0.85,
        pii_category="national_id",
        case_sensitive=True,
    ),

    # ------------------------------------------------------------------
    # Turkish IBAN  (TR + 24 digits = 26 chars total)
    # Separate entry so context-aware boosting and the IBAN checksum
    # validator can be applied with a TR-specific label.
    # ------------------------------------------------------------------
    "iban_tr": PatternDefinition(
        r"\bTR[0-9]{24}\b",
        "Turkish IBAN",
        0.8,
        requires_checksum=True,
        pii_category="financial",
        case_sensitive=True,
    ),

    # ------------------------------------------------------------------
    # Turkish phone – stricter alternative to tr_phone for context-aware use
    # Matches mobile (05xx) and landline (0xxx) formats with international
    # prefix (+90) optional.
    # ------------------------------------------------------------------
    "tr_phone_strict": PatternDefinition(
        r"\b(?:\+90[ \-]?)?0[1-9][0-9]{2}[ \-]?[0-9]{3}[ \-]?[0-9]{2}[ \-]?[0-9]{2}\b",
        "Turkish telephone number (strict)",
        0.45,
        pii_category="contact",
    ),

    # ------------------------------------------------------------------
    # EU VAT numbers – per-country stricter formats
    # Germany: DE + 9 digits
    # France:  FR + 2 alphanumeric + 9 digits
    # Turkey:  TR VAT: 10 digits (vergi no), no EU country prefix
    # ------------------------------------------------------------------
    "vat_de": PatternDefinition(
        r"\bDE[0-9]{9}\b",
        "German VAT number",
        0.6,
        pii_category="financial",
        case_sensitive=True,
    ),
    "vat_tr": PatternDefinition(
        r"\b[0-9]{10}\b",
        "Turkish Tax / Vergi Kimlik Numarasi (VKN)",
        0.5,
        pii_category="financial",
    ),
}


def build_custom_patterns(custom_defs: list[dict]) -> dict[str, PatternDefinition]:
    """Build PatternDefinition objects from user-supplied custom pattern definitions.

    Each element in custom_defs must be a dict with at minimum:
      - id       (str): unique rule identifier
      - pattern  (str): raw regex string
      - description (str): human-readable description
      - severity (float): 0.0–1.0 severity weight

    Optional fields:
      - pii_category (str): category label (default "custom")

    Invalid patterns (bad regex) are skipped with a warning written to the
    module logger.
    """
    result: dict[str, PatternDefinition] = {}
    for defn in custom_defs:
        rule_id = defn.get("id")
        pattern_str = defn.get("pattern")
        description = defn.get("description", "Custom pattern")
        severity_raw = defn.get("severity", 0.5)
        pii_category = defn.get("pii_category", "custom")

        if not rule_id or not pattern_str:
            _logger.warning(
                "Skipping custom pattern with missing 'id' or 'pattern': %r",
                defn,
            )
            continue
        try:
            severity = float(severity_raw)
            if not 0.0 <= severity <= 1.0:
                severity = max(0.0, min(1.0, severity))
            case_sensitive = bool(defn.get("case_sensitive", False))
            result[rule_id] = PatternDefinition(
                pattern_str,
                description,
                severity,
                pii_category=pii_category,
                case_sensitive=case_sensitive,
            )
        except re.error as exc:
            _logger.warning(
                "Invalid regex for custom pattern '%s': %s",
                rule_id,
                exc,
            )
    return result
