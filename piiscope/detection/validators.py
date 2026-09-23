"""Checksum and format validators for structured PII types.

These validators reduce false positives by applying mathematical
checks on top of regex pattern matches. They are called after an
initial regex match confirms the rough format of a value.
"""

from __future__ import annotations

import re


def luhn_check(number: str) -> bool:
    """Return True if the given digit string passes the Luhn algorithm.

    Strips all non-digit characters before processing, so formatted
    card numbers like '4111 1111 1111 1111' or '4111-1111-1111-1111'
    are accepted.
    """
    digits = re.sub(r"\D", "", number)
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def iban_check(value: str) -> bool:
    """Return True if the value is a structurally valid IBAN.

    Performs format check, length check per country code, and the
    MOD-97 checksum defined in ISO 13616.
    """
    # Normalise: remove spaces and convert to upper
    iban = re.sub(r"\s", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", iban):
        return False

    # Known IBAN lengths by country code (not exhaustive but covers EU + TR)
    COUNTRY_LENGTHS: dict[str, int] = {
        "AL": 28,
        "AD": 24,
        "AT": 20,
        "AZ": 28,
        "BH": 22,
        "BE": 16,
        "BA": 20,
        "BR": 29,
        "BG": 22,
        "CR": 22,
        "HR": 21,
        "CY": 28,
        "CZ": 24,
        "DK": 18,
        "DO": 28,
        "EE": 20,
        "FO": 18,
        "FI": 18,
        "FR": 27,
        "GE": 22,
        "DE": 22,
        "GI": 23,
        "GR": 27,
        "GL": 18,
        "GT": 28,
        "HU": 28,
        "IS": 26,
        "IE": 22,
        "IL": 23,
        "IT": 27,
        "JO": 30,
        "KZ": 20,
        "XK": 20,
        "KW": 30,
        "LV": 21,
        "LB": 28,
        "LI": 21,
        "LT": 20,
        "LU": 20,
        "MK": 19,
        "MT": 31,
        "MR": 27,
        "MU": 30,
        "MD": 24,
        "MC": 27,
        "ME": 22,
        "NL": 18,
        "NO": 15,
        "PK": 24,
        "PS": 29,
        "PL": 28,
        "PT": 25,
        "QA": 29,
        "RO": 24,
        "SM": 27,
        "SA": 24,
        "RS": 22,
        "SK": 24,
        "SI": 19,
        "ES": 24,
        "SE": 24,
        "CH": 21,
        "TL": 23,
        "TN": 24,
        "TR": 26,
        "AE": 23,
        "GB": 22,
        "VG": 24,
    }
    country = iban[:2]
    expected_len = COUNTRY_LENGTHS.get(country)
    if expected_len is not None and len(iban) != expected_len:
        return False

    # MOD-97 check: move first 4 chars to end, convert letters to digits
    rearranged = iban[4:] + iban[:4]
    numeric = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        else:
            numeric += str(ord(ch) - ord("A") + 10)
    return int(numeric) % 97 == 1


def tc_kimlik_check(value: str) -> bool:
    """Return True if the 11-digit string is a valid Turkish TC Kimlik number.

    Rules:
    - Must be exactly 11 digits
    - First digit must not be 0
    - digits[10] == (sum of first 10 digits) % 10
    - digits[9] == ((sum of digits at odd indices 0,2,4,6,8) * 7
                    - (sum of digits at even indices 1,3,5,7)) % 10
    """
    digits_str = re.sub(r"\D", "", value)
    if len(digits_str) != 11:
        return False
    digits = [int(d) for d in digits_str]
    if digits[0] == 0:
        return False
    # Checksum 1: 10th digit
    if sum(digits[:10]) % 10 != digits[10]:
        return False
    # Checksum 2: 9th digit
    odd_sum = sum(digits[i] for i in range(0, 9, 2))  # indices 0,2,4,6,8
    even_sum = sum(digits[i] for i in range(1, 8, 2))  # indices 1,3,5,7
    if (odd_sum * 7 - even_sum) % 10 != digits[9]:
        return False
    return True


def is_private_ip(ip: str) -> bool:
    """Return True if the IPv4 address is in a private/loopback/link-local range.

    Private ranges: 10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if any(o < 0 or o > 255 for o in octets):
        return False
    a, b = octets[0], octets[1]
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return True
    if a == 169 and b == 254:
        return True
    return False


def is_valid_ipv4(ip: str) -> bool:
    """Return True if the string is a well-formed IPv4 address."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
        return all(0 <= o <= 255 for o in octets)
    except ValueError:
        return False


def is_valid_ipv6(value: str) -> bool:
    """Return True if the string looks like a valid IPv6 address."""
    import socket

    try:
        socket.inet_pton(socket.AF_INET6, value)
        return True
    except OSError:
        return False


# Columns where a name match should NOT be treated as a person name
_NAME_NEGATIVE_COLUMN_CONTEXTS = frozenset(
    {
        "product",
        "item",
        "category",
        "label",
        "type",
        "status",
        "description",
        "comment",
        "note",
        "message",
        "content",
        "subject",
        "title",
        "code",
        "key",
        "tag",
        "version",
        "url",
        "path",
        "filename",
        "format",
        "action",
        "event",
        "method",
        "source",
    }
)

# Columns where a name match IS strongly expected to be a person name
_NAME_POSITIVE_COLUMN_CONTEXTS = frozenset(
    {
        "name",
        "full_name",
        "fullname",
        "first_name",
        "last_name",
        "given_name",
        "surname",
        "patient",
        "employee",
        "author",
        "contact",
        "person",
        "owner",
        "user",
        "client",
        "customer",
        "recipient",
        "sender",
        "buyer",
        "applicant",
        "vendor",
        "lastname",
        "family_name",
        "familyname",
        "nachname",
        "soyad",
        "soyadi",
        "apellido",
        "apellidos",
        "sobrenome",
        "nom",
        "cognome",
        "achternaam",
        "nazwisko",
        "customer_name",
        "contact_name",
    }
)


def column_name_context_boost(column_name: str, rule_id: str) -> float:
    """Return a confidence multiplier based on the column name context.

    A multiplier > 1.0 indicates the column name strongly suggests the
    rule is applicable. A multiplier < 1.0 downgrades confidence.
    A multiplier of 1.0 means no context signal is available.
    """
    col_lower = column_name.lower().replace("-", "_").replace(" ", "_")
    # Strip common prefixes/suffixes for matching
    col_clean = col_lower

    if rule_id in ("given_name", "surname", "ner_person"):
        for ctx in _NAME_POSITIVE_COLUMN_CONTEXTS:
            if ctx in col_clean:
                return 1.4
        for ctx in _NAME_NEGATIVE_COLUMN_CONTEXTS:
            if ctx in col_clean:
                return 0.3
        return 1.0

    if rule_id == "email":
        if "email" in col_clean or "mail" in col_clean:
            return 1.5
        if any(c in col_clean for c in _NAME_NEGATIVE_COLUMN_CONTEXTS):
            return 0.6
        return 1.0

    if rule_id == "credit_card":
        positive = {"card", "credit", "payment", "cc", "pan"}
        negative = {
            "id",
            "code",
            "ref",
            "order",
            "product",
            "item",
            "sku",
            "index",
            "count",
            "total",
        }
        for p in positive:
            if p in col_clean:
                return 1.5
        for n in negative:
            if col_clean == n or col_clean.endswith("_" + n) or col_clean.startswith(n + "_"):
                return 0.3
        return 1.0

    if rule_id == "iban":
        if "iban" in col_clean or "bank" in col_clean or "account" in col_clean:
            return 1.5
        return 1.0

    if rule_id == "tc_kimlik":
        positive = {"tc", "kimlik", "tckn", "nid", "national_id", "id_number"}
        for p in positive:
            if p in col_clean:
                return 1.5
        return 1.0

    if rule_id in ("tr_phone_strict", "tr_phone"):
        if any(word in col_clean for word in ("phone", "tel", "mobile", "fax", "gsm", "cep")):
            return 1.5
        return 1.0

    if rule_id in ("eu_phone", "phone", "us_phone"):
        if any(word in col_clean for word in ("phone", "tel", "mobile", "fax")):
            return 1.5
        return 1.0

    if rule_id in ("ipv4_address", "ipv6_address"):
        if "ip" in col_clean or "address" in col_clean or "host" in col_clean:
            return 1.3
        return 1.0

    if rule_id == "date":
        positive = {"dob", "birth", "born", "date", "birthday"}
        for p in positive:
            if p in col_clean:
                return 1.3
        if any(token in col_clean for token in ("ip", "host", "version", "release", "build")):
            return 0.2
        return 1.0

    if rule_id in ("swift_bic",):
        if "swift" in col_clean or "bic" in col_clean or "bank" in col_clean:
            return 1.5
        return 1.0

    if rule_id in ("passport_tr", "passport_de", "passport_uk", "passport"):
        if "passport" in col_clean or "travel" in col_clean or "document" in col_clean:
            return 1.5
        if any(token in col_clean for token in ("vat", "tax", "vergi")):
            return 0.2
        return 1.0

    if rule_id in ("iban_tr",):
        if "iban" in col_clean or "bank" in col_clean or "account" in col_clean:
            return 1.5
        return 1.0

    if rule_id in ("vat_de", "vat_tr", "vat"):
        if "vat" in col_clean or "tax" in col_clean or "vergi" in col_clean:
            return 1.5
        return 1.0


    return 1.0
