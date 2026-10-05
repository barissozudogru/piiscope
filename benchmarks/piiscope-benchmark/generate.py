#!/usr/bin/env python3
"""Generate the privacy-safe Piiscope structured-pattern benchmark."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

OUTPUT = Path(__file__).parent / "data" / "test.jsonl"


@dataclass(frozen=True)
class BaseCase:
    family: str
    value: str
    column_name: str
    expected_rules: tuple[str, ...]
    category: str
    case_type: str
    difficulty: str
    safety_basis: str


def iban(country: str, bban: str) -> str:
    """Return a checksum-valid synthetic IBAN for a non-transactable test BBAN."""
    provisional = f"{country}00{bban}".upper()
    rearranged = provisional[4:] + provisional[:4]
    numeric = "".join(str(ord(char) - 55) if char.isalpha() else char for char in rearranged)
    check_digits = 98 - (int(numeric) % 97)
    return f"{country}{check_digits:02d}{bban}".upper()


GB_TEST_IBAN = iban("GB", "TEST00000000000000")
TR_TEST_IBAN = iban("TR", "0000000000000000000000")


BASE_CASES = (
    BaseCase(
        "email",
        "tester+piiscope@example.com",
        "email",
        ("email",),
        "contact",
        "positive",
        "easy",
        "example.com is reserved for documentation",
    ),
    BaseCase(
        "credit_card",
        "4111 1111 1111 1111",
        "payment_card",
        ("credit_card",),
        "financial",
        "positive",
        "medium",
        "payment processor test number with no account",
    ),
    BaseCase(
        "iban",
        GB_TEST_IBAN,
        "bank_account",
        ("iban",),
        "financial",
        "positive",
        "hard",
        "checksum-valid TEST BBAN that is not a bank account",
    ),
    BaseCase(
        "iban_tr",
        TR_TEST_IBAN,
        "iban",
        ("iban", "iban_tr"),
        "financial",
        "positive",
        "hard",
        "checksum-valid all-zero test BBAN that is not a bank account",
    ),
    BaseCase(
        "us_phone",
        "+1 212-555-0100",
        "phone",
        ("us_phone",),
        "contact",
        "positive",
        "medium",
        "555-0100 is in the North American fictional-use range",
    ),
    BaseCase(
        "eu_phone",
        "+44 7700 900123",
        "phone",
        ("eu_phone",),
        "contact",
        "positive",
        "medium",
        "07700 900000 to 900999 is reserved for UK drama use",
    ),
    BaseCase(
        "tr_phone",
        "0555 000 00 00",
        "phone",
        ("eu_phone", "tr_phone", "tr_phone_strict"),
        "contact",
        "positive",
        "hard",
        "repeated-zero synthetic test value with no person attached",
    ),
    BaseCase(
        "ipv4_address",
        "192.0.2.42",
        "ip_address",
        ("ipv4_address",),
        "network",
        "positive",
        "easy",
        "192.0.2.0/24 is reserved for documentation",
    ),
    BaseCase(
        "ipv6_address",
        "2001:0db8:0000:0000:0000:0000:0000:0042",
        "ip_address",
        ("ipv6_address",),
        "network",
        "positive",
        "medium",
        "2001:db8::/32 is reserved for documentation",
    ),
    BaseCase(
        "vat_de",
        "DE000000000",
        "vat_number",
        ("vat", "vat_de"),
        "financial",
        "positive",
        "medium",
        "all-zero synthetic test value",
    ),
    BaseCase(
        "vat_eu",
        "FRZZ000000000",
        "vat_number",
        ("vat",),
        "financial",
        "positive",
        "medium",
        "ZZ and zeros mark a synthetic test value",
    ),
    BaseCase(
        "url",
        "https://example.com/privacy/record-42",
        "url",
        ("url",),
        "other",
        "positive",
        "easy",
        "example.com is reserved for documentation",
    ),
    BaseCase(
        "date",
        "2000-02-29",
        "birth_date",
        ("date",),
        "demographic",
        "positive",
        "easy",
        "synthetic leap-day value with no person attached",
    ),
    BaseCase(
        "medical_record",
        "MRN-000001",
        "medical_record",
        ("medical_record",),
        "health",
        "positive",
        "easy",
        "all-zero synthetic test identifier",
    ),
    BaseCase(
        "swift_bic",
        "TESTZZ00XXX",
        "swift_bic",
        ("swift_bic",),
        "financial",
        "positive",
        "medium",
        "TEST bank code and invalid ZZ country marker",
    ),
    BaseCase(
        "passport_uk",
        "ZZ000000",
        "passport",
        ("passport", "passport_uk"),
        "national_id",
        "positive",
        "medium",
        "ZZ and zeros mark a synthetic test value",
    ),
    BaseCase(
        "passport_tr",
        "T00000000",
        "passport",
        ("national_id", "passport", "passport_de", "passport_tr"),
        "national_id",
        "positive",
        "hard",
        "all-zero synthetic test value",
    ),
    BaseCase(
        "passport_de",
        "C00000000",
        "passport",
        ("national_id", "passport", "passport_de"),
        "national_id",
        "positive",
        "hard",
        "all-zero synthetic test value",
    ),
    BaseCase(
        "email_near_miss",
        "tester@example",
        "email",
        (),
        "contact",
        "hard_negative",
        "medium",
        "reserved documentation domain without a top-level domain",
    ),
    BaseCase(
        "credit_card_bad_checksum",
        "4111 1111 1111 1112",
        "payment_card",
        (),
        "financial",
        "hard_negative",
        "hard",
        "synthetic number that intentionally fails Luhn validation",
    ),
    BaseCase(
        "iban_bad_checksum",
        "GB00TEST00000000000000",
        "bank_account",
        (),
        "financial",
        "hard_negative",
        "hard",
        "synthetic TEST BBAN with an intentionally invalid checksum",
    ),
    BaseCase(
        "tc_kimlik_bad_checksum",
        "10000000145",
        "national_id",
        (),
        "national_id",
        "hard_negative",
        "hard",
        "synthetic value with an intentionally invalid checksum",
    ),
    BaseCase(
        "ipv4_out_of_range",
        "192.0.2.999",
        "ip_address",
        (),
        "network",
        "hard_negative",
        "medium",
        "documentation address with an invalid octet",
    ),
    BaseCase(
        "ipv6_invalid",
        "2001:db8:zzzz::42",
        "ip_address",
        (),
        "network",
        "hard_negative",
        "medium",
        "documentation prefix with invalid hexadecimal characters",
    ),
    BaseCase(
        "vat_lowercase",
        "de000000000",
        "vat_number",
        (),
        "financial",
        "hard_negative",
        "medium",
        "synthetic lowercase near miss for a case-sensitive detector",
    ),
    BaseCase(
        "url_without_scheme",
        "example.com/privacy/record-42",
        "url",
        (),
        "other",
        "hard_negative",
        "easy",
        "reserved documentation domain without a URL scheme",
    ),
    BaseCase(
        "medical_record_short",
        "MRN-0042",
        "medical_record",
        (),
        "health",
        "hard_negative",
        "medium",
        "synthetic identifier shorter than the detector contract",
    ),
    BaseCase(
        "swift_lowercase",
        "testzz00xxx",
        "swift_bic",
        (),
        "financial",
        "hard_negative",
        "medium",
        "synthetic lowercase near miss for a case-sensitive detector",
    ),
    BaseCase(
        "passport_lowercase",
        "zz000000",
        "passport",
        (),
        "national_id",
        "hard_negative",
        "medium",
        "synthetic lowercase near miss for a case-sensitive country detector",
    ),
    BaseCase(
        "phone_too_short",
        "555-0100",
        "phone",
        (),
        "contact",
        "hard_negative",
        "easy",
        "short number from a fictional-use exchange",
    ),
    BaseCase(
        "version_number",
        "2026.08.26.1",
        "version",
        (),
        "other",
        "hard_negative",
        "hard",
        "synthetic release version that resembles numeric identifiers",
    ),
    BaseCase(
        "commit_identifier",
        "abcdef0123456789",
        "commit_sha",
        (),
        "other",
        "hard_negative",
        "easy",
        "synthetic hexadecimal identifier",
    ),
)


TEMPLATES = (
    ("en_plain", "en", "Recorded value: {value}"),
    ("en_csv", "en", "value,{value},verified"),
    ("en_brackets", "en", "Audit entry [{value}]"),
    ("en_sentence", "en", "The source field contains {value} for review."),
    ("de_plain", "de", "Erfasster Wert: {value}"),
    ("de_csv", "de", "wert,{value},geprueft"),
    ("de_brackets", "de", "Pruefeintrag [{value}]"),
    ("de_sentence", "de", "Das Quellfeld enthaelt {value} zur Pruefung."),
    ("tr_plain", "tr", "Kayitli deger: {value}"),
    ("tr_csv", "tr", "deger,{value},dogrulandi"),
    ("tr_brackets", "tr", "Denetim kaydi [{value}]"),
    ("tr_sentence", "tr", "Kaynak alan inceleme icin {value} iceriyor."),
    ("pt_plain", "pt", "Valor registrado: {value}"),
    ("pt_csv", "pt", "valor,{value},verificado"),
    ("pt_brackets", "pt", "Registro de auditoria [{value}]"),
    ("pt_sentence", "pt", "O campo de origem contem {value} para revisao."),
)


def records() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for case_index, case in enumerate(BASE_CASES, start=1):
        for template_index, (template_id, language, template) in enumerate(TEMPLATES, start=1):
            rows.append(
                {
                    "id": f"pb-{case_index:03d}-{template_index:02d}",
                    "text": template.format(value=case.value),
                    "value": case.value,
                    "column_name": case.column_name,
                    "expected_rules": list(case.expected_rules),
                    "expected_sensitive": bool(case.expected_rules),
                    "family": case.family,
                    "category": case.category,
                    "case_type": case.case_type,
                    "difficulty": case.difficulty,
                    "language": language,
                    "template_id": template_id,
                    "synthetic": True,
                    "safety_basis": case.safety_basis,
                }
            )
    return rows


def main() -> None:
    rows = records()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"wrote {len(rows)} rows to {OUTPUT}")


if __name__ == "__main__":
    main()
