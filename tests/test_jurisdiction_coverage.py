from piiscope.detection.jurisdictions.gdpr import PROFILE as GDPR_PROFILE
from piiscope.detection.regex_patterns import PATTERNS


def test_every_pattern_in_gdpr():
    expected_ids = set(PATTERNS.keys())
    # Add dictionary detectors and NER
    expected_ids.update(
        [
            "given_name",
            "surname",
            "medical_condition",
            "drug_name",
            "hospital_name",
            "ner_person",
            "ner_gpe",
            "ner_org",
            "ner_loc",
            "ner_date",
            "ner_cardinal",
        ]
    )

    gdpr_ids = set(GDPR_PROFILE.keys())

    missing_in_gdpr = expected_ids - gdpr_ids
    assert not missing_in_gdpr, f"Rule IDs missing in GDPR: {missing_in_gdpr}"

    dead_keys = gdpr_ids - expected_ids
    assert not dead_keys, f"Dead keys in GDPR (not in PATTERNS or dicts): {dead_keys}"
