from piiscope.detection.jurisdictions.ccpa import PROFILE as CCPA_PROFILE
from piiscope.detection.jurisdictions.gdpr import PROFILE as GDPR_PROFILE
from piiscope.detection.jurisdictions.kvkk import PROFILE as KVKK_PROFILE
from piiscope.detection.jurisdictions.lgpd import PROFILE as LGPD_PROFILE
from piiscope.detection.regex_patterns import PATTERNS

EXPECTED_RULE_IDS = set(PATTERNS.keys()) | {
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
}


def test_every_pattern_in_gdpr():
    gdpr_ids = set(GDPR_PROFILE.keys())
    missing_in_gdpr = EXPECTED_RULE_IDS - gdpr_ids
    assert not missing_in_gdpr, f"Rule IDs missing in GDPR: {missing_in_gdpr}"
    dead_keys = gdpr_ids - EXPECTED_RULE_IDS
    assert not dead_keys, f"Dead keys in GDPR (not in PATTERNS or dicts): {dead_keys}"


def test_every_pattern_in_ccpa():
    ccpa_ids = set(CCPA_PROFILE.keys())
    missing_in_ccpa = EXPECTED_RULE_IDS - ccpa_ids
    assert not missing_in_ccpa, f"Rule IDs missing in CCPA: {missing_in_ccpa}"
    dead_keys = ccpa_ids - EXPECTED_RULE_IDS
    assert not dead_keys, f"Dead keys in CCPA (not in PATTERNS or dicts): {dead_keys}"


def test_every_pattern_in_kvkk():
    kvkk_ids = set(KVKK_PROFILE.keys())
    missing_in_kvkk = EXPECTED_RULE_IDS - kvkk_ids
    assert not missing_in_kvkk, f"Rule IDs missing in KVKK: {missing_in_kvkk}"
    dead_keys = kvkk_ids - EXPECTED_RULE_IDS
    assert not dead_keys, f"Dead keys in KVKK (not in PATTERNS or dicts): {dead_keys}"


def test_every_pattern_in_lgpd():
    lgpd_ids = set(LGPD_PROFILE.keys())
    missing_in_lgpd = EXPECTED_RULE_IDS - lgpd_ids
    assert not missing_in_lgpd, f"Rule IDs missing in LGPD: {missing_in_lgpd}"
    # cpf is a compliance profile entry specific to Brazilian LGPD
    dead_keys = lgpd_ids - EXPECTED_RULE_IDS - {"cpf"}
    assert not dead_keys, f"Dead keys in LGPD (not in PATTERNS or dicts): {dead_keys}"
