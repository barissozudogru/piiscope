import time

from piiscope.detection.dictionaries import get_given_names
from piiscope.detection.engine import DetectionEngine


def test_lowercase_free_text_no_names():
    engine = DetectionEngine({})
    findings = engine.detect_cell(
        "will mark may april june summer hope art rose bill", "description"
    )
    name_findings = [f for f in findings if f.rule_id in ("given_name", "surname")]
    assert len(name_findings) == 0


def test_capitalised_name_in_notes_column():
    engine = DetectionEngine({})
    findings = engine.detect_cell("Dr. Ayşe Yılmaz visited Charité on Monday", "notes")
    name_findings = {
        f.rule_id: f.evidence for f in findings if f.rule_id in ("given_name", "surname")
    }
    assert "given_name" in name_findings
    assert name_findings["given_name"] == "ayşe"
    assert "surname" in name_findings
    assert name_findings["surname"] == "yılmaz"


def test_last_name_column():
    """Each spelling (diacritics or ASCII-folded) is recognised in a surname column."""
    engine = DetectionEngine({})
    for value in ("müller", "mueller", "yılmaz", "yilmaz", "silva"):
        findings = engine.detect_cell(value, "last_name")
        surnames = [f.evidence for f in findings if f.rule_id == "surname"]
        assert surnames == [value], value
        assert not [f for f in findings if f.rule_id == "given_name"], value


def test_first_name_column():
    """Lowercase given names are recognised in a given-name column, never as surnames."""
    engine = DetectionEngine({})
    for value in ("ali", "fatma", "hans", "zeynep"):
        findings = engine.detect_cell(value, "first_name")
        given = [f.evidence for f in findings if f.rule_id == "given_name"]
        assert given == [value], value
        assert not [f for f in findings if f.rule_id == "surname"], value


def test_one_name_finding_per_cell():
    """A full name in one cell yields one given_name and one surname finding."""
    engine = DetectionEngine({})
    findings = engine.detect_cell("Maria Silva Santos", "customer_name")
    rules = sorted(f.rule_id for f in findings if f.rule_id in ("given_name", "surname"))
    assert rules == ["given_name", "surname"]


def test_place_columns_do_not_yield_names():
    engine = DetectionEngine({})
    cases = (("city", "Florence"), ("street", "Charlotte Street"), ("company", "Morgan Ltd"))
    for column, value in cases:
        findings = engine.detect_cell(value, column)
        assert not [f for f in findings if f.rule_id in ("given_name", "surname")], column


def test_loader_caches():
    # Warm up cache
    get_given_names()
    start = time.time()
    get_given_names()
    duration = time.time() - start
    assert duration < 0.1  # should be instantaneous if cached


def test_user_supplied_dictionary(tmp_path):
    dict_file = tmp_path / "custom_names.txt"
    dict_file.write_text("UniqueNewName\nAnotherUniqueName")

    profile = {"user_dictionaries": {"given_name": str(dict_file)}}
    engine = DetectionEngine(profile)
    findings = engine.detect_cell("UniqueNewName", "first_name")
    names = [f.evidence for f in findings if f.rule_id == "given_name"]
    assert "uniquenewname" in names


def test_both_list_tokens_resolve_by_position():
    """"John Doe": john is in both lists and resolves as the given name, doe as the surname."""
    engine = DetectionEngine({})
    findings = {f.rule_id: f.evidence for f in engine.detect_cell("John Doe", "name")}
    assert findings.get("given_name") == "john"
    assert findings.get("surname") == "doe"
    single = {f.rule_id for f in engine.detect_cell("John", "name")}
    assert "given_name" in single and "surname" not in single


def test_sentence_initial_names_need_context():
    """A capitalised token that opens a sentence is a name only with a title or a surname."""
    engine = DetectionEngine({})
    negatives = (
        "Gift card purchase. No personal notes.",
        "June referral scheduled.",
        "Grace period ends",
    )
    positives = (
        "Dr. Ayşe Yılmaz visited on Monday",
        "Hans Müller called twice",
        "Referred by Frau Petra",
    )
    for text in negatives:
        assert not [f for f in engine.detect_cell(text, "notes") if f.rule_id == "given_name"], text
    for text in positives:
        assert [f for f in engine.detect_cell(text, "notes") if f.rule_id == "given_name"], text
