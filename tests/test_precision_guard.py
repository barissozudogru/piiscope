from piiscope.detection.engine import DetectionEngine


def test_precision_guard():
    engine = DetectionEngine({})

    findings = engine.detect_cell("We will mark the bill in May", "notes")
    for f in findings:
        assert f.rule_id != "given_name", (
            f"False positive given_name on stoplist word: {f.evidence}"
        )

    for value in ("Ayşe", "Jürgen"):
        findings2 = engine.detect_cell(value, "first_name")
        assert any(
            f.evidence == value.lower() and f.rule_id == "given_name" for f in findings2
        ), f"{value} not found"
