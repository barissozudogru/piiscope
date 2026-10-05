import json
from pathlib import Path

from piiscope.detection.engine import DetectionEngine

DATASET = (
    Path(__file__).parents[1]
    / "benchmarks"
    / "piiscope-benchmark"
    / "data"
    / "test.jsonl"
)


def test_structured_pattern_benchmark_has_no_regressions():
    engine = DetectionEngine(
        {
            "dictionaries": {
                "names": {"enabled": False},
                "hospitals": {"enabled": False},
                "drugs": {"enabled": False},
                "medical": {"enabled": False},
            }
        }
    )

    failures = []
    for line in DATASET.read_text().splitlines():
        row = json.loads(line)
        predicted = {
            finding.rule_id
            for finding in engine.detect_cell(row["text"], row["column_name"])
        }
        expected = set(row["expected_rules"])
        if predicted != expected:
            failures.append((row["id"], sorted(expected), sorted(predicted)))

    assert not failures, failures[:10]
