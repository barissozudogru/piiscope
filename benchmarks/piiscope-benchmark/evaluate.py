#!/usr/bin/env python3
"""Evaluate an installed Piiscope release on the structured-pattern benchmark."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from piiscope import __version__
from piiscope.detection.engine import DetectionEngine

ROOT = Path(__file__).parent
DATASET = ROOT / "data" / "test.jsonl"
OUTPUT = ROOT / "results" / f"piiscope-{__version__}.json"


def ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def main() -> None:
    profile = {
        "dictionaries": {
            "names": {"enabled": False},
            "hospitals": {"enabled": False},
            "drugs": {"enabled": False},
            "medical": {"enabled": False},
        }
    }
    engine = DetectionEngine(profile)
    rows = [json.loads(line) for line in DATASET.read_text().splitlines() if line]

    true_positive = 0
    false_positive = 0
    false_negative = 0
    exact_matches = 0
    hard_negative_passes = 0
    hard_negative_count = 0
    per_rule: dict[str, Counter[str]] = defaultdict(Counter)
    failures: list[dict[str, object]] = []

    for row in rows:
        expected = set(row["expected_rules"])
        predicted = {
            finding.rule_id
            for finding in engine.detect_cell(row["text"], row["column_name"])
        }

        tp = expected & predicted
        fp = predicted - expected
        fn = expected - predicted
        true_positive += len(tp)
        false_positive += len(fp)
        false_negative += len(fn)

        for rule in tp:
            per_rule[rule]["true_positive"] += 1
        for rule in fp:
            per_rule[rule]["false_positive"] += 1
        for rule in fn:
            per_rule[rule]["false_negative"] += 1

        if predicted == expected:
            exact_matches += 1
        else:
            failures.append(
                {
                    "id": row["id"],
                    "family": row["family"],
                    "expected": sorted(expected),
                    "predicted": sorted(predicted),
                }
            )

        if row["case_type"] == "hard_negative":
            hard_negative_count += 1
            if not predicted:
                hard_negative_passes += 1

    precision = ratio(true_positive, true_positive + false_positive)
    recall = ratio(true_positive, true_positive + false_negative)
    f1 = ratio(2 * precision * recall, precision + recall)

    report = {
        "benchmark": "barissozudogru/piiscope-benchmark",
        "benchmark_scope": "structured pattern detection with dictionaries disabled",
        "piiscope_version": __version__,
        "rows": len(rows),
        "positive_rows": sum(bool(row["expected_rules"]) for row in rows),
        "hard_negative_rows": hard_negative_count,
        "metrics": {
            "micro_precision": precision,
            "micro_recall": recall,
            "micro_f1": f1,
            "exact_match_rate": ratio(exact_matches, len(rows)),
            "hard_negative_pass_rate": ratio(hard_negative_passes, hard_negative_count),
        },
        "counts": {
            "true_positive": true_positive,
            "false_positive": false_positive,
            "false_negative": false_negative,
            "exact_matches": exact_matches,
        },
        "per_rule": {
            rule: dict(sorted(counts.items())) for rule, counts in sorted(per_rule.items())
        },
        "failures": failures,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report["metrics"], indent=2))
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
