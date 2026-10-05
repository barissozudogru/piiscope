---
license: cc-by-4.0
language:
  - en
  - de
  - tr
  - pt
task_categories:
  - text-classification
tags:
  - pii
  - privacy
  - synthetic
  - benchmark
  - data-protection
  - piiscope
  - personal-data
pretty_name: Piiscope Structured PII Pattern Benchmark
configs:
  - config_name: default
    data_files:
      - split: test
        path: data/test.jsonl
---

# Piiscope Structured PII Pattern Benchmark

A deterministic, privacy-safe benchmark for structured personal-data detectors.
Every value is synthetic, reserved for documentation, or a published test
credential. The dataset contains no records collected from people, no customer
data, and no transactable financial identifiers.

The benchmark is maintained with
[Piiscope](https://github.com/barissozudogru/piiscope), a local PII scanner and
privacy-risk CLI. It can also evaluate compatible rule-based detectors that
return one or more rule identifiers for a text field.

The focused [Piiscope tool page](https://petri-labs.org/tools/piiscope/)
collects the install path, operating limits, reproducible workflow, and source
links in one place.

## Dataset structure

The test split contains 512 rows built from 32 base cases and 16 English,
German, Turkish, and Portuguese contexts.

- Positive cases cover emails, checksum-valid test cards and IBANs, fictional
  phone ranges, documentation IP addresses, URLs, dates, medical record
  markers, VAT markers, SWIFT markers, and synthetic passport patterns.
- Hard negatives cover malformed checksums, invalid network addresses,
  lowercase near misses for case-sensitive rules, short identifiers, version
  numbers, and commit-like hexadecimal strings.
- `expected_rules` is a multi-label detector contract.
- `safety_basis` explains why the embedded value does not represent a person
  or live account.

## Reproduce the data

```sh
python benchmarks/piiscope-benchmark/generate.py
```

Generation uses only the Python standard library and contains no random step.
The same source always produces the same ordered JSONL file.

## Evaluate Piiscope

```sh
python -m pip install piiscope
python benchmarks/piiscope-benchmark/evaluate.py
```

The checked-in result records the exact Piiscope version and reports micro
precision, micro recall, exact multi-label match rate, and hard-negative pass
rate. Dictionary detectors are disabled so this first release measures the
structured-pattern layer in isolation.

## Published results

| Piiscope | Micro precision | Micro recall | Micro F1 | Exact match | Hard-negative pass |
|---|---:|---:|---:|---:|---:|
| 1.2.0 | 0.7941 | 0.9643 | 0.8710 | 0.7500 | 0.7143 |
| 1.3.0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

The 1.2.0 baseline was measured from the published PyPI wheel. The 1.3.0 row is
the release result after the benchmark exposed phone-boundary, partial-IPv6,
and cross-detector false positives. Full failures and per-rule counts are stored
under `results/`.

## Intended use

- Regression testing for deterministic structured PII detectors
- Comparing checksum and near-miss handling across releases
- Demonstrating privacy-scanner behavior without publishing real PII
- Teaching safe benchmark construction for privacy tooling

## Limitations

- This is a pattern-detection benchmark, not a model of real-world PII
  prevalence.
- It does not measure demographic fairness or multilingual named-entity recall.
- It deliberately excludes positive national identity numbers when no clearly
  reserved test range is available.
- Repeated synthetic values test context handling, not memorization resistance.
- A high score does not prove that a scanner is sufficient for compliance.

## Licensing and citation

The dataset is released under CC BY 4.0. Generator and evaluation scripts in
the Piiscope repository remain under Apache 2.0.

When citing the benchmark, link both the dataset and the evaluated Piiscope
release so the detector behavior can be reproduced.
