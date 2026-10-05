"""Render piiscope findings as SARIF 2.1.0 without including matched values."""

from __future__ import annotations

import json
from collections.abc import Sequence
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from piiscope.scan import Finding, ScanResult


def _package_version() -> str:
    try:
        return version("piiscope")
    except PackageNotFoundError:  # pragma: no cover - source tree without installation
        return "unknown"


def _level(finding: Finding) -> str:
    if finding.severity >= 0.8:
        return "error"
    if finding.severity >= 0.5:
        return "warning"
    return "note"


def _artifact(result: ScanResult, finding: Finding) -> str:
    value = finding.file or result.source
    if value == "dataframe":
        return value
    return Path(value).as_posix()


def render_sarif(results: Sequence[ScanResult]) -> str:
    """Return one SARIF run for one or more scan results.

    SARIF deliberately contains detector metadata, counts, confidence, and file
    locations only. Matched or redacted sample values never enter the artifact.
    """

    rules: dict[str, dict[str, object]] = {}
    sarif_results: list[dict[str, object]] = []

    for result in results:
        for finding in result.findings:
            if finding.detector not in rules:
                rules[finding.detector] = {
                    "id": finding.detector,
                    "name": finding.detector,
                    "shortDescription": {
                        "text": f"Potential {finding.category} personal data",
                    },
                    "helpUri": "https://petri-labs.org/tools/piiscope/",
                    "properties": {
                        "category": finding.category,
                        "jurisdictions": finding.jurisdictions,
                    },
                }

            sarif_results.append(
                {
                    "ruleId": finding.detector,
                    "level": _level(finding),
                    "message": {
                        "text": (
                            f"Detected {finding.count} potential {finding.category} value(s) "
                            f'in column "{finding.column}" with confidence '
                            f"{finding.confidence:.2f}."
                        )
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": _artifact(result, finding)}
                            },
                            "logicalLocations": [
                                {"name": finding.column, "kind": "column"}
                            ],
                        }
                    ],
                    "properties": {
                        "count": finding.count,
                        "confidence": finding.confidence,
                        "severity": finding.severity,
                        "jurisdictions": finding.jurisdictions,
                        "riskScore": result.risk.score,
                        "riskLevel": result.risk.level,
                    },
                }
            )

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "piiscope",
                        "version": _package_version(),
                        "informationUri": "https://petri-labs.org/tools/piiscope/",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(payload, indent=2)
