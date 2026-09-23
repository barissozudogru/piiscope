"""Top level scan API.

``scan`` accepts a file path (csv, json, jsonl, parquet, txt), a
directory, a pathlib Path or a pandas DataFrame and returns a
:class:`ScanResult` with aggregated findings, privacy metrics and a risk
score. Detection logic itself lives in :mod:`piiscope.detection`.
"""

from __future__ import annotations

import json
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

from piiscope.detection.engine import DetectionEngine
from piiscope.detection.engine import Finding as EngineFinding
from piiscope.detection.jurisdictions import (
    JURISDICTION_PROFILES,
    get_applicable_jurisdictions,
)
from piiscope.errors import PiiscopeError
from piiscope.io.readers import iter_frames, walk_directory
from piiscope.metrics.metrics import (
    compute_k_anonymity,
    compute_l_diversity,
    compute_t_closeness,
)
from piiscope.metrics.risk_scorer import RiskScorer
from piiscope.remediation.masking import partial_redact

JURISDICTIONS = ("gdpr", "ccpa", "kvkk", "lgpd")

# Rows kept in memory for metric computation; larger inputs are measured
# on a prefix (set sample_rows for a deliberate sample instead).
_MAX_METRICS_ROWS = 100_000

# Column names that commonly act as quasi identifiers when the caller
# does not name any explicitly.
_QI_NAME_HINTS = (
    "age",
    "zip",
    "zip_code",
    "zipcode",
    "postal_code",
    "postcode",
    "gender",
    "sex",
    "city",
    "country",
    "state",
    "region",
    "district",
    "dob",
    "date_of_birth",
    "birth_date",
    "birth_year",
    "nationality",
    "occupation",
    "job_title",
    "education",
)

_MAX_SAMPLES_PER_FINDING = 3


@dataclass
class Finding:
    """Aggregated detection result for one column and one detector."""

    column: str
    category: str
    detector: str
    count: int
    confidence: float
    severity: float
    samples_redacted: list[str]
    jurisdictions: list[str]
    file: str | None = None


@dataclass
class MetricsResult:
    """Privacy metrics computed over the quasi identifier columns."""

    quasi_identifiers: list[str]
    sensitive_attribute: str | None = None
    k_anonymity: int | None = None
    l_diversity: int | None = None
    t_closeness: float | None = None


@dataclass
class RiskScore:
    """Overall risk for one scan on a 0-100 scale."""

    score: int
    level: str
    drivers: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Everything a scan produced, serialisable to dict, json, markdown."""

    source: str
    rows: int
    columns: int
    findings: list[Finding]
    metrics: MetricsResult | None
    risk: RiskScore
    jurisdictions: list[str]
    scan_time: float
    files: int = 1

    def to_dict(self) -> dict[str, Any]:
        """Return a json-safe dict of the whole result."""
        return {
            "source": self.source,
            "rows": self.rows,
            "columns": self.columns,
            "files": self.files,
            "scan_time": round(self.scan_time, 3),
            "jurisdictions": list(self.jurisdictions),
            "findings": [
                {
                    "column": f.column,
                    "category": f.category,
                    "detector": f.detector,
                    "count": f.count,
                    "confidence": f.confidence,
                    "severity": f.severity,
                    "samples_redacted": f.samples_redacted,
                    "jurisdictions": f.jurisdictions,
                    "file": f.file,
                }
                for f in self.findings
            ],
            "metrics": (
                {
                    "quasi_identifiers": self.metrics.quasi_identifiers,
                    "sensitive_attribute": self.metrics.sensitive_attribute,
                    "k_anonymity": self.metrics.k_anonymity,
                    "l_diversity": self.metrics.l_diversity,
                    "t_closeness": self.metrics.t_closeness,
                }
                if self.metrics is not None
                else None
            ),
            "risk": {
                "score": self.risk.score,
                "level": self.risk.level,
                "drivers": self.risk.drivers,
            },
        }

    def to_json(self) -> str:
        """Return the result as an indented json string."""
        return json.dumps(self.to_dict(), indent=2)

    def to_markdown(self) -> str:
        """Return the result as a markdown report."""
        from piiscope.report import render_markdown

        return render_markdown(self)


class _Aggregate:
    """Mutable accumulator used while streaming frames through the engine."""

    def __init__(self, engine: DetectionEngine, jurisdictions: Sequence[str]) -> None:
        self.engine = engine
        self.jurisdictions = list(jurisdictions)
        self.rows = 0
        self.columns: list[str] = []
        self.record_index = 0
        self.metrics_rows_kept = 0
        # (file, column, rule_id) -> stats
        self.stats: dict[tuple[str | None, str, str], dict[str, Any]] = {}
        # (file, column) -> int
        self.non_null_counts: dict[tuple[str | None, str], int] = {}
        self.qi_frames: list[pd.DataFrame] = []

    def observe_columns(self, columns: Sequence[str]) -> None:
        for col in columns:
            if col not in self.columns:
                self.columns.append(col)

    def add(self, findings: list[EngineFinding], file: str | None) -> None:
        for f in findings:
            key = (file, f.column_name, f.rule_id)
            entry = self.stats.get(key)
            if entry is None:
                pattern = self.engine.patterns.get(f.rule_id)
                entry = {
                    "category": pattern.pii_category if pattern else "other",
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "count": 0,
                    "samples": [],
                }
                self.stats[key] = entry
            entry["count"] += 1
            entry["severity"] = max(entry["severity"], f.severity)
            entry["confidence"] = max(entry["confidence"], f.confidence)
            sample = f.evidence if f.evidence else ""
            redacted = (
                "*" * len(sample) if len(sample) <= 6 else partial_redact(sample, left=1, right=1)
            )
            is_new = redacted not in entry["samples"]
            if is_new and len(entry["samples"]) < _MAX_SAMPLES_PER_FINDING:
                entry["samples"].append(redacted)

    def scan_frame(self, frame: pd.DataFrame, file: str | None, keep_for_metrics: bool) -> None:
        self.rows += len(frame)
        self.observe_columns(list(frame.columns))
        for col in frame.columns:
            non_null = (frame[col] != "").sum()
            self.non_null_counts[(file, col)] = self.non_null_counts.get((file, col), 0) + int(
                non_null
            )
        records = frame.to_dict("records")
        for record in records:
            findings = self.engine.scan_row(record, self.record_index)
            self.record_index += 1
            self.add(findings, file)
        if keep_for_metrics and self.metrics_rows_kept < _MAX_METRICS_ROWS:
            room = _MAX_METRICS_ROWS - self.metrics_rows_kept
            self.qi_frames.append(frame.head(room).copy())
            self.metrics_rows_kept += min(room, len(frame))


def _resolve_profile(profile: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(profile, dict):
        return profile
    name = profile.lower()
    if name == "default":
        return {}
    if name == "nlp":
        return {"model": {"use_spacy": True, "model_name": "en_core_web_sm"}}
    raise PiiscopeError(f"unknown profile '{profile}'; use 'default', 'nlp' or pass a profile dict")


def _resolve_jurisdictions(jurisdictions: Sequence[str]) -> list[str]:
    resolved: list[str] = []
    for item in jurisdictions:
        lowered = item.lower()
        if lowered == "all":
            candidates = list(JURISDICTIONS)
        elif lowered in JURISDICTIONS:
            candidates = [lowered]
        else:
            raise PiiscopeError(
                f"unknown jurisdiction '{item}'; choose from {', '.join(JURISDICTIONS)} or 'all'"
            )
        for candidate in candidates:
            if candidate not in resolved:
                resolved.append(candidate)
    return resolved


def _auto_quasi_identifiers(columns: Sequence[str], findings: list[Finding]) -> list[str]:
    """Guess quasi identifiers from column names and detected categories."""
    selected = [c for c in columns if c.lower() in _QI_NAME_HINTS]
    demographic = sorted(
        {f.column for f in findings if f.category == "demographic" and f.column not in selected}
    )
    return selected + demographic


def _sensitive_attribute(findings: list[Finding], qi: Sequence[str]) -> str | None:
    """Pick the sensitive column for l-diversity and t-closeness."""
    health = [f.column for f in findings if f.category == "health" and f.column not in qi]
    if health:
        return health[0]
    ranked = sorted(findings, key=lambda f: f.severity, reverse=True)
    for f in ranked:
        if f.column not in qi and f.category not in ("other",):
            return f.column
    return None


def _compute_metrics(
    aggregate: _Aggregate,
    findings: list[Finding],
    quasi_identifiers: Sequence[str] | None,
) -> MetricsResult | None:
    if not aggregate.qi_frames:
        return None
    qi = (
        [c for c in quasi_identifiers if c in aggregate.columns]
        if quasi_identifiers
        else _auto_quasi_identifiers(aggregate.columns, findings)
    )
    if not qi:
        return MetricsResult(quasi_identifiers=[])
    frame = pd.concat(aggregate.qi_frames, ignore_index=True)
    k = compute_k_anonymity(frame, qi)
    sensitive = _sensitive_attribute(findings, qi)
    l_div: int | None = None
    t: float | None = None
    if sensitive and sensitive in frame.columns:
        l_div = compute_l_diversity(frame, qi, sensitive)
        t = compute_t_closeness(frame, qi, sensitive)
    return MetricsResult(
        quasi_identifiers=qi,
        sensitive_attribute=sensitive,
        k_anonymity=k,
        l_diversity=l_div,
        t_closeness=t,
    )


def _score_risk(findings: list[Finding], jurisdictions: Sequence[str]) -> RiskScore:
    scorer = RiskScorer(context="flat_file", jurisdictions=list(jurisdictions))
    scored = [(f, scorer.score_finding(f.detector, f.confidence, f.count)) for f in findings]
    if not scored:
        return RiskScore(score=0, level="low", drivers=[])
    scored.sort(key=lambda pair: pair[1].final_score, reverse=True)
    top = scored[0][1].final_score
    score = int(round(top * 10))
    if score >= 75:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    else:
        level = "low"
    drivers = [
        f"{f.column}: {f.detector} ({f.category}, {f.count} value"
        f"{'s' if f.count != 1 else ''}, confidence {f.confidence:.2f})"
        for f, s in scored[:3]
    ]
    return RiskScore(score=score, level=level, drivers=drivers)


def _build_findings(aggregate: _Aggregate, min_coverage: float) -> list[Finding]:
    profile_names = [j.upper() for j in aggregate.jurisdictions]
    applicable = get_applicable_jurisdictions(
        [rule for (_, _, rule) in aggregate.stats],
        jurisdictions=profile_names or list(JURISDICTION_PROFILES.keys()),
    )

    # Apply dominance rule
    if min_coverage > 0:
        # group by (file, column)
        col_groups: dict[tuple[str | None, str], list[tuple[str, dict[str, Any]]]] = {}
        for (file, column, rule), entry in aggregate.stats.items():
            col_groups.setdefault((file, column), []).append((rule, entry))

        for (file, column), rules in col_groups.items():
            non_null = aggregate.non_null_counts.get((file, column), 0)
            if non_null == 0:
                continue

            # Find dominant
            dominant = None
            for rule, entry in rules:
                if entry["count"] / non_null >= 0.8 and entry["confidence"] >= 0.9:
                    if dominant is None or entry["count"] > dominant[1]["count"]:
                        dominant = (rule, entry)

            if dominant:
                dom_cat = dominant[1]["category"]
                # drop weak ones from a different category
                to_drop = []
                for rule, entry in rules:
                    if entry["category"] != dom_cat and entry["count"] / non_null < min_coverage:
                        to_drop.append(rule)
                for rule in to_drop:
                    del aggregate.stats[(file, column, rule)]

    findings = []
    for (file, column, rule), entry in sorted(
        aggregate.stats.items(),
        key=lambda kv: (-kv[1]["severity"], -kv[1]["count"], kv[0][1], kv[0][0] or "", kv[0][2]),
    ):
        f_juris = applicable.get(rule, [])
        if not f_juris:
            f_juris = ["other"]

        findings.append(
            Finding(
                column=column,
                category=entry["category"],
                detector=rule,
                count=entry["count"],
                confidence=round(entry["confidence"], 3),
                severity=entry["severity"],
                samples_redacted=entry["samples"],
                jurisdictions=f_juris,
                file=file,
            )
        )
    return findings


def scan(
    source: str | Path | pd.DataFrame,
    *,
    jurisdictions: Sequence[str] = ("gdpr", "ccpa", "kvkk", "lgpd"),
    quasi_identifiers: Sequence[str] | None = None,
    sample_rows: int | None = None,
    profile: str | dict[str, Any] = "default",
    include_metrics: bool = True,
    chunk_size: int = 5000,
    max_file_size_mb: float | None = None,
    min_coverage: float = 0.15,
    dictionaries: dict[str, str] | None = None,
) -> ScanResult:
    """Scan a file, directory or DataFrame for personal data.

    jurisdictions: one or more of gdpr, ccpa, kvkk, lgpd, or "all".
    quasi_identifiers: columns for k-anonymity; auto-detected when None.
    sample_rows: scan only the first N rows.
    profile: "default", "nlp" (spaCy NER) or a raw profile dict.
    """
    start = time.perf_counter()
    resolved_jurisdictions = _resolve_jurisdictions(jurisdictions)
    resolved_profile = dict(_resolve_profile(profile))
    if dictionaries:
        user_dicts = dict(resolved_profile.get("user_dictionaries", {}))
        user_dicts.update(dictionaries)
        resolved_profile["user_dictionaries"] = user_dicts
    engine = DetectionEngine(resolved_profile)
    aggregate = _Aggregate(engine, resolved_jurisdictions)
    keep_for_metrics = include_metrics or quasi_identifiers is not None
    label: str
    files = 1

    if isinstance(source, pd.DataFrame):
        label = "dataframe"
        frame = source.fillna("").astype(str)
        aggregate.scan_frame(frame, None, keep_for_metrics)
    elif isinstance(source, (str, Path)) and Path(source).is_dir():
        label = str(source)
        targets = walk_directory(source)
        files = len(targets)
        for target in targets:
            for frame in iter_frames(
                target,
                chunk_size=chunk_size,
                max_file_size_mb=max_file_size_mb,
                sample_rows=sample_rows,
            ):
                aggregate.scan_frame(frame, target.name, keep_for_metrics)
    else:
        path = Path(source)
        label = str(path)
        for frame in iter_frames(
            path,
            chunk_size=chunk_size,
            max_file_size_mb=max_file_size_mb,
            sample_rows=sample_rows,
        ):
            aggregate.scan_frame(frame, None, keep_for_metrics)

    findings = _build_findings(aggregate, min_coverage=min_coverage)
    metrics = (
        _compute_metrics(aggregate, findings, quasi_identifiers)
        if include_metrics and aggregate.qi_frames
        else None
    )
    risk = _score_risk(findings, resolved_jurisdictions)
    return ScanResult(
        source=label,
        rows=aggregate.rows,
        columns=len(aggregate.columns),
        findings=findings,
        metrics=metrics,
        risk=risk,
        jurisdictions=resolved_jurisdictions,
        scan_time=time.perf_counter() - start,
        files=files,
    )
