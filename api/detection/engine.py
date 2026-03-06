"""Core detection engine for sensitive data discovery.

The engine combines rule-based regular expressions, dictionary look-ups
and optional NLP models to flag potentially sensitive information.
It operates on rows of data provided by a streaming parser. Findings
are yielded one row at a time to avoid loading entire datasets into
memory.

Key improvements over the original:
  - Checksum validation for credit cards (Luhn), IBANs (MOD-97) and
    Turkish TC Kimlik numbers to eliminate false positives.
  - Context-aware confidence scoring: the column name is used to boost
    or downgrade the base confidence of a match.
  - IPv6 detection in addition to IPv4.
  - Public vs. private IP classification stored as evidence metadata.
  - Custom pattern support: user-defined regex patterns are loaded from
    the profile definition and merged with the built-in patterns.
  - False positive management: findings can be marked as suppressed via
    the profile's suppression_rules list; suppressed findings are not
    emitted.
  - Plugin architecture: new detection modules can be registered via
    register_plugin(); each plugin receives the text+column and may
    return additional findings.
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import pandas as pd

try:
    import pyarrow.parquet as pq  # type: ignore
except ImportError:
    pq = None

try:
    import spacy
    from spacy.language import Language
except ImportError:
    spacy = None
    Language = None  # type: ignore

from .regex_patterns import PATTERNS, PatternDefinition, build_custom_patterns
from .dictionaries import GIVEN_NAMES, HOSPITAL_NAMES, DRUG_NAMES
from .validators import (
    luhn_check,
    iban_check,
    tc_kimlik_check,
    is_valid_ipv4,
    is_valid_ipv6,
    is_private_ip,
    column_name_context_boost,
)


logger = logging.getLogger(__name__)

# Minimum confidence threshold below which findings are not emitted
_MIN_CONFIDENCE = 0.2

# Rules that require checksum validation before emitting
_CHECKSUM_VALIDATORS: Dict[str, Callable[[str], bool]] = {
    "credit_card": luhn_check,
    "iban": iban_check,
    "iban_tr": iban_check,   # Turkish IBAN uses the same MOD-97 check
    "tc_kimlik": tc_kimlik_check,
}

# Plugin registry: external modules can call register_plugin() to extend detection
_PLUGINS: List[Callable[[str, str], List["Finding"]]] = []


def register_plugin(fn: Callable[[str, str], List["Finding"]]) -> None:
    """Register a detection plugin function.

    The plugin receives (text: str, column_name: str) and should return
    a list of Finding objects.  Plugins are called after built-in rules.
    """
    _PLUGINS.append(fn)


@dataclass
class Finding:
    record_index: int
    column_name: str
    rule_id: str
    severity: float
    confidence: float
    evidence: str
    # Extra metadata (e.g. ip_classification, is_private_ip)
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Whether the finding was marked as a false positive
    is_false_positive: bool = False


class DetectionEngine:
    def __init__(self, profile: Dict[str, Any]):
        """Initialise the detection engine from a profile definition.

        profile keys:
          - patterns: mapping of rule_id -> {severity: float} overrides.
          - custom_patterns: list of custom pattern definitions.
          - dictionaries: enabling/disabling specific dictionaries.
          - model: {use_spacy: bool, model_name: str}.
          - suppression_rules: list of {rule_id, column_name, value_pattern}
              dicts defining false-positive suppression.
          - quasi_identifiers: list of column names (for metric computation).
          - sensitive_attribute: column name for l-diversity / t-closeness.
        """
        self.profile = profile or {}

        # Start from built-in patterns
        self.patterns: Dict[str, PatternDefinition] = {
            k: v for k, v in PATTERNS.items()
        }

        # Apply severity overrides from the profile
        for rule_id, spec in self.profile.get("patterns", {}).items():
            if rule_id in self.patterns and "severity" in spec:
                self.patterns[rule_id].severity = float(spec["severity"])

        # Load custom patterns from the profile
        custom_defs = self.profile.get("custom_patterns", [])
        if custom_defs:
            custom = build_custom_patterns(custom_defs)
            # Custom patterns override built-ins with the same ID
            self.patterns.update(custom)

        # Dictionary settings
        dict_cfg = self.profile.get("dictionaries", {})
        self.use_name_dict = dict_cfg.get("names", {}).get("enabled", True)
        self.use_hospital_dict = dict_cfg.get("hospitals", {}).get("enabled", True)
        self.use_drug_dict = dict_cfg.get("drugs", {}).get("enabled", True)

        # Suppression rules for false positive management
        # Format: [{rule_id: str, column_name: str (optional),
        #           value_pattern: str (optional regex)}]
        self._suppression_rules = self.profile.get("suppression_rules", [])
        self._suppression_compiled = []
        for rule in self._suppression_rules:
            vp = rule.get("value_pattern")
            self._suppression_compiled.append({
                "rule_id": rule.get("rule_id"),
                "column_name": rule.get("column_name"),
                "value_re": re.compile(vp, re.IGNORECASE) if vp else None,
            })

        # NLP model
        model_cfg = self.profile.get("model", {})
        self.use_spacy = bool(model_cfg.get("use_spacy", False)) and spacy is not None
        self.nlp: Optional[Language] = None
        if self.use_spacy:
            try:
                self.nlp = spacy.load(model_cfg.get("model_name", "en_core_web_sm"))
            except Exception as e:
                logger.warning("Failed to load spaCy model: %s", e)
                self.use_spacy = False

    # ------------------------------------------------------------------
    # Suppression check
    # ------------------------------------------------------------------

    def _is_suppressed(self, finding: Finding) -> bool:
        """Return True if this finding matches a suppression rule."""
        for rule in self._suppression_compiled:
            if rule["rule_id"] and rule["rule_id"] != finding.rule_id:
                continue
            if rule["column_name"] and rule["column_name"].lower() != finding.column_name.lower():
                continue
            if rule["value_re"] and not rule["value_re"].search(finding.evidence):
                continue
            return True
        return False

    # ------------------------------------------------------------------
    # Cell-level detection
    # ------------------------------------------------------------------

    def detect_cell(self, value: str, column_name: str) -> List[Finding]:
        """Detect sensitive information in a single cell.

        Returns a list of findings. Each finding carries:
          - severity from the pattern definition
          - base confidence from the rule type
          - context-adjusted confidence based on the column name
          - checksum-validated accuracy for credit cards, IBANs, TC Kimlik
        """
        findings: List[Finding] = []
        text = str(value).strip()
        if not text:
            return findings

        placeholder = 0  # record_index is set later by scan_row

        # ------------------------------------------------------------------
        # 1. Regex pattern matching
        # ------------------------------------------------------------------
        for rule_id, pattern_def in self.patterns.items():
            for match in pattern_def.pattern.finditer(text):
                matched_text = match.group()
                base_confidence = 0.85

                # Run checksum validation for rules that require it
                if pattern_def.requires_checksum or rule_id in _CHECKSUM_VALIDATORS:
                    validator = _CHECKSUM_VALIDATORS.get(rule_id)
                    if validator is not None and not validator(matched_text):
                        # Failed checksum - skip this match entirely
                        continue
                    # Checksum passed → higher confidence
                    base_confidence = 0.95

                # IPv4: validate octet ranges and classify public/private
                extra_meta: Dict[str, Any] = {}
                if rule_id == "ipv4_address":
                    if not is_valid_ipv4(matched_text):
                        continue
                    extra_meta["ip_version"] = "4"
                    extra_meta["is_private"] = is_private_ip(matched_text)
                    # Private IPs are less sensitive
                    if extra_meta["is_private"]:
                        base_confidence = 0.5

                if rule_id == "ipv6_address":
                    if not is_valid_ipv6(matched_text):
                        continue
                    extra_meta["ip_version"] = "6"
                    extra_meta["is_private"] = False

                # Context-aware confidence boost/downgrade
                ctx_mult = column_name_context_boost(column_name, rule_id)
                confidence = min(1.0, max(0.0, base_confidence * ctx_mult))

                if confidence < _MIN_CONFIDENCE:
                    continue

                f = Finding(
                    record_index=placeholder,
                    column_name=column_name,
                    rule_id=rule_id,
                    severity=pattern_def.severity,
                    confidence=round(confidence, 3),
                    evidence=text[:200],
                    metadata=extra_meta,
                )
                if not self._is_suppressed(f):
                    findings.append(f)
                    # One finding per rule per cell is usually sufficient
                    break

        lower = text.lower()

        # ------------------------------------------------------------------
        # 2. Dictionary look-ups
        # ------------------------------------------------------------------
        if self.use_name_dict:
            tokens = lower.split()
            for token in tokens:
                if token in GIVEN_NAMES:
                    ctx_mult = column_name_context_boost(column_name, "given_name")
                    confidence = round(min(1.0, 0.6 * ctx_mult), 3)
                    if confidence >= _MIN_CONFIDENCE:
                        f = Finding(
                            record_index=placeholder,
                            column_name=column_name,
                            rule_id="given_name",
                            severity=0.3,
                            confidence=confidence,
                            evidence=token,
                        )
                        if not self._is_suppressed(f):
                            findings.append(f)
                    break

        if self.use_hospital_dict:
            for h in HOSPITAL_NAMES:
                if h in lower:
                    f = Finding(
                        record_index=placeholder,
                        column_name=column_name,
                        rule_id="hospital_name",
                        severity=0.4,
                        confidence=0.7,
                        evidence=h,
                    )
                    if not self._is_suppressed(f):
                        findings.append(f)
                    break

        if self.use_drug_dict:
            for d in DRUG_NAMES:
                if d in lower:
                    f = Finding(
                        record_index=placeholder,
                        column_name=column_name,
                        rule_id="drug_name",
                        severity=0.5,
                        confidence=0.7,
                        evidence=d,
                    )
                    if not self._is_suppressed(f):
                        findings.append(f)
                    break

        # ------------------------------------------------------------------
        # 3. spaCy NER (optional)
        # ------------------------------------------------------------------
        if self.use_spacy and self.nlp:
            doc = self.nlp(text)
            for ent in doc.ents:
                if ent.label_ in {"PERSON", "GPE", "ORG", "LOC", "DATE", "CARDINAL"}:
                    severity = 0.3 if ent.label_ == "PERSON" else 0.2
                    rule_id = f"ner_{ent.label_.lower()}"
                    ctx_mult = column_name_context_boost(column_name, rule_id)
                    confidence = round(min(1.0, 0.5 * ctx_mult), 3)
                    if confidence < _MIN_CONFIDENCE:
                        continue
                    f = Finding(
                        record_index=placeholder,
                        column_name=column_name,
                        rule_id=rule_id,
                        severity=severity,
                        confidence=confidence,
                        evidence=ent.text,
                    )
                    if not self._is_suppressed(f):
                        findings.append(f)

        # ------------------------------------------------------------------
        # 4. External plugins
        # ------------------------------------------------------------------
        for plugin_fn in _PLUGINS:
            try:
                plugin_findings = plugin_fn(text, column_name)
                for f in plugin_findings:
                    f.record_index = placeholder
                    if not self._is_suppressed(f):
                        findings.append(f)
            except Exception as exc:
                logger.warning("Plugin %s raised an error: %s", plugin_fn.__name__, exc)

        return findings

    # ------------------------------------------------------------------
    # Row-level detection
    # ------------------------------------------------------------------

    def scan_row(self, row: Dict[str, Any], record_index: int) -> List[Finding]:
        """Scan a dictionary representing one row and return all findings."""
        all_findings: List[Finding] = []
        for col_name, value in row.items():
            cell_findings = self.detect_cell(value, col_name)
            for f in cell_findings:
                f.record_index = record_index
                all_findings.append(f)
        return all_findings

    # ------------------------------------------------------------------
    # File scanning (streaming)
    # ------------------------------------------------------------------

    def scan_csv(
        self,
        file_path: str,
        callback: Callable[[int, List[Finding]], None],
        *,
        chunksize: int = 1000,
    ) -> None:
        """Scan a CSV file in chunks, invoking callback per row with findings."""
        import time

        start_time = time.time()
        processed_rows = 0
        try:
            reader = pd.read_csv(
                file_path, chunksize=chunksize, dtype=str, keep_default_na=False
            )
            record_index = 0
            for chunk in reader:
                chunk_start = time.time()
                chunk_findings = 0
                for _, row in chunk.iterrows():
                    row_dict = row.to_dict()
                    findings = self.scan_row(row_dict, record_index)
                    if findings:
                        callback(record_index, findings)
                        chunk_findings += len(findings)
                    record_index += 1
                    processed_rows += 1
                logger.debug(
                    "Processed chunk of %d rows in %.2fs, found %d findings",
                    len(chunk),
                    time.time() - chunk_start,
                    chunk_findings,
                )
        except Exception as e:
            logger.error("Error scanning CSV file %s: %s", file_path, e)
            raise
        finally:
            logger.info(
                "Completed CSV scan: %d rows in %.2fs",
                processed_rows,
                time.time() - start_time,
            )

    def scan_json(
        self,
        file_path: str,
        callback: Callable[[int, List[Finding]], None],
    ) -> None:
        """Scan a newline-delimited JSON file (NDJSON)."""
        record_index = 0
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    findings = self.scan_row(obj, record_index)
                    if findings:
                        callback(record_index, findings)
                    record_index += 1

    def scan_parquet(
        self,
        file_path: str,
        callback: Callable[[int, List[Finding]], None],
        *,
        batch_size: int = 1000,
    ) -> None:
        """Scan a Parquet file using pyarrow in record batches."""
        if pq is None:
            raise RuntimeError("pyarrow is not installed; cannot read Parquet files")
        parquet_file = pq.ParquetFile(file_path)
        record_index = 0
        for batch in parquet_file.iter_batches(batch_size=batch_size):
            df = batch.to_pandas().astype(str)
            for _, row in df.iterrows():
                row_dict = row.to_dict()
                findings = self.scan_row(row_dict, record_index)
                if findings:
                    callback(record_index, findings)
                record_index += 1

    def scan_file(
        self,
        file_path: str,
        file_format: str,
        callback: Callable[[int, List[Finding]], None],
    ) -> None:
        """Dispatch scanning based on file format."""
        fmt = file_format.lower()
        if fmt == "csv":
            self.scan_csv(file_path, callback)
        elif fmt == "json":
            self.scan_json(file_path, callback)
        elif fmt in {"parquet", "parq"}:
            self.scan_parquet(file_path, callback)
        else:
            raise ValueError(f"Unsupported file format: {file_format}")
