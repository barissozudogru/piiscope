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
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

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

from .dictionaries import (
    get_drug_names,
    get_given_names,
    get_hospital_keywords,
    get_medical_terms,
    get_surnames,
    load_user_dictionary,
)
from .regex_patterns import PATTERNS, PatternDefinition, build_custom_patterns
from .validators import (
    column_name_context_boost,
    iban_check,
    is_private_ip,
    is_valid_ipv4,
    is_valid_ipv6,
    luhn_check,
    tc_kimlik_check,
)

logger = logging.getLogger(__name__)

# Minimum confidence threshold below which findings are not emitted
# Column-name tokens that identify a column as holding only given names or only
# surnames. Matched on whole tokens (split on non-alphanumerics) so that "ad"
# (Turkish for given name) does not match "address".
_GIVEN_NAME_COLUMN_TOKENS = frozenset(
    {
        "first", "firstname", "given", "givenname", "forename", "forenames",
        "vorname", "prenom", "voornaam", "imie", "ad", "adi", "nombre", "primeiro",
    }
)
_NON_PERSON_COLUMN_TOKENS = frozenset(
    {
        "city", "town", "street", "address", "addr", "country", "state", "province",
        "region", "county", "zip", "postal", "postcode", "company", "organisation",
        "organization", "org", "employer", "vendor", "supplier", "product", "item",
        "sku", "brand", "category", "department", "dept", "url", "domain", "host",
        "path", "file", "filename", "hospital", "clinic", "school", "university",
    }
)
_SURNAME_COLUMN_TOKENS = frozenset(
    {
        "last", "lastname", "surname", "surnames", "family", "familyname",
        "nachname", "familienname", "soyad", "soyadi", "apellido", "apellidos",
        "sobrenome", "cognome", "achternaam", "nazwisko",
    }
)


_MIN_CONFIDENCE = 0.2

# Rules that require checksum validation before emitting
_CHECKSUM_VALIDATORS: dict[str, Callable[[str], bool]] = {
    "credit_card": luhn_check,
    "iban": iban_check,
    "iban_tr": iban_check,  # Turkish IBAN uses the same MOD-97 check
    "tc_kimlik": tc_kimlik_check,
}

# Plugin registry: external modules can call register_plugin() to extend detection
_PLUGINS: list[Callable[[str, str], list[Finding]]] = []


def register_plugin(fn: Callable[[str, str], list[Finding]]) -> None:
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
    metadata: dict[str, Any] = field(default_factory=dict)
    # Whether the finding was marked as a false positive
    is_false_positive: bool = False


class DetectionEngine:
    def __init__(self, profile: dict[str, Any]):
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
        self.patterns: dict[str, PatternDefinition] = {k: v for k, v in PATTERNS.items()}

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

        dict_cfg = self.profile.get("dictionaries", {})
        self.use_name_dict = dict_cfg.get("names", {}).get("enabled", True)
        self.use_hospital_dict = dict_cfg.get("hospitals", {}).get("enabled", True)
        self.use_drug_dict = dict_cfg.get("drugs", {}).get("enabled", True)
        self.use_medical_dict = dict_cfg.get("medical", {}).get("enabled", True)

        self.given_names = get_given_names().copy() if self.use_name_dict else set()
        self.surnames = get_surnames().copy() if self.use_name_dict else set()
        self.hospital_keywords = get_hospital_keywords().copy() if self.use_hospital_dict else set()
        self.drug_names = get_drug_names().copy() if self.use_drug_dict else set()
        self.medical_terms = get_medical_terms().copy() if self.use_medical_dict else set()

        user_dicts = self.profile.get("user_dictionaries", {})
        if "given_name" in user_dicts:
            self.given_names.update(load_user_dictionary(user_dicts["given_name"]))
        if "surname" in user_dicts:
            self.surnames.update(load_user_dictionary(user_dicts["surname"]))
        if "hospital_keyword" in user_dicts:
            self.hospital_keywords.update(load_user_dictionary(user_dicts["hospital_keyword"]))
        if "drug_name" in user_dicts:
            self.drug_names.update(load_user_dictionary(user_dicts["drug_name"]))
        if "medical_condition" in user_dicts:
            self.medical_terms.update(load_user_dictionary(user_dicts["medical_condition"]))

        self.stoplist_names = {
            "will",
            "bill",
            "mark",
            "may",
            "april",
            "june",
            "summer",
            "grace",
            "hope",
            "art",
            "rose",
            "joy",
            "sunny",
            "paris",
            "jordan",
            "georgia",
            "virginia",
            "chance",
            "guy",
            "earl",
            "miles",
            "ray",
            "dean",
            "lane",
            "page",
            "gene",
            "major",
            "king",
            "prince",
            "christian",
            "ivy",
            "olive",
            "amber",
            "pearl",
            "rusty",
            "ginger",
            "faith",
            "destiny",
            "autumn",
            "crystal",
            "angel",
            "precious",
            "lucky",
            "harmony",
            "melody",
            "dawn",
            "eve",
            "sky",
            "river",
            "brook",
            "forest",
            "stone",
            "rock",
            "cliff",
            "clay",
            "cole",
            "dale",
            "glen",
            "heath",
            "hunter",
            "mason",
            "taylor",
            "tyler",
            "carter",
            "cooper",
            "parker",
            "tanner",
            "walker",
            "ryder",
            "chase",
            "reed",
            "wade",
            "grant",
            "lance",
            "blaze",
            "rain",
            "storm",
            "winter",
        }

        # Suppression rules for false positive management
        # Format: [{rule_id: str, column_name: str (optional),
        #           value_pattern: str (optional regex)}]
        self._suppression_rules = self.profile.get("suppression_rules", [])
        self._suppression_compiled = []
        for rule in self._suppression_rules:
            vp = rule.get("value_pattern")
            self._suppression_compiled.append(
                {
                    "rule_id": rule.get("rule_id"),
                    "column_name": rule.get("column_name"),
                    "value_re": re.compile(vp, re.IGNORECASE) if vp else None,
                }
            )

        # NLP model
        model_cfg = self.profile.get("model", {})
        self.use_spacy = bool(model_cfg.get("use_spacy", False)) and spacy is not None
        self.nlp: Language | None = None
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

    def detect_cell(self, value: str, column_name: str) -> list[Finding]:
        """Detect sensitive information in a single cell.

        Returns a list of findings. Each finding carries:
          - severity from the pattern definition
          - base confidence from the rule type
          - context-adjusted confidence based on the column name
          - checksum-validated accuracy for credit cards, IBANs, TC Kimlik
        """
        findings: list[Finding] = []
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
                extra_meta: dict[str, Any] = {}
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
                    break

        # ------------------------------------------------------------------
        # 2. Dictionary look-ups
        # ------------------------------------------------------------------

        # Extract tokens with their original case for capitalization checks
        orig_tokens = [m.group() for m in re.finditer(r"\b\w+\b", text) if len(m.group()) >= 3]

        # We also need lower tokens for simple matching of drugs/hospitals
        tokens = [t.lower() for t in orig_tokens]
        bigrams = (
            [f"{tokens[i]} {tokens[i + 1]}" for i in range(len(tokens) - 1)]
            if len(tokens) > 1
            else []
        )

        col_tokens_all = set(re.split(r"[^a-z0-9]+", column_name.lower()))
        non_person_col = bool(col_tokens_all & _NON_PERSON_COLUMN_TOKENS) and not (
            col_tokens_all & (_GIVEN_NAME_COLUMN_TOKENS | _SURNAME_COLUMN_TOKENS | {"name"})
        )
        if self.use_name_dict and not non_person_col:
            given_name_ctx = column_name_context_boost(column_name, "given_name")
            surname_ctx = column_name_context_boost(column_name, "surname")
            col_tokens = set(re.split(r"[^a-z0-9]+", column_name.lower()))
            given_only_col = bool(col_tokens & _GIVEN_NAME_COLUMN_TOKENS) and not (
                col_tokens & _SURNAME_COLUMN_TOKENS
            )
            surname_only_col = bool(col_tokens & _SURNAME_COLUMN_TOKENS) and not (
                col_tokens & _GIVEN_NAME_COLUMN_TOKENS
            )
            is_name_col = (
                given_name_ctx > 1.0 or surname_ctx > 1.0 or given_only_col or surname_only_col
            )

            for i, token in enumerate(orig_tokens):
                lower_token = tokens[i]
                is_capitalised = token.istitle() or token.isupper()
                # A token that is both a given name and a surname, directly after a
                # given name in free text ("Ayse Yilmaz"), is read as the surname.
                follows_given_name = (
                    i > 0
                    and not is_name_col
                    and tokens[i - 1] in self.given_names
                    and lower_token in self.surnames
                )

                # Given name logic (skipped in columns that are explicitly surnames)
                if (
                    lower_token in self.given_names
                    and not surname_only_col
                    and not follows_given_name
                ):
                    # In name columns, match case-insensitively.
                    # In other columns, token must be capitalised and not in stoplist.
                    if is_name_col or (is_capitalised and lower_token not in self.stoplist_names):
                        ctx = given_name_ctx if is_name_col else max(1.0, given_name_ctx)
                        confidence = round(min(1.0, 0.6 * ctx), 3)
                        if confidence >= _MIN_CONFIDENCE:
                            f = Finding(
                                record_index=placeholder,
                                column_name=column_name,
                                rule_id="given_name",
                                severity=0.3,
                                confidence=confidence,
                                evidence=lower_token,
                            )
                            if not self._is_suppressed(f):
                                findings.append(f)

                # Surname logic (skipped in columns that are explicitly given names)
                if lower_token in self.surnames and not given_only_col:
                    fire_surname = False
                    if is_name_col:
                        fire_surname = True
                    elif is_capitalised:
                        # check if part of consecutive capitalised tokens, first being a given name
                        if i > 0:
                            prev = orig_tokens[i - 1]
                            if (
                                prev.istitle() or prev.isupper()
                            ) and prev.lower() in self.given_names:
                                fire_surname = True

                    if fire_surname:
                        ctx = surname_ctx if is_name_col else max(1.0, surname_ctx)
                        confidence = round(min(1.0, 0.6 * ctx), 3)
                        if confidence >= _MIN_CONFIDENCE:
                            f = Finding(
                                record_index=placeholder,
                                column_name=column_name,
                                rule_id="surname",
                                severity=0.3,
                                confidence=confidence,
                                evidence=lower_token,
                            )
                            if not self._is_suppressed(f):
                                findings.append(f)

        if self.use_hospital_dict:
            for t in tokens:
                if t in self.hospital_keywords:
                    f = Finding(
                        record_index=placeholder,
                        column_name=column_name,
                        rule_id="hospital_name",
                        severity=0.9,
                        confidence=0.7,
                        evidence=t,
                    )
                    if not self._is_suppressed(f):
                        findings.append(f)
            for b in bigrams:
                if b in self.hospital_keywords:
                    f = Finding(
                        record_index=placeholder,
                        column_name=column_name,
                        rule_id="hospital_name",
                        severity=0.9,
                        confidence=0.7,
                        evidence=b,
                    )
                    if not self._is_suppressed(f):
                        findings.append(f)

        if self.use_drug_dict:
            for t in tokens:
                if t in self.drug_names:
                    f = Finding(
                        record_index=placeholder,
                        column_name=column_name,
                        rule_id="drug_name",
                        severity=0.9,
                        confidence=0.7,
                        evidence=t,
                    )
                    if not self._is_suppressed(f):
                        findings.append(f)
            for b in bigrams:
                if b in self.drug_names:
                    f = Finding(
                        record_index=placeholder,
                        column_name=column_name,
                        rule_id="drug_name",
                        severity=0.9,
                        confidence=0.7,
                        evidence=b,
                    )
                    if not self._is_suppressed(f):
                        findings.append(f)

        if getattr(self, "use_medical_dict", False):
            for t in tokens:
                if t in self.medical_terms:
                    f = Finding(
                        record_index=placeholder,
                        column_name=column_name,
                        rule_id="medical_condition",
                        severity=0.9,
                        confidence=0.7,
                        evidence=t,
                    )
                    if not self._is_suppressed(f):
                        findings.append(f)
            for b in bigrams:
                if b in self.medical_terms:
                    f = Finding(
                        record_index=placeholder,
                        column_name=column_name,
                        rule_id="medical_condition",
                        severity=0.9,
                        confidence=0.7,
                        evidence=b,
                    )
                    if not self._is_suppressed(f):
                        findings.append(f)

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

        return _collapse_name_findings(findings)

    # ------------------------------------------------------------------
    # Row-level detection
    # ------------------------------------------------------------------

    def scan_row(self, row: dict[str, Any], record_index: int) -> list[Finding]:
        """Scan a dictionary representing one row and return all findings."""
        all_findings: list[Finding] = []
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
        callback: Callable[[int, list[Finding]], None],
        *,
        chunksize: int = 1000,
    ) -> None:
        """Scan a CSV file in chunks, invoking callback per row with findings."""
        import time

        start_time = time.time()
        processed_rows = 0
        try:
            reader = pd.read_csv(file_path, chunksize=chunksize, dtype=str, keep_default_na=False)
            record_index = 0
            for chunk in reader:
                chunk_start = time.time()
                chunk_findings = 0
                records = chunk.to_dict("records")
                for row_dict in records:
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
        callback: Callable[[int, list[Finding]], None],
    ) -> None:
        """Scan a newline-delimited JSON file (NDJSON)."""
        record_index = 0
        with open(file_path, encoding="utf-8") as f:
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
        callback: Callable[[int, list[Finding]], None],
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
            records = df.to_dict("records")
            for row_dict in records:
                findings = self.scan_row(row_dict, record_index)
                if findings:
                    callback(record_index, findings)
                record_index += 1

    def scan_file(
        self,
        file_path: str,
        file_format: str,
        callback: Callable[[int, list[Finding]], None],
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


def _collapse_name_findings(findings: list[Finding]) -> list[Finding]:
    """Keep one given_name and one surname finding per cell.

    Name detectors fire per token; a cell such as "Maria Silva Santos" would
    otherwise count as two surname hits, which inflates per-column hit counts
    beyond the number of rows. The highest-confidence finding is kept.
    """
    best: dict[str, Finding] = {}
    others: list[Finding] = []
    for finding in findings:
        if finding.rule_id in ("given_name", "surname"):
            current = best.get(finding.rule_id)
            if current is None or finding.confidence > current.confidence:
                best[finding.rule_id] = finding
        else:
            others.append(finding)
    return others + list(best.values())
