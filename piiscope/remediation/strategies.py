"""Apply remediation strategies to columns of a dataset.

A strategy maps one column value to a safe replacement value:

- hash: SHA-256 hex digest (deterministic, not salted)
- redact: keep the first and last characters, mask the middle
- null: empty string
- generalise: numeric values become ranges, dates become years,
  anything else is redacted
- tokenise: salted hash (pseudonym that is stable for one salt)
- date-shift: dates moved by a fixed number of days

``remediate`` reads a source, works out which columns hold findings
(unless columns are given explicitly), applies the strategy and writes
the result to a new file.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union

import pandas as pd

from piiscope.errors import PiiscopeError, RemediationError
from piiscope.io.readers import format_for_path, read_dataframe
from piiscope.remediation.masking import (
    date_shift,
    generalize_numeric,
    hash_value,
    partial_redact,
    tokenize_value,
)

PathLike = Union[str, Path]  # noqa: UP007

STRATEGIES = ("hash", "redact", "null", "generalise", "tokenise", "date-shift")

_WRITE_FORMATS = ("csv", "json", "jsonl", "parquet", "text")


def _generalise(value: str, bucket_size: int) -> str:
    # only bucket short numerics: long digit strings (card and account
    # numbers) would leak a Luhn-valid range boundary, so redact them
    if value.isdigit() and len(value) > 9:
        return partial_redact(value)
    bucket = generalize_numeric(value, bucket_size)
    if bucket is not None:
        return bucket
    shifted = date_shift(value, 0)
    if shifted is not None:
        return shifted[:4]
    if value == "":
        return ""
    return partial_redact(value)


def _shift(value: str, days: int) -> str:
    if value == "":
        return ""
    shifted = date_shift(value, days)
    return shifted if shifted is not None else partial_redact(value)


def _make_transform(
    strategy: str, salt: str, bucket_size: int, shift_days: int
) -> Callable[[str], str]:
    if strategy == "hash":
        return lambda v: hash_value(v) if v != "" else ""
    if strategy == "redact":
        return lambda v: partial_redact(v) if v != "" else ""
    if strategy == "null":
        return lambda v: ""
    if strategy == "generalise":
        return lambda v: _generalise(v, bucket_size)
    if strategy == "tokenise":
        return lambda v: tokenize_value(v, salt) if v != "" else ""
    if strategy == "date-shift":
        return lambda v: _shift(v, shift_days)
    raise RemediationError(f"unknown strategy '{strategy}'; choose from {', '.join(STRATEGIES)}")


def apply_strategy(
    frame: pd.DataFrame,
    *,
    strategy: str,
    columns: Sequence[str],
    salt: str | None = None,
    bucket_size: int = 10,
    shift_days: int = 30,
) -> tuple[dict[str, int], str]:
    """Transform the given columns in place; return changed value counts and the salt."""
    if strategy not in STRATEGIES:
        raise RemediationError(
            f"unknown strategy '{strategy}'; choose from {', '.join(STRATEGIES)}"
        )
    effective_salt = salt if salt is not None else secrets.token_hex(16)
    transform = _make_transform(strategy, effective_salt, bucket_size, shift_days)
    changed: dict[str, int] = {}
    for column in columns:
        if column not in frame.columns:
            raise RemediationError(
                f"column '{column}' not found; available: {', '.join(map(str, frame.columns))}"
            )
        series = frame[column].astype(str)
        transformed = series.map(transform)
        changed[column] = int((transformed != series).sum())
        frame[column] = transformed
    return changed, effective_salt


def columns_with_findings(source: PathLike, **scan_kwargs) -> list[str]:
    """Return every column that produced at least one finding."""
    # Imported here to avoid a circular import with piiscope.scan.
    from piiscope.scan import scan

    result = scan(source, **scan_kwargs)
    columns: list[str] = []
    for finding in result.findings:
        if finding.column not in columns:
            columns.append(finding.column)
    return columns


@dataclass
class RemediationResult:
    """Outcome of a remediate() call."""

    source: str
    out: str
    strategy: str
    rows: int
    columns_changed: dict[str, int] = field(default_factory=dict)
    salt: str | None = None


def remediate_frame(
    frame: pd.DataFrame,
    *,
    strategy: str = "hash",
    columns: Sequence[str] | None = None,
    salt: str | None = None,
    bucket_size: int = 10,
    shift_days: int = 30,
    source: PathLike | None = None,
) -> tuple[dict[str, int], str]:
    """Apply a strategy to a DataFrame in place.

    When columns is None every column holding findings is selected by
    scanning source (or the frame itself when no source is given).
    """
    if strategy not in STRATEGIES:
        raise RemediationError(
            f"unknown strategy '{strategy}'; choose from {', '.join(STRATEGIES)}"
        )
    selected = list(columns) if columns is not None else None
    if selected is None:
        scan_target: str | Path | pd.DataFrame = source if source is not None else frame
        selected = columns_with_findings(
            scan_target, include_metrics=False, jurisdictions=("gdpr", "ccpa", "kvkk", "lgpd")
        )
    return apply_strategy(
        frame,
        strategy=strategy,
        columns=selected,
        salt=salt,
        bucket_size=bucket_size,
        shift_days=shift_days,
    )


def _write_frame(frame: pd.DataFrame, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    writer = format_for_path(out)
    if writer == "csv":
        frame.to_csv(out, index=False)
    elif writer == "json":
        frame.to_json(out, orient="records", indent=2, force_ascii=False)
    elif writer == "jsonl":
        frame.to_json(out, orient="records", lines=True, force_ascii=False)
    elif writer == "parquet":
        try:
            frame.to_parquet(out, index=False)
        except ImportError as exc:
            raise RemediationError(
                "pyarrow is not installed; install it with "
                "'pip install piiscope[parquet]' to write parquet output"
            ) from exc
    elif writer == "text":
        column = "text" if "text" in frame.columns else frame.columns[0]
        out.write_text("\n".join(frame[column].astype(str)) + "\n", encoding="utf-8")
    else:  # pragma: no cover - format_for_path already validated
        raise PiiscopeError(f"cannot write {writer} output")


def remediate(
    source: str | Path | pd.DataFrame,
    out: PathLike,
    *,
    strategy: str = "hash",
    columns: Sequence[str] | None = None,
    salt: str | None = None,
    bucket_size: int = 10,
    shift_days: int = 30,
    max_file_size_mb: float | None = None,
) -> RemediationResult:
    """Remediate a source file and write the result to out.

    columns=None selects every column that produced findings in a full
    four-jurisdiction scan of the source.
    """
    out_path = Path(out)
    if isinstance(source, pd.DataFrame):
        frame = source.fillna("").astype(str)
        source_label = "dataframe"
    else:
        source_path = Path(source)
        if not source_path.is_file():
            raise RemediationError(f"file not found: {source_path}")
        source_label = str(source_path)
        frame = read_dataframe(source_path, max_file_size_mb=max_file_size_mb)

    changed, effective_salt = remediate_frame(
        frame,
        strategy=strategy,
        columns=columns,
        salt=salt,
        bucket_size=bucket_size,
        shift_days=shift_days,
        source=source_label if source_label != "dataframe" else None,
    )
    _write_frame(frame, out_path)
    return RemediationResult(
        source=source_label,
        out=str(out_path),
        strategy=strategy,
        rows=len(frame),
        columns_changed=changed,
        salt=effective_salt if strategy == "tokenise" else None,
    )
