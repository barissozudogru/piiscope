"""Readers for tabular and text sources.

Every reader yields pandas DataFrames in chunks so large files stream
through the detector without being fully loaded. Supported source types:
csv, json, jsonl (ndjson), parquet (requires the ``parquet`` extra),
plain text and directories containing any of the former.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Union

import pandas as pd

from piiscope.errors import FileReadError, UnsupportedFormatError

PathLike = Union[str, os.PathLike]  # noqa: UP007

SUPPORTED_EXTENSIONS = {
    ".csv": "csv",
    ".json": "json",
    ".jsonl": "jsonl",
    ".ndjson": "jsonl",
    ".parquet": "parquet",
    ".parq": "parquet",
    ".txt": "text",
    ".text": "text",
}

_TEXT_SNIFF_SIZE = 8192


def format_for_path(path: PathLike) -> str:
    """Return the reader name for a path, raising for unknown extensions."""
    suffix = Path(path).suffix.lower()
    reader = SUPPORTED_EXTENSIONS.get(suffix)
    if reader is None:
        raise UnsupportedFormatError(
            f"unsupported file type '{suffix or Path(path).name}'; "
            f"supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
        )
    return reader


def _check_readable(path: Path, max_file_size_mb: float | None) -> None:
    """Guard against missing files, oversized files and binary garbage."""
    if not path.is_file():
        raise FileReadError(f"file not found: {path}")
    if max_file_size_mb is not None:
        size_mb = path.stat().st_size / (1024 * 1024)
        if size_mb > max_file_size_mb:
            raise FileReadError(
                f"file {path} is {size_mb:.1f} MB which exceeds the {max_file_size_mb} MB limit"
            )
    if path.suffix.lower() not in (".parquet", ".parq"):
        with open(path, "rb") as fh:
            head = fh.read(_TEXT_SNIFF_SIZE)
        if b"\x00" in head:
            raise FileReadError(
                f"file {path} appears to be binary; only text formats "
                "(csv, json, jsonl, txt) and parquet are supported"
            )


def _batches(records: list[dict], chunk_size: int) -> Iterator[pd.DataFrame]:
    """Slice a record list into DataFrames of at most chunk_size rows."""
    for start in range(0, len(records), chunk_size):
        yield pd.DataFrame(records[start : start + chunk_size], dtype=str)


def _iter_csv(
    path: Path, chunk_size: int, encoding: str, encoding_errors: str
) -> Iterator[pd.DataFrame]:
    try:
        reader = pd.read_csv(
            path,
            chunksize=chunk_size,
            dtype=str,
            keep_default_na=False,
            encoding=encoding,
            encoding_errors=encoding_errors,
        )
        for chunk in reader:
            yield chunk.fillna("")
    except pd.errors.EmptyDataError:
        return
    except pd.errors.ParserError as exc:
        raise FileReadError(f"malformed csv file {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise FileReadError(f"cannot decode {path} as {encoding}: {exc}") from exc


def _iter_json(path: Path, chunk_size: int, encoding: str) -> Iterator[pd.DataFrame]:
    """Read a json file that is either an array of objects or json lines."""
    text = path.read_text(encoding=encoding, errors="replace").strip()
    records: list[dict] = []
    if text:
        try:
            payload = json.loads(text)
            if isinstance(payload, list):
                records = [r for r in payload if isinstance(r, dict)]
            elif isinstance(payload, dict):
                records = [payload]
        except json.JSONDecodeError:
            # Fall back to newline-delimited mode; malformed lines are skipped.
            records = []
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    records.append(obj)
    yield from _batches(records, chunk_size)


def _iter_jsonl(path: Path, chunk_size: int, encoding: str) -> Iterator[pd.DataFrame]:
    records: list[dict] = []
    with open(path, encoding=encoding, errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                records.append(obj)
    yield from _batches(records, chunk_size)


def _iter_parquet(path: Path, batch_size: int) -> Iterator[pd.DataFrame]:
    try:
        import pyarrow.parquet as pq  # type: ignore
    except ImportError as exc:  # pragma: no cover - exercised via doctor
        raise FileReadError(
            "pyarrow is not installed; install it with 'pip install piiscope[parquet]' "
            "to scan parquet files"
        ) from exc
    try:
        parquet_file = pq.ParquetFile(path)
        for batch in parquet_file.iter_batches(batch_size=batch_size):
            yield batch.to_pandas().astype(str)
    except Exception as exc:
        raise FileReadError(f"malformed parquet file {path}: {exc}") from exc


def _iter_text(path: Path, chunk_size: int, encoding: str) -> Iterator[pd.DataFrame]:
    lines: list[str] = []
    with open(path, encoding=encoding, errors="replace") as fh:
        for line in fh:
            lines.append(line.rstrip("\n"))
            if len(lines) >= chunk_size:
                yield pd.DataFrame({"text": lines}, dtype=str)
                lines = []
    if lines:
        yield pd.DataFrame({"text": lines}, dtype=str)


def iter_frames(
    source: PathLike,
    *,
    chunk_size: int = 5000,
    max_file_size_mb: float | None = None,
    encoding: str = "utf-8",
    encoding_errors: str = "replace",
    sample_rows: int | None = None,
) -> Iterator[pd.DataFrame]:
    """Yield a file's content as DataFrames of at most chunk_size rows.

    sample_rows caps the total number of rows yielded across chunks.
    csv input always decodes with encoding_errors handling so a stray
    latin-1 byte never aborts a scan; binary files are rejected up front.
    """
    path = Path(source)
    _check_readable(path, max_file_size_mb)
    reader = format_for_path(path)
    if reader == "csv":
        frames = _iter_csv(path, chunk_size, encoding, encoding_errors)
    elif reader == "json":
        frames = _iter_json(path, chunk_size, encoding)
    elif reader == "jsonl":
        frames = _iter_jsonl(path, chunk_size, encoding)
    elif reader == "parquet":
        frames = _iter_parquet(path, chunk_size)
    else:
        frames = _iter_text(path, chunk_size, encoding)

    yielded = 0
    for frame in frames:
        if sample_rows is not None and yielded >= sample_rows:
            return
        if sample_rows is not None and yielded + len(frame) > sample_rows:
            frame = frame.iloc[: sample_rows - yielded]
        yield frame
        yielded += len(frame)


def walk_directory(directory: PathLike) -> list[Path]:
    """Return every supported file below directory, sorted for stability."""
    root = Path(directory)
    if not root.is_dir():
        raise FileReadError(f"not a directory: {root}")
    files = [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS]
    return sorted(files)


def read_dataframe(
    source: PathLike,
    *,
    max_file_size_mb: float | None = None,
    encoding: str = "utf-8",
    sample_rows: int | None = None,
) -> pd.DataFrame:
    """Read a whole file into one DataFrame (used by remediation)."""
    frames: list[pd.DataFrame] = list(
        iter_frames(
            source,
            max_file_size_mb=max_file_size_mb,
            encoding=encoding,
            sample_rows=sample_rows,
        )
    )
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True)
