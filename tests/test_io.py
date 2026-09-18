"""Tests for piiscope.io readers and directory walking."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from piiscope.errors import FileReadError, UnsupportedFormatError
from piiscope.io.readers import (
    format_for_path,
    iter_frames,
    read_dataframe,
    walk_directory,
)


class TestFormatForPath:
    def test_known_extensions(self):
        assert format_for_path("data.csv") == "csv"
        assert format_for_path("data.json") == "json"
        assert format_for_path("data.jsonl") == "jsonl"
        assert format_for_path("data.ndjson") == "jsonl"
        assert format_for_path("data.parquet") == "parquet"
        assert format_for_path("data.parq") == "parquet"
        assert format_for_path("notes.txt") == "text"
        assert format_for_path("NOTES.CSV") == "csv"

    def test_unknown_extension(self):
        with pytest.raises(UnsupportedFormatError):
            format_for_path("data.xyz")


class TestCsvReading:
    def test_basic_csv(self, tmp_path):
        path = tmp_path / "basic.csv"
        path.write_text("a,b\n1,2\n3,4\n")
        frame = read_dataframe(path)
        assert len(frame) == 2
        assert list(frame.columns) == ["a", "b"]

    def test_latin1_bytes_do_not_crash(self, tmp_path):
        path = tmp_path / "latin.csv"
        path.write_bytes("name,city\nJosé,München\nÅke,Århus\n".encode("latin-1"))
        frame = read_dataframe(path)
        assert len(frame) == 2
        assert frame.iloc[0]["city"] != ""

    def test_chunked_iteration_preserves_order(self, tmp_path):
        path = tmp_path / "chunked.csv"
        rows = "\n".join(f"{i},value{i}" for i in range(10))
        path.write_text("id,val\n" + rows + "\n")
        seen = []
        for frame in iter_frames(path, chunk_size=3):
            seen.extend(frame["id"].tolist())
        assert seen == [str(i) for i in range(10)]

    def test_missing_file(self, tmp_path):
        with pytest.raises(FileReadError):
            read_dataframe(tmp_path / "nope.csv")

    def test_empty_file(self, tmp_path):
        path = tmp_path / "empty.csv"
        path.write_text("")
        frame = read_dataframe(path)
        assert len(frame) == 0

    def test_binary_file_rejected(self, tmp_path):
        path = tmp_path / "blob.csv"
        path.write_bytes(b"id\n\x00\x01\x02binary\xff\xfe\n")
        with pytest.raises(FileReadError):
            read_dataframe(path)

    def test_sample_rows_limit(self, tmp_path):
        path = tmp_path / "big.csv"
        path.write_text("id\n" + "\n".join(str(i) for i in range(100)) + "\n")
        frame = read_dataframe(path, sample_rows=5)
        assert len(frame) == 5


class TestJsonReading:
    def test_json_array(self, tmp_path):
        path = tmp_path / "array.json"
        path.write_text('[{"a": 1}, {"a": 2}]')
        frame = read_dataframe(path)
        assert len(frame) == 2
        assert frame.iloc[1]["a"] == "2"

    def test_jsonl_with_bad_lines(self, tmp_path):
        path = tmp_path / "stream.jsonl"
        path.write_text('{"a": 1}\nnot json\n{"a": 3}\n')
        frame = read_dataframe(path)
        assert frame["a"].tolist() == ["1", "3"]

    def test_empty_jsonl(self, tmp_path):
        path = tmp_path / "empty.jsonl"
        path.write_text("")
        frame = read_dataframe(path)
        assert len(frame) == 0


class TestTextReading:
    def test_lines_become_text_column(self, tmp_path):
        path = tmp_path / "notes.txt"
        path.write_text("first line\nsecond line\n")
        frame = read_dataframe(path)
        assert list(frame.columns) == ["text"]
        assert len(frame) == 2


class TestParquetReading:
    def test_round_trip(self, tmp_path):
        pytest.importorskip("pyarrow")
        path = tmp_path / "data.parquet"
        pd.DataFrame({"a": [1, 2], "b": ["x", "y"]}).to_parquet(path)
        frame = read_dataframe(path)
        assert len(frame) == 2
        assert frame.iloc[0]["b"] == "x"

    def test_parquet_bytes_skip_binary_sniff(self, tmp_path):
        pytest.importorskip("pyarrow")
        path = tmp_path / "blob.parquet"
        pd.DataFrame({"a": [1]}).to_parquet(path)
        assert path.read_bytes()[:4] == b"PAR1"
        frame = read_dataframe(path)
        assert len(frame) == 1


class TestDirectoryWalk:
    def test_only_supported_files_in_sorted_order(self, tmp_path):
        (tmp_path / "b.csv").write_text("a\n1\n")
        (tmp_path / "a.jsonl").write_text('{"a": 1}')
        (tmp_path / "skip.xyz").write_text("nope")
        (tmp_path / "nested").mkdir()
        (tmp_path / "nested" / "c.txt").write_text("hello\n")
        files = walk_directory(tmp_path)
        assert [f.name for f in files] == ["a.jsonl", "b.csv", "c.txt"]

    def test_scan_directory_via_public_api(self):
        from piiscope import scan
        from piiscope.io.readers import walk_directory

        samples = Path(__file__).resolve().parent.parent / "samples"
        result = scan(samples)
        expected_files = len(walk_directory(samples))
        assert result.files == expected_files
        assert result.rows > 0
        with_file = [f for f in result.findings if f.file == "customers.csv"]
        assert with_file, "findings should carry their source file name"
