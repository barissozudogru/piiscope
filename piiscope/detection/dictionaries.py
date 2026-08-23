"""Dictionary and gazetteer support for the detection engine.

The detection engine uses built-in comprehensive name lists, hospital names,
medical terms, and drug catalogues to flag potential sensitive information.
These are loaded lazily from the package data.
"""

from __future__ import annotations

import functools
import importlib.resources
from pathlib import Path


@functools.lru_cache
def _load_data_file(filename: str) -> set[str]:
    """Load a text file from piiscope.detection.data into a set of lowercased words."""
    try:
        # For Python 3.9+ we use files()
        ref = importlib.resources.files("piiscope.detection.data").joinpath(filename)
        text = ref.read_text(encoding="utf-8")
        return {
            line.strip().lower()
            for line in text.splitlines()
            if line.strip() and not line.startswith("#")
        }
    except Exception:
        # Fallback if package is not installed normally or file is missing
        local_path = Path(__file__).parent / "data" / filename
        if local_path.is_file():
            text = local_path.read_text(encoding="utf-8")
            return {
                line.strip().lower()
                for line in text.splitlines()
                if line.strip() and not line.startswith("#")
            }
        return set()


def load_user_dictionary(filepath: str) -> set[str]:
    """Load a user-provided dictionary file into a set of lowercased words."""
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"User dictionary file not found: {filepath}")
    text = path.read_text(encoding="utf-8")
    return {
        line.strip().lower()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    }


def get_given_names() -> set[str]:
    return _load_data_file("given_names.txt")


def get_surnames() -> set[str]:
    return _load_data_file("surnames.txt")


def get_drug_names() -> set[str]:
    return _load_data_file("drug_names.txt")


def get_medical_terms() -> set[str]:
    return _load_data_file("medical_terms.txt")


def get_hospital_keywords() -> set[str]:
    return _load_data_file("hospital_keywords.txt")
