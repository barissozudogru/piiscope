"""Jurisdiction-specific compliance profiles for privacy regulation mapping.

Each sub-module exports a PROFILE dict mapping pattern rule_id values to
compliance metadata:
  - status       : "required" | "optional" | "prohibited"
  - severity     : regulation-specific severity weight (0.0 - 1.0)
  - article      : the specific article / section that applies
  - obligation   : short human-readable description of the obligation
  - legal_basis  : required legal basis for lawful processing (if applicable)

The combine_jurisdictions() helper merges multiple profiles into a unified
compliance matrix keyed by rule_id, so callers can pass a list of applicable
jurisdictions and receive a single view of all obligations.
"""

from __future__ import annotations

from typing import Any

from .ccpa import PROFILE as CCPA_PROFILE
from .gdpr import PROFILE as GDPR_PROFILE
from .kvkk import PROFILE as KVKK_PROFILE
from .lgpd import PROFILE as LGPD_PROFILE

# Registry of all supported jurisdiction profiles
JURISDICTION_PROFILES: dict[str, dict[str, Any]] = {
    "GDPR": GDPR_PROFILE,
    "CCPA": CCPA_PROFILE,
    "KVKK": KVKK_PROFILE,
    "LGPD": LGPD_PROFILE,
}

__all__ = [
    "GDPR_PROFILE",
    "CCPA_PROFILE",
    "KVKK_PROFILE",
    "LGPD_PROFILE",
    "JURISDICTION_PROFILES",
    "combine_jurisdictions",
    "get_applicable_jurisdictions",
]


def combine_jurisdictions(
    jurisdiction_names: list[str],
) -> dict[str, list[dict[str, Any]]]:
    """Merge compliance profiles from multiple jurisdictions.

    Returns a dict keyed by rule_id. Each value is a list of jurisdiction
    obligations that apply to that rule, so a caller can see all applicable
    articles at a glance.

    Example output::

        {
            "email": [
                {"jurisdiction": "GDPR", "status": "required",
                 "article": "Art. 4(1)", ...},
                {"jurisdiction": "KVKK", "status": "required",
                 "article": "Art. 3(1)(d)", ...},
            ],
            ...
        }
    """
    merged: dict[str, list[dict[str, Any]]] = {}
    for jname in jurisdiction_names:
        profile = JURISDICTION_PROFILES.get(jname.upper())
        if profile is None:
            continue
        for rule_id, rule_meta in profile.items():
            entry = {"jurisdiction": jname.upper()}
            entry.update(rule_meta)
            merged.setdefault(rule_id, []).append(entry)
    return merged


def get_applicable_jurisdictions(
    rule_ids: list[str],
    jurisdictions: list[str] | None = None,
) -> dict[str, list[str]]:
    """Return the jurisdictions under which each rule_id has compliance obligations.

    If jurisdictions is None, all known profiles are checked.

    Returns a dict mapping rule_id -> list of jurisdiction names that mandate
    or regulate that data type.
    """
    if jurisdictions is None:
        jurisdictions = list(JURISDICTION_PROFILES.keys())

    result: dict[str, list[str]] = {}
    for rule_id in rule_ids:
        applicable = []
        for jname in jurisdictions:
            profile = JURISDICTION_PROFILES.get(jname.upper(), {})
            if rule_id in profile:
                applicable.append(jname.upper())
        if applicable:
            result[rule_id] = applicable
    return result
