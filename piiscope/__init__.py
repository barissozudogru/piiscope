"""piiscope: find, score and remediate personal data in files and databases."""

from piiscope import detection, errors, io, metrics, remediation, report
from piiscope.errors import (
    FileReadError,
    PiiscopeError,
    RemediationError,
    UnsupportedFormatError,
)
from piiscope.remediation.strategies import RemediationResult, remediate, remediate_frame
from piiscope.scan import (
    JURISDICTIONS,
    Finding,
    MetricsResult,
    RiskScore,
    ScanResult,
    scan,
)

__version__ = "1.3.0"

__all__ = [
    "JURISDICTIONS",
    "FileReadError",
    "Finding",
    "MetricsResult",
    "PiiscopeError",
    "RemediationError",
    "RemediationResult",
    "RiskScore",
    "ScanResult",
    "UnsupportedFormatError",
    "__version__",
    "detection",
    "errors",
    "io",
    "metrics",
    "remediate",
    "remediate_frame",
    "remediation",
    "report",
    "scan",
]
