"""Automated remediation suggestions for findings.

For each rule_id the module provides:
  - A list of human-readable remediation steps
  - Code snippets illustrating masking, encryption or tokenisation
  - An estimated effort level (low / medium / high)

Findings are prioritised by descending risk score then ascending effort so
that the highest-risk, lowest-effort items appear first.

Remediation status (open, in_progress, resolved) is tracked per finding ID
via RemediationTracker.  The tracker operates in-memory but its state can be
serialised to / from a plain dict for persistence by the caller.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Effort ranking (used for sorting)
# ---------------------------------------------------------------------------
class EffortLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


_EFFORT_RANK: Dict[str, int] = {
    EffortLevel.LOW: 1,
    EffortLevel.MEDIUM: 2,
    EffortLevel.HIGH: 3,
}


# ---------------------------------------------------------------------------
# Remediation status
# ---------------------------------------------------------------------------
class RemediationStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"


# ---------------------------------------------------------------------------
# Built-in remediation templates
# ---------------------------------------------------------------------------

@dataclass
class RemediationTemplate:
    rule_id: str
    title: str
    steps: List[str]
    code_snippet: str
    effort: EffortLevel
    references: List[str] = field(default_factory=list)


_TEMPLATES: Dict[str, RemediationTemplate] = {
    "us_ssn": RemediationTemplate(
        rule_id="us_ssn",
        title="Mask or tokenise US Social Security Numbers",
        steps=[
            "Identify all columns and tables storing raw SSNs.",
            "Replace stored SSNs with format-preserving tokens "
            "or store only the last four digits.",
            "Enforce column-level encryption (e.g. pgcrypto) for any "
            "column that must retain the full SSN.",
            "Restrict SELECT access to authorised roles only.",
            "Audit all application code paths that read SSN columns.",
        ],
        code_snippet=(
            "# Python – format-preserving SSN masking\n"
            "import re\n\n"
            "def mask_ssn(ssn: str) -> str:\n"
            "    \"\"\"Replace SSN digits with asterisks, retaining last 4.\"\"\"\n"
            "    clean = re.sub(r'\\D', '', ssn)\n"
            "    if len(clean) == 9:\n"
            "        return f'***-**-{clean[-4:]}'\n"
            "    return '***-**-****'\n"
        ),
        effort=EffortLevel.HIGH,
        references=["https://www.ssa.gov/privacy/", "GDPR Art. 25"],
    ),

    "tc_kimlik": RemediationTemplate(
        rule_id="tc_kimlik",
        title="Protect Turkish TC identity numbers",
        steps=[
            "Store TC Kimlik only when strictly necessary for legal purposes.",
            "Encrypt the column at rest using AES-256.",
            "Log all access to TC Kimlik columns in an audit table.",
            "Provide a pseudonymised ID (UUID) for all internal processing.",
        ],
        code_snippet=(
            "# Python – pseudonymise TC Kimlik\n"
            "import hashlib, hmac, os\n\n"
            "_SECRET = os.environ['TC_HASH_SECRET'].encode()\n\n"
            "def pseudonymise_tc(tc: str) -> str:\n"
            "    return hmac.new(_SECRET, tc.encode(), hashlib.sha256).hexdigest()\n"
        ),
        effort=EffortLevel.HIGH,
        references=["KVKK Art. 6", "GDPR Art. 9"],
    ),

    "credit_card": RemediationTemplate(
        rule_id="credit_card",
        title="Tokenise credit card PANs (PCI-DSS Req. 3)",
        steps=[
            "Remove raw PANs from logs and reports immediately.",
            "Integrate a PCI-compliant tokenisation vault "
            "(e.g. Stripe, Braintree, Vault).",
            "Display only the last four digits in UI.",
            "Ensure no PAN is stored in application logs.",
            "Run PCI-DSS SAQ or full QSA assessment.",
        ],
        code_snippet=(
            "# Python – store only last-four and card type\n"
            "def sanitise_card(pan: str) -> dict:\n"
            "    digits = pan.replace(' ', '').replace('-', '')\n"
            "    return {\n"
            "        'last_four': digits[-4:],\n"
            "        'masked': f'****-****-****-{digits[-4:]}',\n"
            "    }\n"
        ),
        effort=EffortLevel.HIGH,
        references=["PCI-DSS v4.0 Req. 3", "https://www.pcisecuritystandards.org/"],
    ),

    "iban": RemediationTemplate(
        rule_id="iban",
        title="Encrypt or mask IBAN bank account numbers",
        steps=[
            "Identify all storage locations for raw IBANs.",
            "Apply column-level encryption or use a tokenisation service.",
            "For display purposes, show only the last 4 characters of the BBAN.",
            "Restrict access to the decryption key via IAM policies.",
        ],
        code_snippet=(
            "# Python – IBAN masking for display\n"
            "def mask_iban(iban: str) -> str:\n"
            "    clean = iban.replace(' ', '').upper()\n"
            "    if len(clean) < 8:\n"
            "        return '****'\n"
            "    return clean[:4] + '*' * (len(clean) - 8) + clean[-4:]\n"
        ),
        effort=EffortLevel.MEDIUM,
        references=["GDPR Art. 32", "EBA Guidelines on ICT Risk"],
    ),

    "email": RemediationTemplate(
        rule_id="email",
        title="Pseudonymise or hash email addresses",
        steps=[
            "Use a keyed hash (HMAC-SHA256) for email-based lookups.",
            "Store the plain email only where legally required.",
            "Apply purpose limitation: do not share email with third parties "
            "beyond the original consent scope.",
        ],
        code_snippet=(
            "# Python – keyed email hash for pseudonymisation\n"
            "import hashlib, hmac, os\n\n"
            "_KEY = os.environ['EMAIL_HASH_KEY'].encode()\n\n"
            "def hash_email(email: str) -> str:\n"
            "    return hmac.new(_KEY, email.lower().encode(), hashlib.sha256).hexdigest()\n"
        ),
        effort=EffortLevel.LOW,
        references=["GDPR Art. 25", "GDPR Recital 26"],
    ),

    "medical_record": RemediationTemplate(
        rule_id="medical_record",
        title="Restrict and encrypt medical record numbers (HIPAA)",
        steps=[
            "Apply role-based access control; only clinical staff may read MRNs.",
            "Encrypt MRN columns using envelope encryption with a KMS key.",
            "Replace MRNs in analytics pipelines with surrogate keys.",
            "Log all access in a HIPAA-compliant audit trail.",
            "Conduct a HIPAA Security Risk Assessment.",
        ],
        code_snippet=(
            "# SQL – column-level encryption with pgcrypto (PostgreSQL)\n"
            "-- Encrypt:\n"
            "UPDATE patients\n"
            "SET mrn_encrypted = pgp_sym_encrypt(mrn::text, current_setting('app.mrn_key'))\n"
            "WHERE mrn IS NOT NULL;\n\n"
            "-- Decrypt (authorised users only):\n"
            "SELECT pgp_sym_decrypt(mrn_encrypted, current_setting('app.mrn_key')) AS mrn\n"
            "FROM patients;\n"
        ),
        effort=EffortLevel.HIGH,
        references=["HIPAA Security Rule 45 CFR §164.312", "NIST SP 800-111"],
    ),

    "passport": RemediationTemplate(
        rule_id="passport",
        title="Minimise passport data storage",
        steps=[
            "Store passport data only for identity verification; delete after verification.",
            "Apply encryption at rest.",
            "Implement a data retention policy and automated deletion.",
        ],
        code_snippet=(
            "# Python – redact passport number after verification\n"
            "def redact_passport(number: str) -> str:\n"
            "    \"\"\"Keep first 2 and last 2 chars, redact the rest.\"\"\"\n"
            "    if len(number) <= 4:\n"
            "        return '****'\n"
            "    return number[:2] + '*' * (len(number) - 4) + number[-2:]\n"
        ),
        effort=EffortLevel.MEDIUM,
        references=["GDPR Art. 5(1)(e)", "ICAO Doc 9303"],
    ),

    "eu_phone": RemediationTemplate(
        rule_id="eu_phone",
        title="Minimise and anonymise phone numbers",
        steps=[
            "Determine whether full phone storage is necessary for the stated purpose.",
            "Store only country code + area code for analytics use cases.",
            "Hash phone numbers used as lookup keys.",
        ],
        code_snippet=(
            "# Python – partial phone masking\n"
            "import re\n\n"
            "def mask_phone(phone: str) -> str:\n"
            "    digits = re.sub(r'\\D', '', phone)\n"
            "    if len(digits) < 6:\n"
            "        return '****'\n"
            "    return digits[:3] + '****' + digits[-3:]\n"
        ),
        effort=EffortLevel.LOW,
        references=["GDPR Art. 5"],
    ),

    "ipv4_address": RemediationTemplate(
        rule_id="ipv4_address",
        title="Anonymise IP addresses in logs",
        steps=[
            "Truncate the last octet of IPv4 addresses before storing logs.",
            "Apply log anonymisation at the reverse-proxy / load-balancer layer.",
            "Consider using differential privacy techniques for analytics.",
        ],
        code_snippet=(
            "# Python – last-octet zeroing for GDPR IP anonymisation\n"
            "def anonymise_ipv4(ip: str) -> str:\n"
            "    parts = ip.split('.')\n"
            "    if len(parts) == 4:\n"
            "        return '.'.join(parts[:3]) + '.0'\n"
            "    return ip\n"
        ),
        effort=EffortLevel.LOW,
        references=["GDPR WP29 Opinion 1/2008 on IP addresses"],
    ),

    "vat": RemediationTemplate(
        rule_id="vat",
        title="Control access to VAT registration numbers",
        steps=[
            "Classify VAT numbers as Confidential business data.",
            "Restrict access to finance and legal teams only.",
            "Remove from public-facing reports and API responses.",
        ],
        code_snippet=(
            "# Python – mask VAT number for display\n"
            "def mask_vat(vat: str) -> str:\n"
            "    if len(vat) <= 4:\n"
            "        return '****'\n"
            "    return vat[:2] + '*' * (len(vat) - 4) + vat[-2:]\n"
        ),
        effort=EffortLevel.LOW,
        references=["EU VAT Directive 2006/112/EC"],
    ),

    "national_id": RemediationTemplate(
        rule_id="national_id",
        title="Protect national identity documents",
        steps=[
            "Apply encryption at rest for all national ID fields.",
            "Implement strict need-to-know access controls.",
            "Log all access and set retention limits.",
        ],
        code_snippet=(
            "# Python – hash national ID for pseudonymisation\n"
            "import hashlib, hmac, os\n\n"
            "_KEY = os.environ['NID_HASH_KEY'].encode()\n\n"
            "def hash_national_id(nid: str) -> str:\n"
            "    return hmac.new(_KEY, nid.encode(), hashlib.sha256).hexdigest()\n"
        ),
        effort=EffortLevel.HIGH,
        references=["GDPR Art. 87"],
    ),
}

# Fallback template for unrecognised rule IDs
_FALLBACK_TEMPLATE = RemediationTemplate(
    rule_id="generic",
    title="Review and minimise exposure of sensitive data",
    steps=[
        "Identify whether storing this data is strictly necessary.",
        "Apply encryption at rest if storage is required.",
        "Restrict access via role-based access controls.",
        "Implement data minimisation as per privacy-by-design principles.",
    ],
    code_snippet=(
        "# General data minimisation pattern\n"
        "# 1. Identify if the field is required\n"
        "# 2. If not required, drop or null the column\n"
        "# 3. If required, encrypt before storing\n"
    ),
    effort=EffortLevel.MEDIUM,
    references=["GDPR Art. 5(1)(c) – Data Minimisation"],
)


# ---------------------------------------------------------------------------
# Suggestion output
# ---------------------------------------------------------------------------

@dataclass
class RemediationSuggestion:
    finding_id: Any
    rule_id: str
    column_name: str
    risk_score: float
    title: str
    steps: List[str]
    code_snippet: str
    effort: EffortLevel
    references: List[str]
    status: RemediationStatus = RemediationStatus.OPEN


# ---------------------------------------------------------------------------
# Main service
# ---------------------------------------------------------------------------

class RemediationService:
    """Generate and prioritise remediation suggestions for scan findings."""

    def get_suggestion(
        self,
        finding_id: Any,
        rule_id: str,
        column_name: str = "",
        risk_score: float = 5.0,
        status: RemediationStatus = RemediationStatus.OPEN,
    ) -> RemediationSuggestion:
        """Return a remediation suggestion for a single finding."""
        template = _TEMPLATES.get(rule_id, _FALLBACK_TEMPLATE)
        return RemediationSuggestion(
            finding_id=finding_id,
            rule_id=rule_id,
            column_name=column_name,
            risk_score=risk_score,
            title=template.title,
            steps=list(template.steps),
            code_snippet=template.code_snippet,
            effort=template.effort,
            references=list(template.references),
            status=status,
        )

    def suggest_for_scan(
        self,
        findings: List[Dict[str, Any]],
        risk_scores: Optional[Dict[Any, float]] = None,
    ) -> List[RemediationSuggestion]:
        """Generate prioritised suggestions for all findings in a scan.

        Parameters
        ----------
        findings:
            List of finding dicts containing at minimum ``id``, ``rule_id``
            and optionally ``column_name``.
        risk_scores:
            Optional mapping of finding_id -> risk_score (1-10).  When absent
            the finding's ``severity`` field is scaled to [1, 10].

        Returns
        -------
        List of RemediationSuggestion sorted by descending risk score then
        ascending effort.
        """
        suggestions: List[RemediationSuggestion] = []
        risk_scores = risk_scores or {}

        for f in findings:
            fid = f.get("id")
            rule_id = f.get("rule_id", "unknown")
            column_name = f.get("column_name", "")
            # Derive risk score: prefer pre-computed, fallback to severity * 10
            score = risk_scores.get(fid, float(f.get("severity", 0.5)) * 10.0)

            suggestion = self.get_suggestion(
                finding_id=fid,
                rule_id=rule_id,
                column_name=column_name,
                risk_score=round(score, 2),
            )
            suggestions.append(suggestion)

        # Deduplicate by rule_id to avoid showing the same fix multiple times,
        # keeping the entry with the highest risk score for that rule.
        seen_rules: Dict[str, RemediationSuggestion] = {}
        for s in suggestions:
            if s.rule_id not in seen_rules or s.risk_score > seen_rules[s.rule_id].risk_score:
                seen_rules[s.rule_id] = s

        deduped = list(seen_rules.values())

        # Sort: descending risk score, then ascending effort
        deduped.sort(
            key=lambda s: (-s.risk_score, _EFFORT_RANK.get(s.effort.value, 2))
        )
        return deduped

    def to_dict(self, suggestion: RemediationSuggestion) -> Dict[str, Any]:
        """Serialise a suggestion to a plain dict."""
        return {
            "finding_id": suggestion.finding_id,
            "rule_id": suggestion.rule_id,
            "column_name": suggestion.column_name,
            "risk_score": suggestion.risk_score,
            "title": suggestion.title,
            "steps": suggestion.steps,
            "code_snippet": suggestion.code_snippet,
            "effort": suggestion.effort.value,
            "references": suggestion.references,
            "status": suggestion.status.value,
        }


# ---------------------------------------------------------------------------
# Remediation tracker (in-memory, serialisable)
# ---------------------------------------------------------------------------

class RemediationTracker:
    """Track remediation status for individual findings.

    State is stored in a plain dict and can be persisted externally
    (e.g. in a database JSON column) via ``dump()`` / ``load()``.
    """

    def __init__(self) -> None:
        # finding_id -> {status, updated_at, notes}
        self._state: Dict[Any, Dict[str, Any]] = {}

    def update(
        self,
        finding_id: Any,
        status: RemediationStatus,
        notes: str = "",
    ) -> None:
        self._state[finding_id] = {
            "status": status.value,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "notes": notes,
        }
        logger.info(
            "Remediation status for finding %s set to %s", finding_id, status.value
        )

    def get_status(self, finding_id: Any) -> RemediationStatus:
        entry = self._state.get(finding_id)
        if entry is None:
            return RemediationStatus.OPEN
        return RemediationStatus(entry["status"])

    def dump(self) -> Dict[str, Any]:
        """Serialise state for external persistence."""
        return dict(self._state)

    @classmethod
    def load(cls, data: Dict[str, Any]) -> "RemediationTracker":
        """Restore tracker state from a previously serialised dict."""
        tracker = cls()
        tracker._state = {k: v for k, v in data.items()}
        return tracker
