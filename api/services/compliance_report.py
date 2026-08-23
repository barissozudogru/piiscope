"""Compliance report generator.

Generates three classes of compliance documents:

  1. GDPR Article 30 Records of Processing Activities (RoPA)
  2. Data Protection Impact Assessment (DPIA) skeleton
  3. General compliance summary with remediation recommendations

Output formats supported:
  - JSON  (machine-readable, always available)
  - HTML  (human-readable report with inline CSS)
  - PDF-ready Markdown (can be fed into pandoc or weasyprint)

Usage::

    from api.services.compliance_report import ComplianceReportGenerator

    generator = ComplianceReportGenerator()
    report = generator.generate(
        scan_id=42,
        findings=[...],          # list of finding dicts
        classified_inventory=[...],
        risk_summary=...,        # ScanRiskSummary
        suggestions=[...],       # list of RemediationSuggestion dicts
        format="json",
    )
"""

from __future__ import annotations

import html
import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Mapping: data category -> GDPR Article 30 processing purpose template
# ---------------------------------------------------------------------------
_CATEGORY_PURPOSE_MAP: dict[str, str] = {
    "PII": "Identity verification and service delivery",
    "PHI": "Healthcare provision and medical records management",
    "PCI": "Payment processing and financial transaction recording",
    "Confidential": "Internal business operations",
    "Internal": "System operations and logging",
    "Public": "Public-facing service delivery",
}

# GDPR legal basis options (informational)
_LEGAL_BASIS = [
    "Consent (Art. 6(1)(a))",
    "Contract (Art. 6(1)(b))",
    "Legal obligation (Art. 6(1)(c))",
    "Vital interests (Art. 6(1)(d))",
    "Public task (Art. 6(1)(e))",
    "Legitimate interests (Art. 6(1)(f))",
]

# Retention recommendations by category
_RETENTION_MAP: dict[str, str] = {
    "PII": "Delete within 30 days of purpose fulfilment unless legally required",
    "PHI": "Retain per applicable healthcare regulations (typically 10 years)",
    "PCI": "Retain transaction records for max 12 months; PAN not to be stored",
    "Confidential": "Per organisational data retention policy",
    "Internal": "90 days maximum for log data",
    "Public": "No specific retention limit required",
}


class ComplianceReportGenerator:
    """Generate GDPR RoPA, DPIA, and compliance summary reports."""

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def generate(
        self,
        scan_id: int,
        findings: list[dict[str, Any]],
        classified_inventory: list[dict[str, Any]],
        risk_summary: dict[str, Any] | None = None,
        suggestions: list[dict[str, Any]] | None = None,
        format: str = "json",
        organisation: str = "Organisation",
        data_controller: str = "Data Controller",
    ) -> str:
        """Generate a compliance report in the requested format.

        Parameters
        ----------
        scan_id:
            The scan job ID (used as a reference in the report).
        findings:
            Raw list of finding dicts from the database.
        classified_inventory:
            Output of ``DataClassifier.inventory_to_dict()``.
        risk_summary:
            Output of ``RiskScorer.score_scan()`` serialised to dict.
        suggestions:
            Prioritised remediation suggestions (dicts).
        format:
            One of ``"json"``, ``"html"``, ``"markdown"``.
        organisation:
            Name of the data-processing organisation.
        data_controller:
            Name / contact of the data controller.
        """
        payload = self._build_payload(
            scan_id=scan_id,
            findings=findings,
            classified_inventory=classified_inventory,
            risk_summary=risk_summary or {},
            suggestions=suggestions or [],
            organisation=organisation,
            data_controller=data_controller,
        )

        fmt = format.lower()
        if fmt == "json":
            return self._render_json(payload)
        if fmt == "html":
            return self._render_html(payload)
        if fmt in ("markdown", "md"):
            return self._render_markdown(payload)

        logger.warning("Unknown format '%s'; defaulting to JSON", format)
        return self._render_json(payload)

    # ------------------------------------------------------------------
    # Payload construction
    # ------------------------------------------------------------------

    def _build_payload(
        self,
        scan_id: int,
        findings: list[dict[str, Any]],
        classified_inventory: list[dict[str, Any]],
        risk_summary: dict[str, Any],
        suggestions: list[dict[str, Any]],
        organisation: str,
        data_controller: str,
    ) -> dict[str, Any]:
        generated_at = datetime.now(timezone.utc).isoformat()
        ropa = self._build_ropa(classified_inventory, organisation, data_controller)
        dpia = self._build_dpia(scan_id, findings, classified_inventory, risk_summary)

        return {
            "report_type": "compliance_report",
            "scan_id": scan_id,
            "generated_at": generated_at,
            "organisation": organisation,
            "data_controller": data_controller,
            "summary": {
                "total_findings": len(findings),
                "categories_detected": [e["category"] for e in classified_inventory],
                "aggregate_risk_score": risk_summary.get("aggregate_score", 0),
                "critical_findings": risk_summary.get("critical_count", 0),
                "high_findings": risk_summary.get("high_count", 0),
            },
            "gdpr_article_30_ropa": ropa,
            "dpia": dpia,
            "remediation_recommendations": suggestions[:20],  # top 20
        }

    def _build_ropa(
        self,
        inventory: list[dict[str, Any]],
        organisation: str,
        data_controller: str,
    ) -> dict[str, Any]:
        """Build GDPR Article 30 Records of Processing Activities."""
        processing_activities = []

        for entry in inventory:
            cat = entry["category"]
            activity = {
                "data_category": cat,
                "data_types_detected": entry["sub_labels"],
                "columns_affected": entry["column_names"],
                "purpose_of_processing": _CATEGORY_PURPOSE_MAP.get(cat, "Not specified"),
                "legal_basis": _LEGAL_BASIS[1],  # default: contract
                "retention_recommendation": _RETENTION_MAP.get(cat, "Per organisational policy"),
                "security_measures": self._default_security_measures(cat),
                "international_transfers": "Not identified - verify with DPO",
                "recipients": "Internal systems and authorised processors",
            }
            processing_activities.append(activity)

        return {
            "article": "GDPR Article 30",
            "controller": data_controller,
            "organisation": organisation,
            "processing_activities": processing_activities,
            "note": (
                "This RoPA was auto-generated from scan findings. "
                "It must be reviewed and validated by the Data Protection Officer."
            ),
        }

    def _build_dpia(
        self,
        scan_id: int,
        findings: list[dict[str, Any]],
        inventory: list[dict[str, Any]],
        risk_summary: dict[str, Any],
    ) -> dict[str, Any]:
        """Build a DPIA skeleton (GDPR Article 35)."""
        categories = [e["category"] for e in inventory]
        high_risk = any(c in categories for c in ("PII", "PHI", "PCI"))
        aggregate_score = risk_summary.get("aggregate_score", 0)

        dpia_required = high_risk or aggregate_score >= 7.0

        risks = []
        if "PHI" in categories:
            risks.append(
                {
                    "risk": "Processing of health data without explicit consent",
                    "likelihood": "High",
                    "impact": "High",
                    "mitigation": "Obtain explicit consent; "
                    "implement encryption and access controls",
                }
            )
        if "PCI" in categories:
            risks.append(
                {
                    "risk": "Exposure of payment card data violating PCI-DSS",
                    "likelihood": "Medium",
                    "impact": "High",
                    "mitigation": "Tokenise PANs; engage QSA for PCI-DSS audit",
                }
            )
        if "PII" in categories:
            risks.append(
                {
                    "risk": "Unlawful processing of personal data under GDPR",
                    "likelihood": "Medium",
                    "impact": "High",
                    "mitigation": "Review legal basis; apply data minimisation; "
                    "implement DSAR process",
                }
            )
        if aggregate_score >= 7.0:
            risks.append(
                {
                    "risk": "High aggregate risk score indicating systemic data exposure",
                    "likelihood": "High",
                    "impact": "High",
                    "mitigation": (
                        "Prioritise critical and high findings for immediate remediation; "
                        "engage security team"
                    ),
                }
            )

        return {
            "article": "GDPR Article 35",
            "scan_reference": scan_id,
            "dpia_required": dpia_required,
            "risk_assessment": {
                "aggregate_score": aggregate_score,
                "critical_findings": risk_summary.get("critical_count", 0),
                "risks_identified": risks,
            },
            "necessity_proportionality": (
                "Assessment required: verify that data processing is limited to "
                "what is necessary for the stated purpose."
            ),
            "data_subject_rights": [
                "Right of access (Art. 15)",
                "Right to rectification (Art. 16)",
                "Right to erasure (Art. 17)",
                "Right to restriction (Art. 18)",
                "Right to data portability (Art. 20)",
                "Right to object (Art. 21)",
            ],
            "dpo_consultation_required": dpia_required,
            "note": (
                "This DPIA skeleton requires completion by the Data Protection Officer. "
                "It covers only fields identified during the automated scan."
            ),
        }

    @staticmethod
    def _default_security_measures(category: str) -> list[str]:
        base = [
            "Encryption at rest (AES-256)",
            "Encryption in transit (TLS 1.2+)",
            "Role-based access control",
            "Audit logging of all access",
        ]
        if category in ("PHI", "PCI"):
            base += [
                "Multi-factor authentication required",
                "Regular penetration testing",
                "Incident response plan in place",
            ]
        if category == "PCI":
            base.append("PCI-DSS compliance programme")
        return base

    # ------------------------------------------------------------------
    # Renderers
    # ------------------------------------------------------------------

    @staticmethod
    def _render_json(payload: dict[str, Any]) -> str:
        return json.dumps(payload, indent=2, default=str)

    @staticmethod
    def _render_html(payload: dict[str, Any]) -> str:
        def esc(v: Any) -> str:
            return html.escape(str(v))

        summary = payload["summary"]
        ropa = payload["gdpr_article_30_ropa"]
        dpia = payload["dpia"]
        suggestions = payload.get("remediation_recommendations", [])

        activities_rows = ""
        for act in ropa.get("processing_activities", []):
            activities_rows += (
                f"<tr><td>{esc(act['data_category'])}</td>"
                f"<td>{esc(', '.join(act['data_types_detected']))}</td>"
                f"<td>{esc(act['purpose_of_processing'])}</td>"
                f"<td>{esc(act['legal_basis'])}</td>"
                f"<td>{esc(act['retention_recommendation'])}</td></tr>\n"
            )

        risks_rows = ""
        for r in dpia.get("risk_assessment", {}).get("risks_identified", []):
            risks_rows += (
                f"<tr><td>{esc(r['risk'])}</td>"
                f"<td>{esc(r['likelihood'])}</td>"
                f"<td>{esc(r['impact'])}</td>"
                f"<td>{esc(r['mitigation'])}</td></tr>\n"
            )

        remediation_items = ""
        for s in suggestions:
            steps_html = "".join(f"<li>{esc(st)}</li>" for st in s.get("steps", []))
            risk_score = s.get("risk_score", 0)
            effort = s.get("effort", "")
            title = s.get("title", "")
            snippet = s.get("code_snippet", "")
            remediation_items += (
                f"<div class='remediation-item'>"
                f"<h4>{esc(title)} "
                f"<span class='badge risk-{risk_score:.0f}'>"
                f"Risk: {risk_score:.1f}</span>"
                f"<span class='badge effort-{esc(effort)}'>"
                f"Effort: {esc(effort)}</span></h4>"
                f"<ul>{steps_html}</ul>"
                f"<pre><code>{esc(snippet)}</code></pre>"
                f"</div>\n"
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Compliance Report - Scan {esc(str(payload["scan_id"]))}</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #222; }}
  h1 {{ border-bottom: 2px solid #1a56db; padding-bottom: .5rem; }}
  h2 {{ color: #1a56db; margin-top: 2rem; }}
  h3 {{ color: #374151; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
  th, td {{ border: 1px solid #d1d5db; padding: .5rem .75rem; text-align: left; font-size: .9rem; }}
  th {{ background: #f3f4f6; font-weight: 600; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(3, 1fr);
    gap: 1rem; margin: 1rem 0; }}
  .metric {{ background: #f0f9ff; border: 1px solid #bae6fd;
    border-radius: .5rem; padding: 1rem; text-align: center; }}
  .metric h4 {{ margin: 0 0 .25rem; font-size: .85rem; color: #64748b; }}
  .metric span {{ font-size: 1.75rem; font-weight: 700; color: #0284c7; }}
  .badge {{ font-size: .7rem; padding: .15rem .4rem; border-radius: .25rem;
            background: #e5e7eb; color: #374151; margin-left: .5rem; }}
  .remediation-item {{ border: 1px solid #e5e7eb; border-radius: .5rem;
                       padding: 1rem; margin: .75rem 0; }}
  .remediation-item h4 {{ margin: 0 0 .5rem; }}
  pre {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: .375rem;
         padding: .75rem; overflow-x: auto; font-size: .82rem; }}
  .notice {{ background: #fffbeb; border-left: 4px solid #f59e0b;
             padding: .75rem 1rem; margin: 1rem 0; }}
</style>
</head>
<body>
<h1>Compliance Report</h1>
<p><strong>Scan ID:</strong> {esc(str(payload["scan_id"]))} &nbsp;|&nbsp;
   <strong>Generated:</strong> {esc(payload["generated_at"])} &nbsp;|&nbsp;
   <strong>Organisation:</strong> {esc(payload["organisation"])}</p>

<h2>Executive Summary</h2>
<div class="summary-grid">
  <div class="metric"><h4>Total Findings</h4><span>{summary["total_findings"]}</span></div>
  <div class="metric"><h4>Aggregate Risk</h4><span>{summary["aggregate_risk_score"]}</span></div>
  <div class="metric"><h4>Critical Findings</h4><span>{summary["critical_findings"]}</span></div>
</div>

<h2>GDPR Article 30 - Records of Processing Activities</h2>
<div class="notice">This RoPA is auto-generated and must be reviewed by the DPO before use.</div>
<table>
<thead><tr>
  <th>Data Category</th><th>Data Types</th><th>Purpose</th><th>Legal Basis</th><th>Retention</th>
</tr></thead>
<tbody>{activities_rows}</tbody>
</table>

<h2>DPIA - Risk Assessment (GDPR Article 35)</h2>
<p><strong>DPIA Required:</strong> {esc(str(dpia["dpia_required"]))} &nbsp;|&nbsp;
   <strong>DPO Consultation Required:</strong> {esc(str(dpia["dpo_consultation_required"]))}</p>
<table>
<thead><tr><th>Risk</th><th>Likelihood</th><th>Impact</th><th>Mitigation</th></tr></thead>
<tbody>{risks_rows}</tbody>
</table>

<h2>Remediation Recommendations</h2>
{remediation_items if remediation_items else "<p>No remediation recommendations generated.</p>"}

</body>
</html>"""

    @staticmethod
    def _render_markdown(payload: dict[str, Any]) -> str:
        summary = payload["summary"]
        ropa = payload["gdpr_article_30_ropa"]
        dpia = payload["dpia"]
        suggestions = payload.get("remediation_recommendations", [])
        generated_at = payload["generated_at"]
        scan_id = payload["scan_id"]

        lines: list[str] = [
            f"# Compliance Report - Scan {scan_id}",
            "",
            f"**Generated:** {generated_at}  ",
            f"**Organisation:** {payload['organisation']}  ",
            f"**Data Controller:** {payload['data_controller']}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Total Findings | {summary['total_findings']} |",
            f"| Aggregate Risk Score | {summary['aggregate_risk_score']} |",
            f"| Critical Findings | {summary['critical_findings']} |",
            f"| High Findings | {summary['high_findings']} |",
            f"| Categories Detected | {', '.join(summary['categories_detected'])} |",
            "",
            "---",
            "",
            "## GDPR Article 30 - Records of Processing Activities",
            "",
            "> **Note:** This RoPA is auto-generated from scan results and must be reviewed "
            "and validated by the Data Protection Officer before use.",
            "",
            "| Category | Data Types | Purpose | Legal Basis | Retention |",
            "|---|---|---|---|---|",
        ]

        for act in ropa.get("processing_activities", []):
            lines.append(
                f"| {act['data_category']} "
                f"| {', '.join(act['data_types_detected'])} "
                f"| {act['purpose_of_processing']} "
                f"| {act['legal_basis']} "
                f"| {act['retention_recommendation']} |"
            )

        lines += [
            "",
            "---",
            "",
            "## DPIA - Data Protection Impact Assessment (GDPR Article 35)",
            "",
            f"**DPIA Required:** {dpia['dpia_required']}  ",
            f"**DPO Consultation:** {dpia['dpo_consultation_required']}  ",
            f"**Aggregate Risk Score:** {dpia['risk_assessment']['aggregate_score']}",
            "",
            "### Risks Identified",
            "",
            "| Risk | Likelihood | Impact | Mitigation |",
            "|---|---|---|---|",
        ]

        for r in dpia["risk_assessment"].get("risks_identified", []):
            lines.append(f"| {r['risk']} | {r['likelihood']} | {r['impact']} | {r['mitigation']} |")

        lines += [
            "",
            "### Data Subject Rights",
            "",
        ]
        for right in dpia.get("data_subject_rights", []):
            lines.append(f"- {right}")

        lines += [
            "",
            "---",
            "",
            "## Remediation Recommendations",
            "",
        ]

        for i, s in enumerate(suggestions, 1):
            lines += [
                f"### {i}. {s.get('title', 'Untitled')}",
                "",
                f"**Risk Score:** {s.get('risk_score', 0):.1f} / 10  ",
                f"**Effort:** {s.get('effort', 'medium')}  ",
                f"**Column:** `{s.get('column_name', 'N/A')}`  ",
                f"**Rule:** `{s.get('rule_id', 'N/A')}`",
                "",
                "**Steps:**",
                "",
            ]
            for step in s.get("steps", []):
                lines.append(f"1. {step}")

            if s.get("code_snippet"):
                lines += [
                    "",
                    "```python",
                    s["code_snippet"].rstrip(),
                    "```",
                ]

            if s.get("references"):
                lines += [
                    "",
                    "**References:**",
                    "",
                ]
                for ref in s["references"]:
                    lines.append(f"- {ref}")
            lines.append("")

        return "\n".join(lines)
