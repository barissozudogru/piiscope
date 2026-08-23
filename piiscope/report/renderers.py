"""Render a ScanResult as markdown, json or html."""

from __future__ import annotations

import html
from pathlib import Path
from typing import TYPE_CHECKING

from piiscope.errors import PiiscopeError

if TYPE_CHECKING:  # pragma: no cover - typing only
    from piiscope.scan import ScanResult


def render_markdown(result: ScanResult) -> str:
    """Render a scan result as a markdown document."""
    lines: list[str] = [
        "# piiscope report",
        "",
        f"**Source:** {result.source}  ",
        f"**Rows:** {result.rows}  ",
        f"**Columns:** {result.columns}  ",
        f"**Files:** {result.files}  ",
        f"**Jurisdictions:** {', '.join(result.jurisdictions)}  ",
        f"**Scan time:** {result.scan_time:.2f}s",
        "",
        "## Risk",
        "",
        f"Score **{result.risk.score}/100** ({result.risk.level}).",
        "",
    ]
    if result.risk.drivers:
        lines.append("Top drivers:")
        lines.append("")
        for driver in result.risk.drivers:
            lines.append(f"- {driver}")
        lines.append("")

    lines += ["## Findings", ""]
    if not result.findings:
        lines.append("No personal data findings.")
        lines.append("")
    else:
        lines += [
            "| Column | Category | Detector | Count | Confidence | Jurisdictions |",
            "|---|---|---|---:|---:|---|",
        ]
        for f in result.findings:
            where = f"{f.file}: {f.column}" if f.file else f.column
            lines.append(
                f"| {where} | {f.category} | {f.detector} | {f.count} "
                f"| {f.confidence:.2f} | {', '.join(f.jurisdictions) or '-'} |"
            )
        lines.append("")

    lines += ["## Metrics", ""]
    if result.metrics is None:
        lines.append("No metrics computed (no quasi identifiers or metrics disabled).")
        lines.append("")
    else:
        qi = ", ".join(result.metrics.quasi_identifiers) or "-"
        sensitive = result.metrics.sensitive_attribute or "-"
        k = "-" if result.metrics.k_anonymity is None else str(result.metrics.k_anonymity)
        l_div = "-" if result.metrics.l_diversity is None else str(result.metrics.l_diversity)
        t = "-" if result.metrics.t_closeness is None else f"{result.metrics.t_closeness:.3f}"
        lines += [
            "| Metric | Value |",
            "|---|---|",
            f"| Quasi identifiers | {qi} |",
            f"| Sensitive attribute | {sensitive} |",
            f"| k-anonymity | {k} |",
            f"| l-diversity | {l_div} |",
            f"| t-closeness | {t} |",
            "",
        ]

    lines += [
        "## Next steps",
        "",
        "Remediate the columns above, for example:",
        "",
        "```bash",
        f'piiscope remediate "{result.source}" --out safe.csv --strategy hash',
        "```",
        "",
    ]
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    """Render a scan result as indented json."""
    return result.to_json()


def render_html(result: ScanResult) -> str:
    """Render a scan result as a standalone html document."""
    e = html.escape
    findings_rows = "".join(
        f"<tr><td>{e(f.file + ': ' if f.file else '')}{e(f.column)}</td>"
        f"<td>{e(f.category)}</td><td>{e(f.detector)}</td>"
        f"<td class='num'>{f.count}</td>"
        f"<td class='num'>{f.confidence:.2f}</td>"
        f"<td>{e(', '.join(f.jurisdictions) or '-')}</td></tr>"
        for f in result.findings
    )
    drivers = "".join(f"<li>{e(d)}</li>" for d in result.risk.drivers)
    if result.metrics is None:
        metrics_html = "<p>No metrics computed.</p>"
    else:
        m = result.metrics
        k_html = m.k_anonymity if m.k_anonymity is not None else "-"
        l_html = m.l_diversity if m.l_diversity is not None else "-"
        t_html = f"{m.t_closeness:.3f}" if m.t_closeness is not None else "-"
        qi_html = e(", ".join(m.quasi_identifiers) or "-")
        metrics_html = (
            "<table><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>"
            f"<tr><td>Quasi identifiers</td><td>{qi_html}</td></tr>"
            f"<tr><td>Sensitive attribute</td><td>{e(m.sensitive_attribute or '-')}</td></tr>"
            f"<tr><td>k-anonymity</td><td>{k_html}</td></tr>"
            f"<tr><td>l-diversity</td><td>{l_html}</td></tr>"
            f"<tr><td>t-closeness</td><td>{t_html}</td></tr>"
            "</tbody></table>"
        )
    if findings_rows:
        findings_table = (
            "<table><thead><tr><th>Column</th><th>Category</th>"
            "<th>Detector</th><th>Count</th><th>Confidence</th>"
            "<th>Jurisdictions</th></tr></thead><tbody>"
            f"{findings_rows}</tbody></table>"
        )
    else:
        findings_table = "<p>No personal data findings.</p>"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>piiscope report</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1f2937; }}
h1, h2 {{ color: #111827; border-bottom: 2px solid #2563eb; padding-bottom: .3rem; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
th, td {{ border: 1px solid #d1d5db; padding: .45rem .7rem; text-align: left; font-size: .92rem; }}
th {{ background: #f3f4f6; }}
td.num {{ text-align: right; }}
.level {{ font-weight: 700; padding: .2rem .6rem; border-radius: .3rem; background: #e5e7eb; }}
.level.critical {{ background: #fee2e2; color: #991b1b; }}
.level.high {{ background: #ffedd5; color: #9a3412; }}
.level.medium {{ background: #fef9c3; color: #854d0e; }}
.level.low {{ background: #dcfce7; color: #166534; }}
ul {{ margin-top: .4rem; }}
</style>
</head>
<body>
<h1>piiscope report</h1>
<p><strong>Source:</strong> {e(result.source)} |
<strong>Rows:</strong> {result.rows} |
<strong>Columns:</strong> {result.columns} |
<strong>Files:</strong> {result.files} |
<strong>Jurisdictions:</strong> {e(", ".join(result.jurisdictions))} |
<strong>Scan time:</strong> {result.scan_time:.2f}s</p>

<h2>Risk</h2>
<p>Score <strong>{result.risk.score}/100</strong>
<span class="level {e(result.risk.level)}">{e(result.risk.level)}</span></p>
{f"<ul>{drivers}</ul>" if drivers else ""}

<h2>Findings</h2>
{findings_table}

<h2>Metrics</h2>
{metrics_html}

<h2>Next steps</h2>
<p>Remediate the affected columns, for example:</p>
<pre>piiscope remediate "{e(result.source)}" --out safe.csv --strategy hash</pre>
</body>
</html>"""


def write_report(result: ScanResult, out: Path) -> str:
    """Write a report file; the extension (.json, .md, .html) picks the format."""
    suffix = out.suffix.lower()
    if suffix == ".json":
        content = render_json(result)
    elif suffix in (".md", ".markdown", ".txt"):
        content = render_markdown(result)
    elif suffix in (".html", ".htm"):
        content = render_html(result)
    else:
        raise PiiscopeError(f"cannot write report to {out}; use a .json, .md or .html extension")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content + "\n", encoding="utf-8")
    return content
