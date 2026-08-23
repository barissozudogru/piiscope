"""Command line interface for piiscope."""

from __future__ import annotations

import csv
import io as _io
import json
import os
import traceback
from collections.abc import Sequence
from enum import Enum
from pathlib import Path

import pandas as pd
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

try:  # typer >= 0.20 vendors click as typer._click
    from typer._click.exceptions import UsageError
except ImportError:  # typer < 0.20 depends on the real click package
    from click.exceptions import UsageError

from piiscope import __version__
from piiscope.detection.jurisdictions import JURISDICTION_PROFILES
from piiscope.detection.regex_patterns import PATTERNS
from piiscope.errors import PiiscopeError
from piiscope.remediation.strategies import remediate
from piiscope.report import render_markdown, write_report
from piiscope.scan import ScanResult, scan

app = typer.Typer(
    name="piiscope",
    help="Find, score and remediate personal data in your files and databases.",
    add_completion=False,
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_SEVERITY_STYLES = (
    (0.8, "red"),
    (0.5, "yellow"),
    (0.0, "cyan"),
)

_LEVEL_STYLES = {
    "low": "green",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
}


class OutputFormat(str, Enum):
    table = "table"
    json = "json"
    markdown = "markdown"
    csv = "csv"


class FailLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Strategy(str, Enum):
    hash = "hash"
    redact = "redact"
    null = "null"
    generalise = "generalise"
    tokenise = "tokenise"
    date_shift = "date-shift"


class JurisdictionOpt(str, Enum):
    gdpr = "gdpr"
    ccpa = "ccpa"
    kvkk = "kvkk"
    lgpd = "lgpd"
    all = "all"


_debug = False


def _split_csv(value: str | None) -> list[str] | None:
    if value is None:
        return None
    parts = [p.strip() for p in value.split(",") if p.strip()]
    return parts or None


def _severity_style(severity: float) -> str:
    for threshold, style in _SEVERITY_STYLES:
        if severity >= threshold:
            return style
    return "cyan"  # pragma: no cover - unreachable, list ends at 0.0


def _format_path(path: str | Path) -> str:
    if str(path) == "dataframe":
        return "dataframe"
    p = Path(path).absolute()
    try:
        p = p.relative_to(Path.cwd())
    except ValueError:
        pass
    s = str(p)
    if " " in s:
        return f'"{s}"'
    return s


def _render_header(result: ScanResult) -> Panel:
    info = Table.grid(padding=(0, 2))
    info.add_column(justify="right", style="dim")
    info.add_column()
    info.add_row("Source", result.source)
    info.add_row("Rows", str(result.rows))
    info.add_row("Columns", str(result.columns))
    if result.files > 1:
        info.add_row("Files", str(result.files))
    info.add_row("Scan time", f"{result.scan_time:.2f}s")
    info.add_row("Jurisdictions", ", ".join(result.jurisdictions))
    return Panel(info, title="piiscope scan", title_align="left")


def _render_findings_table(result: ScanResult) -> Table:
    has_files = any(f.file for f in result.findings)
    table = Table(title="Findings", header_style="bold", title_justify="left")
    if has_files:
        table.add_column("File", style="dim", max_width=28, no_wrap=True)
    table.add_column("Column", style="bold")
    table.add_column("Category")
    table.add_column("Detector")
    table.add_column("Hits", justify="right")
    table.add_column("Confidence", justify="right")
    table.add_column("Jurisdictions", style="dim")
    if not result.findings:
        table.add_row(*(["-"] * (7 if has_files else 6)))
        return table
    for f in result.findings:
        style = _severity_style(f.severity)
        from typing import Any

        row: list[Any] = [
            f.file or "",
            Text(f.column, style=style),
            Text(f.category, style=style),
            Text(f.detector, style=style),
            Text(str(f.count), style=style),
            Text(f"{f.confidence:.2f}", style=style),
            Text(", ".join(f.jurisdictions), style=style),
        ]
        if not has_files:
            row = row[1:]
        table.add_row(*row)
    return table


def _render_metrics_panel(result: ScanResult) -> Panel:
    if result.metrics is None:
        body = Text("Not computed (no quasi identifiers found or metrics disabled)", style="dim")
        return Panel(body, title="Privacy metrics", title_align="left")
    m = result.metrics
    qi = ", ".join(m.quasi_identifiers) if m.quasi_identifiers else "none detected"
    lines = Table.grid(padding=(0, 2))
    lines.add_column(justify="right", style="dim")
    lines.add_column()
    lines.add_row("Quasi identifiers", qi)
    if m.sensitive_attribute:
        lines.add_row("Sensitive attribute", m.sensitive_attribute)
    lines.add_row("k-anonymity", "-" if m.k_anonymity is None else str(m.k_anonymity))
    lines.add_row("l-diversity", "-" if m.l_diversity is None else str(m.l_diversity))
    lines.add_row("t-closeness", "-" if m.t_closeness is None else f"{m.t_closeness:.3f}")
    return Panel(lines, title="Privacy metrics", title_align="left")


def _render_risk_panel(result: ScanResult) -> Panel:
    risk = result.risk
    lines = Table.grid(padding=(0, 2))
    lines.add_column(justify="right", style="dim")
    lines.add_column()
    lines.add_row("Score", Text(f"{risk.score}/100", style=_LEVEL_STYLES[risk.level]))
    lines.add_row("Level", Text(risk.level.upper(), style=_LEVEL_STYLES[risk.level]))
    for i, driver in enumerate(risk.drivers[:3], 1):
        lines.add_row(f"Driver {i}", driver)
    return Panel(lines, title="Risk", title_align="left")


def _suggested_output(source: str) -> str:
    """Suggest an output file name next to the source that does not shadow it."""
    if source == "dataframe":
        return "safe.csv"
    src = Path(source)
    if src.is_dir():
        return "safe/"
    suffix = src.suffix or ".csv"
    stem = src.stem
    if stem.endswith("_safe") or stem == "safe":
        stem = f"{stem}_2"
    else:
        stem = f"{stem}_safe"
    return _format_path(src.with_name(stem + suffix))


def _print_table(console: Console, result: ScanResult) -> None:
    console.print(_render_header(result))
    if result.findings:
        console.print(_render_findings_table(result))
    else:
        console.print("[green]No personal data detected.[/green]")
        console.print()
    console.print(_render_metrics_panel(result))
    console.print(_render_risk_panel(result))
    if result.findings:
        first = _format_path(result.source)
        out = _suggested_output(result.source)
        console.print(
            f"Next: [bold]piiscope remediate {first} --out {out} --strategy hash[/bold]"
        )
    else:
        console.print("Nothing to remediate.")
    console.print()


def _findings_csv(result: ScanResult) -> str:
    buffer = _io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "source",
            "file",
            "column",
            "category",
            "detector",
            "count",
            "confidence",
            "severity",
            "jurisdictions",
            "risk_score",
            "risk_level",
        ]
    )
    for f in result.findings:
        writer.writerow(
            [
                result.source,
                f.file or "",
                f.column,
                f.category,
                f.detector,
                f.count,
                f.confidence,
                f.severity,
                " ".join(f.jurisdictions),
                result.risk.score,
                result.risk.level,
            ]
        )
    return buffer.getvalue().rstrip("\n")


def _emit(
    console: Console,
    results: Sequence[ScanResult],
    fmt: OutputFormat,
    output: Path | None,
) -> None:
    """Write scan output to stdout or a file according to the format."""
    if fmt == OutputFormat.json:
        payload = (
            results[0].to_json()
            if len(results) == 1
            else "[\n" + ",\n".join(r.to_json() for r in results) + "\n]"
        )
        text = payload
    elif fmt == OutputFormat.markdown:
        text = "\n\n---\n\n".join(render_markdown(r) for r in results)
    elif fmt == OutputFormat.csv:
        text = "\n".join(_findings_csv(r) for r in results)
    else:
        text = None

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        if text is None:
            file_console = Console(file=output.open("w", encoding="utf-8"), width=120)
            for r in results:
                _print_table(file_console, r)
            file_console.file.close()
        else:
            output.write_text(text + "\n", encoding="utf-8")
        return

    if text is not None:
        # plain print: rich would wrap long lines and corrupt the payload
        typer.echo(text)
    else:
        for r in results:
            _print_table(console, r)


def _jurisdiction_values(jurisdictions: Sequence[JurisdictionOpt]) -> list[str]:
    return [j.value for j in jurisdictions]


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"piiscope {__version__}")
        raise typer.Exit()


@app.callback()
def callback(
    version: bool | None = typer.Option(
        None,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
    debug: bool = typer.Option(False, "--debug", help="Show tracebacks on errors."),
) -> None:
    """Find, score and remediate personal data in your files and databases."""
    global _debug
    _debug = debug


@app.command(name="scan", epilog="Example: piiscope scan data.csv -f json")
def scan_cmd(
    paths: list[Path] = typer.Argument(..., help="Files or directories to scan."),
    format: OutputFormat = typer.Option(
        OutputFormat.table, "--format", "-f", help="Output format."
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write output to this file."),
    jurisdiction: list[JurisdictionOpt] = typer.Option(
        ["gdpr", "ccpa", "kvkk", "lgpd"],
        "--jurisdiction",
        "-j",
        help="Jurisdiction to assess against; repeatable.",
    ),
    quasi_identifiers: str | None = typer.Option(
        None, "--quasi-identifiers", "-q", help="Comma separated quasi identifier columns."
    ),
    sample: int | None = typer.Option(
        None, "--sample", "-s", min=1, help="Scan only the first N rows."
    ),
    fail_on: FailLevel | None = typer.Option(
        None, "--fail-on", help="Exit with code 2 when the risk level is at or above this level."
    ),
    show_all: bool = typer.Option(
        False, "--show-all", help="Disable dominance rule and show all findings."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Print per-file details for directory scans."
    ),
    no_metrics: bool = typer.Option(False, "--no-metrics", help="Skip privacy metric computation."),
    quiet: bool = typer.Option(False, "--quiet", help="Print nothing; exit code only."),
    dictionary: list[str] = typer.Option(
        None,
        "--dictionary",
        help="Custom dictionaries in KEY=FILE format (e.g. given_name=names.txt); repeatable.",
    ),
) -> None:
    """Scan files or directories for personal data."""
    console = Console(quiet=quiet)
    jurisdictions = _jurisdiction_values(jurisdiction)
    qi = _split_csv(quasi_identifiers)

    from piiscope.io.readers import walk_directory

    for p in paths:
        if p.is_dir():
            files = walk_directory(p)
            file_results = [
                scan(
                    f,
                    jurisdictions=jurisdictions,
                    quasi_identifiers=qi,
                    sample_rows=sample,
                    include_metrics=not no_metrics,
                    min_coverage=0.0 if show_all else 0.15,
                )
                for f in files
            ]
            if format == OutputFormat.json:
                max_score = max((r.risk.score for r in file_results), default=0)
                level = "low"
                if max_score >= 75:
                    level = "critical"
                elif max_score >= 50:
                    level = "high"
                elif max_score >= 25:
                    level = "medium"

                payload = {
                    "files": [r.to_dict() for r in file_results],
                    "risk": {"score": max_score, "level": level, "drivers": []},
                }
                out_text = json.dumps(payload, indent=2)
                if output:
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text(out_text + "\n", encoding="utf-8")
                else:
                    typer.echo(out_text)
            elif format == OutputFormat.table:
                table = Table(
                    title=f"Directory scan: {p}", header_style="bold", title_justify="left"
                )
                table.add_column("File")
                table.add_column("Rows", justify="right")
                table.add_column("Findings", justify="right")
                table.add_column("Risk")
                for r in file_results:
                    num_findings = sum(f.count for f in r.findings)
                    table.add_row(
                        Path(r.source).name,
                        str(r.rows),
                        str(num_findings),
                        Text(r.risk.level.upper(), style=_LEVEL_STYLES[r.risk.level]),
                    )
                console.print(table)
                if verbose:
                    for r in file_results:
                        _print_table(console, r)
            else:
                _emit(console, file_results, format, output)

            if fail_on is not None:
                threshold = RANK[fail_on.value]
                worst = max((RANK[r.risk.level] for r in file_results), default=0)
                if worst >= threshold:
                    raise typer.Exit(code=2)
        else:
            res = scan(
                p,
                jurisdictions=jurisdictions,
                quasi_identifiers=qi,
                sample_rows=sample,
                include_metrics=not no_metrics,
                min_coverage=0.0 if show_all else 0.15,
            )
            _emit(console, [res], format, output)
            if fail_on is not None and RANK[res.risk.level] >= RANK[fail_on.value]:
                raise typer.Exit(code=2)


@app.command(
    name="remediate", epilog="Example: piiscope remediate data.csv --out safe.csv --strategy hash"
)
def remediate_cmd(
    path: Path = typer.Argument(..., help="File to remediate."),
    out: Path = typer.Option(..., "--out", help="Remediated output file."),
    strategy: Strategy = typer.Option(
        Strategy.hash, "--strategy", help="Remediation strategy to apply."
    ),
    columns: str | None = typer.Option(
        None, "--columns", "-c", help="Comma separated columns; default: all columns with findings."
    ),
    salt: str | None = typer.Option(
        None, "--salt", help="Salt for tokenise: an environment variable name or a literal value."
    ),
    bucket_size: int = typer.Option(10, "--bucket-size", min=1, help="Bucket size for generalise."),
    shift_days: int = typer.Option(30, "--shift-days", help="Day shift for date-shift."),
    quiet: bool = typer.Option(False, "--quiet", help="Print nothing; exit code only."),
) -> None:
    """Remediate a file by transforming the columns that hold findings."""
    console = Console(quiet=quiet, stderr=True)
    resolved_salt = os.environ.get(salt, salt) if salt else None
    selected = _split_csv(columns)
    result = remediate(
        path,
        out,
        strategy=strategy.value,
        columns=selected,
        salt=resolved_salt,
        bucket_size=bucket_size,
        shift_days=shift_days,
    )
    if quiet:
        return
    console.print(
        f"Remediated [bold]{result.source}[/bold] -> [bold]{result.out}[/bold] "
        f"(strategy: {result.strategy}, rows: {result.rows})"
    )
    if result.salt:
        console.print(f"Tokenisation salt: [bold]{result.salt}[/bold]")
    if result.columns_changed:
        table = Table(header_style="bold", title_justify="left")
        table.add_column("Column", style="bold")
        table.add_column("Values changed", justify="right")
        for column, count in result.columns_changed.items():
            table.add_row(column, str(count))
        console.print(table)
    else:
        console.print("No columns with findings; output written unchanged.")
    console.print(f"Verify with: [bold]piiscope scan {_format_path(out)}[/bold]")


@app.command(name="report", epilog="Example: piiscope report data.csv --out scan.html")
def report_cmd(
    path: Path = typer.Argument(..., help="File or directory to report on."),
    out: Path = typer.Option(..., "--out", help="Report file: .html, .md or .json."),
    jurisdiction: list[JurisdictionOpt] = typer.Option(
        ["gdpr", "ccpa", "kvkk", "lgpd"],
        "--jurisdiction",
        "-j",
        help="Jurisdiction to assess against; repeatable.",
    ),
    quasi_identifiers: str | None = typer.Option(
        None, "--quasi-identifiers", "-q", help="Comma separated quasi identifier columns."
    ),
    sample: int | None = typer.Option(
        None, "--sample", "-s", min=1, help="Scan only the first N rows."
    ),
    quiet: bool = typer.Option(False, "--quiet", help="Print nothing; exit code only."),
) -> None:
    """Write a full report file for a scan."""
    result = scan(
        path,
        jurisdictions=_jurisdiction_values(jurisdiction),
        quasi_identifiers=_split_csv(quasi_identifiers),
        sample_rows=sample,
    )
    write_report(result, out)
    if not quiet:
        console = Console(quiet=quiet)
        console.print(f"Report written to [bold]{out}[/bold]")


@app.command(name="patterns", epilog="Example: piiscope patterns -j gdpr")
def patterns_cmd(
    jurisdiction: JurisdictionOpt | None = typer.Option(
        None, "--jurisdiction", "-j", help="Only show detectors covered by this jurisdiction."
    ),
) -> None:
    """List every built-in detector with its category and description."""
    console = Console()
    profile = None
    if jurisdiction is not None:
        name = jurisdiction.value.upper()
        if name == "ALL":
            entries = sorted({k for p in JURISDICTION_PROFILES.values() for k in p})
            profile = {k: None for k in entries}
        else:
            profile = JURISDICTION_PROFILES.get(name)
            if profile is None:
                console.print(f"error: unknown jurisdiction {name.lower()}")
                raise typer.Exit(code=1)
    table = Table(header_style="bold", title_justify="left")
    table.add_column("Detector", style="bold")
    table.add_column("Category")
    table.add_column("Description")
    if jurisdiction is not None:
        table.add_column("Article")
    for rule_id, pattern in sorted(PATTERNS.items()):
        if profile is not None and rule_id not in profile:
            continue
        from typing import Any

        row: list[Any] = [rule_id, pattern.pii_category, pattern.description]
        if jurisdiction is not None:
            meta: dict[str, str] = profile.get(rule_id) or {} if profile else {}
            row.append(meta.get("article", "-"))
        table.add_row(*row)
    console.print(table)


@app.command(name="doctor")
def doctor_cmd() -> None:
    """Check optional dependencies and report what is enabled."""
    from importlib.util import find_spec

    console = Console()
    table = Table(header_style="bold", title_justify="left")
    table.add_column("Component")
    table.add_column("Status")
    table.add_column("Detail")

    table.add_row("pandas", "enabled", f"v{pd.__version__}")
    table.add_row("typer", "enabled", f"v{typer.__version__}")
    table.add_row("rich", "enabled", f"v{_rich_version()}")

    if find_spec("pyarrow") is not None:
        import pyarrow

        table.add_row("pyarrow (parquet)", "enabled", f"v{pyarrow.__version__}")
    else:
        table.add_row("pyarrow (parquet)", "disabled", "pip install piiscope[parquet]")

    if find_spec("spacy") is None:
        table.add_row("spacy (nlp)", "disabled", "pip install piiscope[nlp]")
    else:
        import spacy

        detail = f"v{spacy.__version__}"
        if spacy.util.is_package("en_core_web_sm"):
            detail += ", en_core_web_sm installed"
        else:
            detail += ", en_core_web_sm missing (python -m spacy download en_core_web_sm)"
        table.add_row("spacy (nlp)", "enabled", detail)
    console.print(table)


def _rich_version() -> str:
    from importlib.metadata import version

    return version("rich")


def main() -> None:
    """Console entry point with clean error handling."""
    try:
        code = app(standalone_mode=False)
    except typer.Exit as exc:
        raise SystemExit(exc.exit_code) from None
    except UsageError as exc:
        message = exc.format_message() if exc.message else str(exc)
        typer.echo(f"error: {message}", err=True)
        raise SystemExit(1) from None
    except typer.Abort:
        typer.echo("aborted", err=True)
        raise SystemExit(130) from None
    except PiiscopeError as exc:
        if _debug:
            traceback.print_exc()
        else:
            typer.echo(f"error: {exc}", err=True)
        raise SystemExit(1) from None
    except OSError as exc:
        if _debug:
            traceback.print_exc()
        else:
            typer.echo(f"error: {exc}", err=True)
        raise SystemExit(1) from None
    # in non-standalone mode typer.Exit is returned, not raised
    if isinstance(code, int):
        raise SystemExit(code)


if __name__ == "__main__":
    main()
