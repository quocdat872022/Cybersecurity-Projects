"""
©AngelaMos | 2026
console.py

Challenge 10: findings demoted by the false-positive classifier are
shown in a separate "Suppressed" section instead of the main list.
"""


from rich.console import Console
from rich.table import Table

from dlp_scanner.constants import SEVERITY_COLORS
from dlp_scanner.models import Finding, ScanResult


TRUNCATE_SNIPPET: int = 60


def _location(finding: Finding, sep: str) -> str:
    loc = finding.location.uri
    if finding.location.line is not None:
        loc += f":{finding.location.line}"
    if finding.location.table_name:
        loc += f"{sep}[{finding.location.table_name}]"
    return loc


def _snippet(finding: Finding) -> str:
    snippet = finding.redacted_snippet
    if len(snippet) > TRUNCATE_SNIPPET:
        snippet = snippet[: TRUNCATE_SNIPPET] + "..."
    return snippet


class ConsoleReporter:
    """
    Rich console output with severity-colored tables
    """
    def __init__(
        self,
        console: Console | None = None,
    ) -> None:
        self._console = console or Console()

    def generate(self, result: ScanResult) -> str:
        """
        Generate plain-text table for piping
        """
        active = result.active_findings
        suppressed = result.suppressed_findings

        lines: list[str] = [
            f"Scan {result.scan_id} | "
            f"{len(active)} findings | "
            f"{len(suppressed)} suppressed | "
            f"{result.targets_scanned} targets",
            "",
        ]

        for finding in active:
            lines.append(
                f"[{finding.severity.upper()}] "
                f"{finding.rule_name} | "
                f"{_location(finding, ' ')} | "
                f"{finding.confidence:.0%} | "
                f"{_snippet(finding)} | "
                f"{', '.join(finding.compliance_frameworks)}"
            )

        if suppressed:
            lines.append("")
            lines.append(
                "Suppressed (likely false positives, demoted by classifier):"
            )
            for finding in suppressed:
                was = (finding.original_severity or finding.severity).upper()
                lines.append(
                    f"[SUPPRESSED p(fp)={finding.fp_probability or 0:.2f} "
                    f"was {was}] "
                    f"{finding.rule_name} | "
                    f"{_location(finding, ' ')} | "
                    f"{finding.confidence:.0%} | "
                    f"{_snippet(finding)}"
                )

        lines.append("")
        lines.append(_format_summary(result))
        return "\n".join(lines)

    def display(self, result: ScanResult) -> None:
        """
        Print Rich-formatted table to console
        """
        self._console.print()

        if not result.findings:
            self._console.print("[green]No findings detected.[/green]")
            _print_summary(self._console, result)
            return

        active = result.active_findings
        if active:
            table = Table(
                title = f"DLP Scan Results ({len(active)} findings)",
                show_lines = True,
            )
            table.add_column("Severity", width = 10, justify = "center")
            table.add_column("Rule", width = 25)
            table.add_column("Location", width = 30)
            table.add_column("Confidence", width = 10)
            table.add_column("Snippet", width = 40)
            table.add_column("Compliance", width = 20)

            for finding in active:
                color = SEVERITY_COLORS.get(finding.severity, "white")
                table.add_row(
                    f"[{color}]{finding.severity.upper()}[/{color}]",
                    finding.rule_name,
                    _location(finding, "\n"),
                    f"{finding.confidence:.0%}",
                    _snippet(finding),
                    "\n".join(finding.compliance_frameworks),
                )
            self._console.print(table)
        else:
            self._console.print("[green]No active findings.[/green]")

        _print_summary(self._console, result)

        suppressed = result.suppressed_findings
        if suppressed:
            self._console.print()
            stable = Table(
                title = (
                    f"Suppressed: likely false positives "
                    f"({len(suppressed)}), audit before dismissing"
                ),
                show_lines = True,
                style = "dim",
            )
            stable.add_column("Was", width = 10, justify = "center")
            stable.add_column("P(FP)", width = 7)
            stable.add_column("Rule", width = 25)
            stable.add_column("Location", width = 30)
            stable.add_column("Confidence", width = 10)
            stable.add_column("Snippet", width = 40)
            for finding in suppressed:
                stable.add_row(
                    (finding.original_severity or finding.severity).upper(),
                    f"{finding.fp_probability or 0:.2f}",
                    finding.rule_name,
                    _location(finding, "\n"),
                    f"{finding.confidence:.0%}",
                    _snippet(finding),
                )
            self._console.print(stable)

        if result.errors:
            self._console.print()
            self._console.print(
                f"[yellow]{len(result.errors)} "
                f"error(s) during scan[/yellow]"
            )


def _severity_parts(result: ScanResult, rich: bool) -> list[str]:
    by_sev = result.findings_by_severity
    parts: list[str] = []
    for sev in ("critical", "high", "medium", "low"):
        count = by_sev.get(sev, 0)
        if count > 0:
            if rich:
                color = SEVERITY_COLORS.get(sev, "white")
                parts.append(f"[{color}]{sev}: {count}[/{color}]")
            else:
                parts.append(f"{sev}: {count}")
    n_supp = len(result.suppressed_findings)
    if n_supp:
        parts.append(f"suppressed: {n_supp}")
    return parts


def _format_summary(result: ScanResult) -> str:
    """
    Format summary statistics as plain text
    """
    parts = _severity_parts(result, rich = False)
    summary = " | ".join(parts) if parts else "clean"
    return (
        f"Summary: {summary} "
        f"({result.targets_scanned} targets scanned)"
    )


def _print_summary(console: Console, result: ScanResult) -> None:
    """
    Print formatted summary using Rich
    """
    console.print()
    parts = _severity_parts(result, rich = True)
    summary = " | ".join(parts) if parts else "[green]clean[/green]"
    console.print(
        f"Summary: {summary} "
        f"({result.targets_scanned} targets)"
    )