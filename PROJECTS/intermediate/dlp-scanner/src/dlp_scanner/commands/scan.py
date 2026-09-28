"""
©AngelaMos | 2026
scan.py

Challenge 4 change: the ``file`` sub-command gains a ``--no-cache`` /
``-N`` flag that forces a full rescan while still writing results back to
the cache for future runs.

Challenge 9 change: every scan sub-command gains a ``--siem`` flag that,
when passed, forwards the completed scan result to whichever SIEM
transport is configured under ``output.siem`` in the config file
(syslog or Splunk HEC -- see reporters/syslog_reporter.py and
reporters/splunk_hec_reporter.py). Forwarding happens in addition to,
not instead of, the normal console/file/stdout report.
"""


from pathlib import Path
from typing import Annotated, Any

import typer


FORMAT_HELP: str = "Output format (console, json, sarif, csv, html)"
OUTPUT_HELP: str = "Write report to file"
NO_CACHE_HELP: str = (
    "Bypass the hash cache and force a full rescan. "
    "Results are still cached for future incremental runs."
)
SIEM_HELP: str = (
    "Forward this scan's findings to the SIEM configured under "
    "output.siem in your config file (syslog or Splunk HEC)."
)

VALID_FORMATS: frozenset[str] = frozenset(
    {
        "console",
        "json",
        "sarif",
        "csv",
        "html",
    }
)


def scan_file(
    ctx: typer.Context,
    target: Annotated[
        str,
        typer.Argument(help="File or directory path"),
    ],
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help=FORMAT_HELP,
        ),
    ] = "console",
    output_file: Annotated[
        str,
        typer.Option(
            "--output",
            "-o",
            help=OUTPUT_HELP,
        ),
    ] = "",
    no_cache: Annotated[
        bool,
        typer.Option(
            "--no-cache",
            "-N",
            help=NO_CACHE_HELP,
            is_flag=True,
        ),
    ] = False,
    siem: Annotated[
        bool,
        typer.Option(
            "--siem",
            help=SIEM_HELP,
            is_flag=True,
        ),
    ] = False,
) -> None:
    """
    Scan files and directories for sensitive data.

    On repeated scans only files whose SHA-256 hash has changed since the
    last run are re-processed.  Use --no-cache to force a full rescan.
    """
    _run_scan(
        ctx,
        "file",
        target,
        output_format,
        output_file,
        no_cache=no_cache,
        siem=siem,
    )


def scan_db(
    ctx: typer.Context,
    target: Annotated[
        str,
        typer.Argument(help="Database connection URI"),
    ],
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help=FORMAT_HELP,
        ),
    ] = "console",
    output_file: Annotated[
        str,
        typer.Option(
            "--output",
            "-o",
            help=OUTPUT_HELP,
        ),
    ] = "",
    siem: Annotated[
        bool,
        typer.Option(
            "--siem",
            help=SIEM_HELP,
            is_flag=True,
        ),
    ] = False,
) -> None:
    """
    Scan database tables for sensitive data.
    """
    _run_scan(ctx, "db", target, output_format, output_file, siem=siem)


def scan_network(
    ctx: typer.Context,
    target: Annotated[
        str,
        typer.Argument(help="PCAP file path"),
    ],
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help=FORMAT_HELP,
        ),
    ] = "console",
    output_file: Annotated[
        str,
        typer.Option(
            "--output",
            "-o",
            help=OUTPUT_HELP,
        ),
    ] = "",
    siem: Annotated[
        bool,
        typer.Option(
            "--siem",
            help=SIEM_HELP,
            is_flag=True,
        ),
    ] = False,
) -> None:
    """
    Scan network capture files for sensitive data in transit.
    """
    _run_scan(
        ctx, "network", target, output_format, output_file, siem=siem
    )


def register(app: typer.Typer) -> None:
    """
    Register scan commands on the root app.
    """
    app.command("file")(scan_file)
    app.command("db")(scan_db)
    app.command("network")(scan_network)


def _run_scan(
    ctx: typer.Context,
    scan_type: str,
    target: str,
    output_format: str,
    output_file: str,
    *,
    no_cache: bool = False,
    siem: bool = False,
) -> None:
    """
    Shared scan execution logic.
    """
    from dlp_scanner.config import (
        ScanConfig,
        load_config,
    )
    from dlp_scanner.engine import ScanEngine
    from dlp_scanner.log import configure_logging

    if output_format not in VALID_FORMATS:
        typer.echo(
            f"Invalid format: {output_format}. "
            f"Choose from: "
            f"{', '.join(sorted(VALID_FORMATS))}",
            err=True,
        )
        raise typer.Exit(code=1)

    obj: dict[str, Any] = ctx.ensure_object(dict)
    config_path: str = obj.get("config_path", "")
    verbose: bool = obj.get("verbose", False)

    if verbose:
        configure_logging(level="DEBUG")
    elif output_format == "console":
        configure_logging(level="INFO")
    else:
        configure_logging(level="WARNING")

    config: ScanConfig
    cfg_path = Path(config_path) if config_path else None
    config = load_config(cfg_path)

    config.output.format = output_format
    if output_file:
        config.output.output_file = output_file

    if siem and not config.output.siem.type:
        typer.echo(
            "--siem was passed but no SIEM is configured. "
            "Set output.siem.type to 'syslog' or 'splunk_hec' "
            "in your config file.",
            err=True,
        )
        raise typer.Exit(code=1)

    engine = ScanEngine(config)

    if scan_type == "file":
        result = engine.scan_files(target)
    elif scan_type == "db":
        result = engine.scan_database(target)
    else:
        result = engine.scan_network(target)

    if siem:
        try:
            sent = engine.send_to_siem(result)
            typer.echo(
                f"Forwarded {sent} message(s) to "
                f"{config.output.siem.type} SIEM"
            )
        except Exception as exc:
            typer.echo(f"SIEM forwarding failed: {exc}", err=True)

    if output_file:
        engine.write_report(result, output_file)
        typer.echo(f"Report written to {output_file}")
    elif output_format == "console":
        engine.display_console(result)
    else:
        output = engine.generate_report(result)
        typer.echo(output)

    if result.errors:
        raise typer.Exit(code=1)