"""
©AngelaMos | 2026
commands/watch.py

``dlp-scan watch <directory>`` — real-time DLP scanning.

Monitors a directory tree for file creation/modification/move events
using watchdog, debounces bursts of events per file (a single editor
save often fires several events within milliseconds), waits for the
file's size to stabilize (large writes/copies keep touching a file
while data is still landing), then scans just that one file and
streams any findings to the console immediately.

This mirrors how endpoint DLP agents work: react to changes as they
happen instead of waiting for the next scheduled batch scan. It
respects the same ``file.include_extensions`` / ``file.exclude_patterns``
config used by ``dlp-scan file``, so a directory's watch behaviour and
batch-scan behaviour never disagree about what counts as scannable.
"""


from pathlib import Path
from typing import Annotated

import structlog
import typer

from dlp_scanner.config import ScanConfig, load_config
from dlp_scanner.detectors.registry import DetectorRegistry
from dlp_scanner.log import configure_logging
from dlp_scanner.models import ScanResult
from dlp_scanner.watch.debounce import EventDebouncer
from dlp_scanner.watch.handler import (
    ScanEventHandler,
    scan_single_file,
    wait_for_stable_size,
)


log = structlog.get_logger()


def _build_registry(config: ScanConfig) -> DetectorRegistry:
    """
    Build a DetectorRegistry the same way ScanEngine does, so watch
    mode and batch scanning apply identical detection rules.
    """
    detection = config.detection
    allowlist_vals = detection.allowlists.values
    return DetectorRegistry(
        enable_patterns = detection.enable_rules,
        disable_patterns = detection.disable_rules,
        allowlist_values = (
            frozenset(allowlist_vals) if allowlist_vals else None
        ),
        context_window_tokens = detection.context_window_tokens,
        custom_rules_dir = detection.custom_rules_dir or None,
    )


def _print_result(path: Path, result: ScanResult) -> None:
    """
    Stream findings for a single file scan to the console as they
    happen, rather than waiting to batch everything at the end.
    """
    if result.errors:
        for err in result.errors:
            typer.echo(f"[error] {err}")
        return

    if not result.findings:
        return

    typer.echo(f"\n[{path}] {len(result.findings)} finding(s):")
    for finding in result.findings:
        loc = finding.location.uri
        if finding.location.line is not None:
            loc += f":{finding.location.line}"

        typer.echo(
            f"  [{finding.severity.upper()}] "
            f"{finding.rule_name} | "
            f"{loc} | "
            f"{finding.confidence:.0%} | "
            f"{finding.redacted_snippet}"
        )


def watch(
    ctx: typer.Context,
    target: Annotated[
        str,
        typer.Argument(help = "Directory to monitor"),
    ],
    debounce_seconds: Annotated[
        float,
        typer.Option(
            "--debounce",
            help = (
                "Seconds of inactivity on a file before it is scanned"
            ),
        ),
    ] = 0.5,
    initial_scan: Annotated[
        bool,
        typer.Option(
            "--initial-scan/--no-initial-scan",
            help = (
                "Run a full batch scan of the directory before watching"
            ),
        ),
    ] = True,
) -> None:
    """
    Watch a directory and scan files as they are created or changed.
    """
    from watchdog.observers import Observer

    target_path = Path(target)
    if not target_path.is_dir():
        typer.echo(f"Not a directory: {target}", err = True)
        raise typer.Exit(code = 1)

    obj: dict[str, object] = ctx.ensure_object(dict)
    config_path = str(obj.get("config_path", "") or "")
    verbose = bool(obj.get("verbose", False))

    configure_logging(level = "DEBUG" if verbose else "INFO")

    config = load_config(Path(config_path) if config_path else None)
    registry = _build_registry(config)

    if initial_scan:
        typer.echo(f"Running initial scan of {target_path}...")

        from dlp_scanner.engine import ScanEngine

        engine = ScanEngine(config)
        result = engine.scan_files(str(target_path))
        engine.display_console(result)
        typer.echo("")

    def _on_file_ready(path: Path) -> None:
        if not path.exists():
            return
        if not wait_for_stable_size(path):
            return
        if not path.exists():
            return

        result = scan_single_file(path, registry, config)
        _print_result(path, result)

    debouncer = EventDebouncer(
        callback = _on_file_ready,
        delay_seconds = debounce_seconds,
    )
    event_handler = ScanEventHandler(debouncer, target_path, config)

    observer = Observer()
    observer.schedule(
        event_handler,
        str(target_path),
        recursive = config.file.recursive,
    )

    typer.echo(f"Watching {target_path} for changes (Ctrl+C to stop)...")
    debouncer.start()
    observer.start()

    try:
        while observer.is_alive():
            observer.join(timeout = 1.0)
    except KeyboardInterrupt:
        typer.echo("\nStopping watch mode...")
    finally:
        observer.stop()
        observer.join(timeout = 2.0)
        debouncer.flush()
        debouncer.stop()


def register(app: typer.Typer) -> None:
    """
    Register the watch command on the root app
    """
    app.command("watch")(watch)