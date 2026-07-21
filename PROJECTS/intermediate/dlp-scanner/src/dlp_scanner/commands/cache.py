"""
©AngelaMos | 2026
commands/cache.py
 
``dlp-scan cache`` sub-commands:
 
    dlp-scan cache stats   – show cache statistics
    dlp-scan cache clear   – wipe all cached entries
 
Both commands locate the cache database the same way FileScanner does:
next to any .dlp-scanner.yml / .dlp-scanner.yaml in the current directory,
falling back to .dlp-scanner-cache.db in the working directory.  The
``--db`` option lets callers override this for scripting.
 
The ``stats`` command opens the database **read-only** (no rule-set hash
needed) by passing the hash that is already stored in the database; the
cache's _maybe_invalidate guard is therefore a no-op, so no rows are ever
silently wiped just because the user ran `cache stats` without a config.
"""
from __future__ import annotations
 
from pathlib import Path
from typing import Annotated, Optional
 
import typer

cache_app = typer.Typer(
    name="cache",
    help="Inspect and manage the incremental scan cache.",
    no_args_is_help=True,
)

# ── helpers ───────────────────────────────────────────────────────────────────
 
def _resolve_db_path(override: Optional[str]) -> Path:
    """
    Return the cache DB path: explicit override → config-adjacent → cwd.
    """
    if override:
        return Path(override)
 
    from dlp_scanner.scanners.file_scanner import CACHE_DB_FILENAME
 
    for candidate in (
        Path(".dlp-scanner.yml"),
        Path(".dlp-scanner.yaml"),
    ):
        if candidate.exists():
            return candidate.parent / CACHE_DB_FILENAME
 
    return Path(CACHE_DB_FILENAME)

def _open_readonly(db_path: Path):
    """
    Open the cache without triggering auto-invalidation.
 
    Reads the stored rule_set_hash from the DB and constructs ScanCache
    with that same hash so _maybe_invalidate is always a no-op.
    Returns None if the database cannot be opened.
    """
    import sqlite3
    from dlp_scanner.cache import ScanCache, _SELECT_META  # noqa: PLC2701
 
    if not db_path.exists():
        return None
 
    try:
        conn = sqlite3.connect(str(db_path))
        row = conn.execute(_SELECT_META, ("rule_set_hash",)).fetchone()
        conn.close()
    except Exception:
        return None
 
    stored_hash = row[0] if row else ""
    return ScanCache(db_path=db_path, rule_set_hash=stored_hash)

def _fmt_bytes(n: int) -> str:
    """Human-readable byte size (IEC units)."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n} B" if unit == "B" else f"{n:.1f} {unit}"
        n //= 1024
    return f"{n:.1f} TB"
 
 
def _fmt_iso(ts: str) -> str:
    """Trim ISO-8601 timestamp to 'YYYY-MM-DD HH:MM:SS', or a dash."""
    return ts[:19].replace("T", " ") if ts else "—"


# ── commands ────────────────────────────────────────────────────────────────
@cache_app.command("stats")
def stats(
    db: Annotated[
        Optional[str],
        typer.Option(
            "--db", "-d",
            help=(
                "Path to the cache database file. "
                "Defaults to .dlp-scanner-cache.db next to your config, "
                "or in the current directory."
            ),
        ),
    ] = None,
    json_out: Annotated[
        bool,
        typer.Option("--json", "-j", help="Emit machine-readable JSON."),
    ] = False,
) -> None:
    """
    Display statistics about the incremental scan cache.
 
    Shows cached file count, total findings, clean vs flagged breakdown,
    oldest/newest scan timestamps, database size, and the active rule-set
    fingerprint.  Use --json for scripting.
    """
    db_path = _resolve_db_path(db)
 
    if not db_path.exists():
        if json_out:
            import json as _json
            typer.echo(
                _json.dumps({"error": "no_cache_found", "path": str(db_path)})
            )
        else:
            typer.echo(
                f"No cache found at {db_path}\n"
                "Run a file scan first to populate the cache.",
                err=True,
            )
        raise typer.Exit(code=1)
 
    cache = _open_readonly(db_path)
    if cache is None:
        typer.echo(f"Could not open cache at {db_path}", err=True)
        raise typer.Exit(code=1)
 
    try:
        d = cache.detailed_stats()
    finally:
        cache.close()
 
    if json_out:
        import json as _json
        d["db_path"] = str(db_path)
        typer.echo(_json.dumps(d, indent=2))
        return
 
    # ── Rich table output ────────────────────────────────────────────────────
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box
 
        console = Console()
        console.print()
 
        table = Table(
            title=f"[bold]DLP Scan Cache[/bold]  [dim]{db_path}[/dim]",
            box=box.ROUNDED,
            show_header=False,
            padding=(0, 2),
        )
        table.add_column("Field", style="dim", width=28)
        table.add_column("Value", style="bold")
 
        table.add_row("Database path", str(db_path))
        table.add_row("Database size", _fmt_bytes(int(d["db_size_bytes"])))
        table.add_row("", "")
        table.add_row("Cached files", str(d["total_files"]))
        table.add_row(
            "  with findings",
            f"[red]{d['files_with_findings']}[/red]"
            if d["files_with_findings"] else "0",
        )
        table.add_row("  clean", f"[green]{d['clean_files']}[/green]")
        table.add_row("Total cached findings", str(d["total_findings"]))
        table.add_row("", "")
        table.add_row("Oldest scan", _fmt_iso(str(d["oldest_scan"])))
        table.add_row("Newest scan", _fmt_iso(str(d["newest_scan"])))
        table.add_row("", "")
        table.add_row(
            "Rule-set fingerprint",
            f"[dim]{d['rule_set_hash_prefix']}[/dim]"
            if d["rule_set_hash_prefix"] else "[dim]not set[/dim]",
        )
 
        console.print(table)
        console.print()
 
    except ImportError:
        # Fallback: plain text when Rich is not installed.
        lines = [
            f"Cache path     : {db_path}",
            f"DB size        : {_fmt_bytes(int(d['db_size_bytes']))}",
            f"Cached files   : {d['total_files']}",
            f"  with findings: {d['files_with_findings']}",
            f"  clean        : {d['clean_files']}",
            f"Total findings : {d['total_findings']}",
            f"Oldest scan    : {_fmt_iso(str(d['oldest_scan']))}",
            f"Newest scan    : {_fmt_iso(str(d['newest_scan']))}",
            f"Rule-set fp    : {d['rule_set_hash_prefix'] or '(not set)'}",
        ]
        typer.echo("\n".join(lines))


@cache_app.command("clear")
def clear(
    db: Annotated[
        Optional[str],
        typer.Option(
            "--db", "-d",
            help=(
                "Path to the cache database file. "
                "Defaults to .dlp-scanner-cache.db next to your config, "
                "or in the current directory."
            ),
        ),
    ] = None,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes", "-y",
            help="Skip the confirmation prompt.",
            
        ),
    ] = False,
    delete_db: Annotated[
        bool,
        typer.Option(
            "--delete-db",
            help=(
                "Also delete the cache database file itself, "
                "not just its contents."
            ),
            
        ),
    ] = False,
) -> None:
    """
    Clear all entries from the incremental scan cache.
 
    By default this empties the cache table but keeps the database file so
    the next scan can write back to it immediately.  Pass --delete-db to
    remove the file entirely (including WAL sidecars).
 
    The next file scan after clearing will re-process every file.
    """
    db_path = _resolve_db_path(db)
 
    if not db_path.exists():
        typer.echo(
            f"No cache found at {db_path} — nothing to clear."
        )
        raise typer.Exit(code=0)
 
    # ── Confirmation prompt ──────────────────────────────────────────────────
    if not yes:
        action = (
            f"delete the database file {db_path}"
            if delete_db
            else f"clear all entries from {db_path}"
        )
        confirmed = typer.confirm(
            f"This will {action}. Continue?",
            default=False,
        )
        if not confirmed:
            typer.echo("Aborted.")
            raise typer.Exit(code=0)
 
    # ── Execute ──────────────────────────────────────────────────────────────
    if delete_db:
        try:
            db_path.unlink()
            # SQLite WAL mode leaves sidecar files; clean them up too.
            for suffix in ("-wal", "-shm"):
                sidecar = Path(str(db_path) + suffix)
                if sidecar.exists():
                    sidecar.unlink()
            typer.echo(f"Deleted cache database: {db_path}")
        except OSError as exc:
            typer.echo(f"Error deleting {db_path}: {exc}", err=True)
            raise typer.Exit(code=1) from exc
    else:
        cache = _open_readonly(db_path)
        if cache is None:
            typer.echo(f"Could not open cache at {db_path}", err=True)
            raise typer.Exit(code=1)
        try:
            before = cache.stats()["cached_files"]
            cache.invalidate_all()
            entry_word = "entry" if before == 1 else "entries"
            typer.echo(f"Cleared {before} {entry_word} from {db_path}")
        finally:
            cache.close()