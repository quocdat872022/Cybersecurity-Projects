"""
©AngelaMos | 2026
handler.py

Watchdog event handler and single-file scan helper for
``dlp-scan watch``.

Watch mode deliberately does *not* reuse ``FileScanner._scan_file``'s
hash-cache path: the whole point of watch mode is "this file just
changed, scan it now", so there is nothing to skip. Instead this
module extracts and detects a single file directly, sharing the
extension map, detector registry, and scoring pipeline with batch
scanning so results are identical in shape (same Finding objects,
same severity/compliance/redaction logic).
"""


import fnmatch
import time
from datetime import datetime, UTC
from pathlib import Path

import structlog
from watchdog.events import FileSystemEvent, FileSystemEventHandler

from dlp_scanner.config import ScanConfig
from dlp_scanner.detectors.registry import DetectorRegistry
from dlp_scanner.models import ScanResult
from dlp_scanner.scanners.file_scanner import (
    _build_extension_map,
    _get_full_suffix,
)
from dlp_scanner.scoring import match_to_finding
from dlp_scanner.watch.debounce import EventDebouncer


log = structlog.get_logger()

# How many consecutive stable-size polls before we trust the file
# has finished being written.
STABILITY_CHECK_COUNT: int = 3
STABILITY_POLL_SECONDS: float = 0.15
# Large copies can legitimately take a while; past this we give up
# waiting and scan whatever is currently on disk rather than stalling
# watch mode indefinitely on one file.
STABILITY_MAX_WAIT_SECONDS: float = 3.0

# Built once; extractors are stateless so sharing this across every
# scan_single_file call avoids rebuilding the map per event.
_EXTENSION_MAP = _build_extension_map()


def wait_for_stable_size(
    path: Path,
    max_wait_seconds: float = STABILITY_MAX_WAIT_SECONDS,
) -> bool:
    """
    Poll a file's size until it stops changing, or give up waiting

    Large file copies and slow writes keep triggering filesystem
    "modified" events while data is still landing on disk; scanning
    mid-write risks truncated or garbled text. Returns True once the
    size has held steady for ``STABILITY_CHECK_COUNT`` consecutive
    polls. If the deadline passes without the size settling, returns
    True anyway so watch mode makes forward progress instead of
    stalling forever on a file that is still growing (e.g. an
    actively-written log file) -- the caller scans best-effort.
    Returns False only if the file disappears while we are waiting.
    """
    deadline = time.monotonic() + max_wait_seconds
    last_size: int | None = None
    stable_count = 0

    while time.monotonic() < deadline:
        try:
            size = path.stat().st_size
        except OSError:
            return False

        if size == last_size:
            stable_count += 1
            if stable_count >= STABILITY_CHECK_COUNT:
                return True
        else:
            stable_count = 0
            last_size = size

        time.sleep(STABILITY_POLL_SECONDS)

    return True


def is_scannable(
    path: Path,
    base_dir: Path,
    config: ScanConfig,
) -> bool:
    """
    Apply the same extension and exclude-pattern filters batch
    scanning uses, so watch mode never scans a file the config says
    to ignore.

    Editor temp-file gotcha: most editors write to a temp name with
    a *different* extension (``.swp``, ``.tmp``, no extension at
    all) before renaming over the real file, so that temp file is
    naturally filtered out here and never scanned. A temp name that
    happens to preserve the target extension (e.g. an atomic-write
    tool using ``file.tmp.txt``) will still pass this filter and can
    get a create/modify event of its own -- that is an accepted,
    rare edge case rather than something worth adding temp-file
    heuristics for. The important correctness guarantee lives in
    ``ScanEventHandler.on_moved`` (only the *destination* of a rename
    is ever touched, never the source) plus the ``path.exists()``
    re-checks around the debounced callback in ``commands/watch.py``:
    if a transient temp file is deleted or renamed away before its
    debounce window elapses, the scan is skipped rather than erroring
    or reporting findings against a path that no longer represents
    the file the user cares about.
    """
    if not path.is_file():
        return False

    suffix = _get_full_suffix(path)
    if suffix not in frozenset(config.file.include_extensions):
        return False

    try:
        relative = str(path.relative_to(base_dir))
    except ValueError:
        relative = path.name
    relative_parts = Path(relative).parts

    for pattern in config.file.exclude_patterns:
        if fnmatch.fnmatch(relative, pattern):
            return False
        if fnmatch.fnmatch(path.name, pattern):
            return False
        if any(fnmatch.fnmatch(part, pattern) for part in relative_parts):
            return False

    return True


def scan_single_file(
    path: Path,
    registry: DetectorRegistry,
    config: ScanConfig,
) -> ScanResult:
    """
    Extract and detect a single file, independent of directory
    walking or the incremental hash cache.
    """
    result = ScanResult(targets_scanned = 1)
    suffix = _get_full_suffix(path)
    extractor = _EXTENSION_MAP.get(suffix)

    if extractor is None:
        result.scan_completed_at = datetime.now(UTC)
        return result

    try:
        chunks = extractor.extract(str(path))
    except Exception:
        log.warning("watch_extraction_failed", path = str(path))
        result.errors.append(f"Extraction failed: {path}")
        result.scan_completed_at = datetime.now(UTC)
        return result

    min_confidence = config.detection.min_confidence

    for chunk in chunks:
        matches = registry.detect(chunk.text)
        for match in matches:
            if match.score < min_confidence:
                continue

            finding = match_to_finding(
                match,
                chunk.text,
                chunk.location,
                config.output.redaction_style,
                compliance_config = config.compliance,
            )
            result.findings.append(finding)

    result.scan_completed_at = datetime.now(UTC)
    return result


class ScanEventHandler(FileSystemEventHandler):
    """
    Routes watchdog filesystem events to a debouncer, filtered by
    the same extension/exclude rules batch scanning uses.

    Handles the "editor save = create + modify + rename" pattern by
    treating created, modified, and moved-to paths identically: any
    of them resets that file's debounce timer. Moved-from (the old
    temp file name in a rename) is ignored since nothing should be
    scanned at a path that no longer exists.
    """
    def __init__(
        self,
        debouncer: EventDebouncer,
        base_dir: Path,
        config: ScanConfig,
    ) -> None:
        self._debouncer = debouncer
        self._base_dir = base_dir
        self._config = config

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._maybe_touch(Path(str(event.src_path)))

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._maybe_touch(Path(str(event.src_path)))

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._maybe_touch(Path(str(event.dest_path)))

    def _maybe_touch(self, path: Path) -> None:
        if is_scannable(path, self._base_dir, self._config):
            self._debouncer.touch(path)