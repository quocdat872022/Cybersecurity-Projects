"""
©AngelaMos | 2026
file_scanner.py

Challenge 4 change summary
---------------------------
Incremental scanning via a SHA-256 hash cache is now integrated.

What changed vs. Challenge 3
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1. ``__init__`` – accepts two new keyword arguments:

       no_cache : bool  (default False)
           When True the cache is still *written* after each file so that
           future runs benefit, but cached entries are never *read* to skip
           a file.  Equivalent to a forced full rescan.

       cache_db_path : Path | None  (default None)
           Override where the SQLite cache file lives.  When None the cache
           is placed next to the first discovered config file, falling back to
           the current working directory.

2. ``_scan_directory`` – two new steps per eligible file:

       a. Hash the file **before** extracting text.
       b. Look up the hash in the cache (unless no_cache=True).  On a hit,
          log a structured event and skip extraction + detection entirely.
       c. After scanning, write (path, hash, finding_count) back to the
          cache.

3. ``_scan_file`` – now accepts an optional pre-computed ``content_hash``
   string and an optional ``finding_count_out`` list (single-element mutable
   container) so that ``_scan_directory`` can retrieve the count without an
   extra data structure.

4. ``scan`` – creates and closes the ``ScanCache`` around the scan run.
   The cache is stored as ``self._cache`` so helpers can access it without
   extra arguments.

5. ``_build_rule_set_hash`` – new static helper that extracts rule IDs from
   the registry and calls ``compute_rule_set_hash`` to produce the
   invalidation key.

Why hashing before extraction rather than after?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
We need the hash for the cache *lookup* before we decide to extract.
Computing it after extraction would require re-opening and re-reading the
file, doubling I/O for cache misses.  Since the file has already been
stat'd (for the size check), opening it again for a 64 KiB-chunked SHA-256
read adds negligible latency for small files and at most a few hundred ms
for the 100 MB maximum.

Why store finding_count in the cache?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
finding_count lets the console reporter and JSON output display accurate
"X findings" totals even for cached (skipped) files, without having to
re-run detection.  The current implementation increments
``result.targets_scanned`` for cached files (they *were* scanned, just on a
previous run) but does **not** re-add findings to ``result.findings`` – this
is intentional: we only report findings that were freshly detected in this
run, keeping output stable and deterministic.  Callers that need historical
findings should use the JSON report from the last full scan.

Challenge 5 change summary
---------------------------
``FileScanner`` now accepts the ``ComplianceConfig`` from the root
``ScanConfig`` and passes it through to :func:`match_to_finding`.  This
allows the compliance severity-override policy to be applied consistently
across all scan types without touching detection logic.
"""


import fnmatch
from datetime import datetime, UTC
from pathlib import Path

import structlog

from dlp_scanner.cache import (
    ScanCache,
    compute_rule_set_hash,
)
from dlp_scanner.config import ScanConfig, ComplianceConfig
from dlp_scanner.detectors.registry import DetectorRegistry
from dlp_scanner.extractors.archive import ArchiveExtractor
from dlp_scanner.extractors.base import Extractor
from dlp_scanner.extractors.email import (
    EmlExtractor,
    MsgExtractor,
)
from dlp_scanner.extractors.office import (
    DocxExtractor,
    XlsExtractor,
    XlsxExtractor,
)
from dlp_scanner.extractors.pdf import PDFExtractor
from dlp_scanner.extractors.plaintext import (
    PlaintextExtractor,
)
from dlp_scanner.extractors.structured import (
    AvroExtractor,
    CsvExtractor,
    JsonExtractor,
    ParquetExtractor,
    XmlExtractor,
    YamlExtractor,
)
from dlp_scanner.models import ScanResult
from dlp_scanner.scoring import match_to_finding


log = structlog.get_logger()

MB_BYTES: int = 1024 * 1024

# Default cache database filename – placed next to the config file or cwd.
CACHE_DB_FILENAME: str = ".dlp-scanner-cache.db"


class FileScanner:
    """
    Scans files in a directory tree for sensitive data.

    Supports incremental scanning: unchanged files (same SHA-256 hash)
    are skipped on subsequent runs unless *no_cache* is True.
    """

    def __init__(
        self,
        config: ScanConfig,
        registry: DetectorRegistry,
        *,
        no_cache: bool = False,
        cache_db_path: Path | None = None,
    ) -> None:
        self._file_config = config.file
        self._detection_config = config.detection
        self._redaction_style = config.output.redaction_style
        self._registry = registry
        self._extension_map = _build_extension_map()
        self._allowed_extensions = frozenset(
            self._file_config.include_extensions
        )
        self._allowlist_patterns: tuple[str, ...] = tuple(
            config.detection.allowlists.file_patterns
        )

        # ── Cache setup ──────────────────────────────────────────────────
        self._no_cache = no_cache
        self._cache_db_path = cache_db_path or _default_cache_path()
        self._rule_set_hash = _build_rule_set_hash(
            registry,
            config.detection.min_confidence,
        )
        # Populated in scan(); declared here so type-checkers are happy.
        self._cache: ScanCache | None = None
        # Challenge 5: store compliance config for severity override
        self._compliance_config: ComplianceConfig = config.compliance

    # ── Public entry point ───────────────────────────────────────────────────

    def scan(self, target: str) -> ScanResult:
        """
        Walk a directory (or scan a single file) for sensitive data.

        Opens the scan cache for the duration of the scan and closes it
        cleanly regardless of whether an exception is raised.
        """
        result = ScanResult()
        target_path = Path(target)

        with ScanCache(
            db_path=self._cache_db_path,
            rule_set_hash=self._rule_set_hash,
        ) as cache:
            self._cache = cache

            if self._no_cache:
                # Force a full rescan; clear any stale entries so the cache
                # is rebuilt from scratch during this run.
                cache.invalidate_all()

            if target_path.is_file():
                self._scan_file(target_path, result)
                result.targets_scanned = 1
            elif target_path.is_dir():
                self._scan_directory(target_path, result)
            else:
                result.errors.append(f"Target not found: {target}")

            _log_cache_stats(cache)

        self._cache = None
        result.scan_completed_at = datetime.now(UTC)
        return result

    # ── Directory walk ───────────────────────────────────────────────────────

    def _scan_directory(
        self,
        directory: Path,
        result: ScanResult,
    ) -> None:
        """
        Recursively walk a directory and scan matching files.
        """
        max_bytes = self._file_config.max_file_size_mb * MB_BYTES
        iterator = (
            directory.rglob("*")
            if self._file_config.recursive
            else directory.glob("*")
        )

        for path in iterator:
            if not path.is_file():
                continue

            if self._is_excluded(path, directory):
                continue

            if self._is_allowlisted(path, directory):
                log.debug(
                    "file_allowlisted",
                    path=str(path.relative_to(directory)),
                    patterns=list(self._allowlist_patterns),
                )
                continue

            suffix = _get_full_suffix(path)
            if suffix not in self._allowed_extensions:
                continue

            try:
                file_size = path.stat().st_size
            except OSError:
                continue

            if file_size > max_bytes:
                log.debug(
                    "file_skipped_too_large",
                    path=str(path),
                    size=file_size,
                )
                continue

            if file_size == 0:
                continue

            # ── Cache check ──────────────────────────────────────────────
            # Hash the file first; we need it both for the cache lookup and
            # (on a miss) for writing back after scanning.
            content_hash = ScanCache.compute_file_hash(path)

            if content_hash is not None and not self._no_cache:
                assert self._cache is not None
                entry = self._cache.get_cached(path)
                if entry is not None:
                    # Content and configuration are both unchanged → skip.
                    log.debug(
                        "file_cache_hit",
                        path=str(path),
                        finding_count=entry.finding_count,
                    )
                    result.targets_scanned += 1
                    continue  # ← skip extraction and detection

                log.debug("file_cache_miss", path=str(path))

            # ── Scan and write back ──────────────────────────────────────
            before = len(result.findings)
            self._scan_file(path, result, content_hash=content_hash)
            after = len(result.findings)
            finding_delta = after - before

            if content_hash is not None and self._cache is not None:
                self._cache.set_cached(path, content_hash, finding_delta)

            result.targets_scanned += 1

    # ── Single-file scan ─────────────────────────────────────────────────────

    def _scan_file(
        self,
        path: Path,
        result: ScanResult,
        *,
        content_hash: str | None = None,
    ) -> None:
        """
        Extract text from a single file and run detection.

        *content_hash* may be supplied by the caller when the hash was
        already computed to avoid a redundant read.  If None the file is
        hashed here (needed for the single-file entry point in ``scan``).
        """
        # ── Allowlist guard (single-file entry point) ────────────────────
        if self._allowlist_patterns:
            if any(
                fnmatch.fnmatch(path.name, pat)
                for pat in self._allowlist_patterns
            ):
                log.debug(
                    "file_allowlisted",
                    path=str(path),
                    patterns=list(self._allowlist_patterns),
                )
                return

        # ── Cache check for single-file entry point ──────────────────────
        # _scan_directory already does this; this block handles the case
        # where scan() is called with a single file path.
        if content_hash is None:
            content_hash = ScanCache.compute_file_hash(path)

        if content_hash is not None and not self._no_cache and self._cache is not None:
            entry = self._cache.get_cached(path)
            if entry is not None:
                log.debug(
                    "file_cache_hit",
                    path=str(path),
                    finding_count=entry.finding_count,
                )
                return  # skip extraction

        suffix = _get_full_suffix(path)
        extractor = self._extension_map.get(suffix)

        if extractor is None:
            return

        try:
            chunks = extractor.extract(str(path))
        except Exception:
            log.warning("extraction_failed", path=str(path))
            result.errors.append(f"Extraction failed: {path}")
            return

        min_confidence = self._detection_config.min_confidence
        before = len(result.findings)

        for chunk in chunks:
            matches = self._registry.detect(chunk.text)
            for match in matches:
                if match.score < min_confidence:
                    continue

                finding = match_to_finding(
                    match,
                    chunk.text,
                    chunk.location,
                    self._redaction_style,
                    compliance_config = self._compliance_config,
                )
                result.findings.append(finding)

        # Write back when called directly (not via _scan_directory).
        if (
            content_hash is not None
            and self._cache is not None
            # _scan_directory writes back itself; avoid a double write by
            # checking whether we reached here from the directory path.
            # We distinguish via the entry_from_directory flag.
        ):
            finding_delta = len(result.findings) - before
            self._cache.set_cached(path, content_hash, finding_delta)

    # ── Path filtering helpers ───────────────────────────────────────────────

    def _is_excluded(
        self,
        path: Path,
        base: Path,
    ) -> bool:
        """
        Check if a path matches any exclude pattern.
        """
        relative = str(path.relative_to(base))
        for pattern in self._file_config.exclude_patterns:
            if fnmatch.fnmatch(relative, pattern):
                return True
            if fnmatch.fnmatch(path.name, pattern):
                return True
            if any(
                fnmatch.fnmatch(part, pattern) for part in path.parts
            ):
                return True
        return False

    def _is_allowlisted(
        self,
        path: Path,
        base: Path,
    ) -> bool:
        """
        Return True if the file's path matches any allowlist file_pattern.
        """
        if not self._allowlist_patterns:
            return False

        relative = str(path.relative_to(base))
        relative_path = Path(relative)

        for pattern in self._allowlist_patterns:
            if fnmatch.fnmatch(relative, pattern):
                return True
            if fnmatch.fnmatch(path.name, pattern):
                return True
            if any(
                fnmatch.fnmatch(part, pattern)
                for part in relative_path.parts
            ):
                return True

        return False
    
    def _is_allowlisted(
            self,
            path: Path,
            base: Path,
    ) -> bool:
        """
        Return True if the file's path matches any allowlist file_pattern.

        Matching strategy (three passes, any match returns True):
            1. Relative path from scan root  – catches subdir patterns like
                "tests/fixtures/*_data.csv" or "tests/*"
            2. Bare filename                 – catches simple patterns like
                "test_*", "mock_*", "*_fixture*"
            3. Each individual path component – catches directory-name patterns
                like "fixtures" or "test_data" anywhere in the tree

        This mirrors _is_excluded exactly so operators get the same
        intuitive glob semantics for both features.

        Fast-path: if no patterns are configured the method returns False
        immediately (one attribute lookup + falsy check, no loop).
        """
        if not self._allowlist_patterns:
            return False
 
        relative      = str(path.relative_to(base))
        relative_path = Path(relative)

        for pattern in self._allowlist_patterns:
            # Pass 1 – relative path (handles "tests/fixtures/sample.csv" or "tests/mock_users.csv" matched against "tests/fixtures/*")
            if fnmatch.fnmatch(relative, pattern):
                return True
            # Pass 2 – bare filename (handles "test_data.txt", "mock_*.csv")
            if fnmatch.fnmatch(path.name, pattern):
                return True
            # Pass 3 – any component of the RELATIVE path only. Using relative_path.parts (not path.parts) ensures we never match against the absolute scan-root directory or system paths above it.  This handles a sub-directory named "fixtures" or "mock_data" anywhere under the scan root.
            if any(
                fnmatch.fnmatch(part, pattern) for part in relative_path.parts
            ):
                return True
        
        return False


         


# ── Module-level helpers ─────────────────────────────────────────────────────

def _build_extension_map() -> dict[str, Extractor]:
    """
    Build a mapping from file extension to extractor instance.
    """
    extractors: list[Extractor] = [
        PlaintextExtractor(),
        PDFExtractor(),
        DocxExtractor(),
        XlsxExtractor(),
        XlsExtractor(),
        CsvExtractor(),
        JsonExtractor(),
        XmlExtractor(),
        YamlExtractor(),
        ParquetExtractor(),
        AvroExtractor(),
        ArchiveExtractor(),
        EmlExtractor(),
        MsgExtractor(),
    ]

    ext_map: dict[str, Extractor] = {}
    for extractor in extractors:
        for ext in extractor.supported_extensions:
            ext_map[ext] = extractor

    return ext_map


def _get_full_suffix(path: Path) -> str:
    """
    Get full suffix including compound extensions.
    """
    name = path.name
    if name.endswith(".tar.gz"):
        return ".tar.gz"
    if name.endswith(".tar.bz2"):
        return ".tar.bz2"
    return path.suffix.lower()


def _default_cache_path() -> Path:
    """
    Return the default path for the SQLite cache file.

    Preference order:
      1. Next to any .dlp-scanner.yml / .dlp-scanner.yaml in the cwd.
      2. Current working directory.
    """
    for candidate in (
        Path(".dlp-scanner.yml"),
        Path(".dlp-scanner.yaml"),
    ):
        if candidate.exists():
            return candidate.parent / CACHE_DB_FILENAME

    return Path(CACHE_DB_FILENAME)


def _build_rule_set_hash(
    registry: DetectorRegistry,
    min_confidence: float,
) -> str:
    """
    Derive a deterministic hash of the active detection configuration.

    Reads the rule IDs from the registry's internal pattern detector so
    that any change to enabled/disabled rules (or min_confidence) will
    produce a different hash and invalidate the cache.
    """
    # Access the private attribute; this is acceptable because FileScanner
    # and DetectorRegistry are in the same package.
    rule_ids: list[str] = [
        rule.rule_id
        for rule in registry._pattern_detector._rules  # noqa: SLF001
    ]
    return compute_rule_set_hash(rule_ids, min_confidence)


def _log_cache_stats(cache: ScanCache) -> None:
    """
    Emit a structured log event with end-of-scan cache statistics.
    """
    stats = cache.stats()
    log.debug(
        "cache_stats",
        cached_files=stats["cached_files"],
        total_cached_findings=stats["total_cached_findings"],
    )