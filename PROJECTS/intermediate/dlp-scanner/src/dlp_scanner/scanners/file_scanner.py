"""
©AngelaMos | 2026
file_scanner.py

Challenge 3 change summary
---------------------------
The only behavioural change in this file is that AllowlistConfig.file_patterns
is now enforced at scan time.  Everything else is identical to the original.
 
What was added:
  1. __init__: reads self._allowlist_patterns from
     config.detection.allowlists.file_patterns  (was silently ignored before)
  2. _scan_directory: calls self._is_allowlisted(path, directory) and skips
     the file — logging a structured debug event — when it matches
  3. _scan_file: same guard, covers the single-file scan path so that
     `dlp-scan file test_data.txt` is also suppressed when the filename
     matches a pattern
  4. _is_allowlisted: new private method; mirrors _is_excluded exactly so
     the matching semantics are identical (relative path, bare filename,
     and each path component all checked against every pattern)
 
Why here and not in _scan_file only?
  _scan_directory is the hot path for directory scans; short-circuiting
  before calling _scan_file avoids the stat() + extractor lookup overhead
  on every allowlisted file.  _scan_file still has the guard for the
  single-file entrypoint.
 
Why not reuse _is_excluded?
  Exclusion and allowlisting are semantically different:
    • exclude_patterns live in FileScanConfig (scan scope — what to look at)
    • file_patterns live in AllowlistConfig   (noise suppression — what to trust)
  Keeping them separate lets operators configure one without affecting the
  other, and makes the log events unambiguous (file_allowlisted vs
  file_excluded).
"""


import fnmatch
from datetime import datetime, UTC
from pathlib import Path

import structlog

from dlp_scanner.config import ScanConfig
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


class FileScanner:
    """
    Scans files in a directory tree for sensitive data
    """
    def __init__(
        self,
        config: ScanConfig,
        registry: DetectorRegistry,
    ) -> None:
        self._file_config = config.file
        self._detection_config = config.detection
        self._redaction_style = config.output.redaction_style
        self._registry = registry
        self._extension_map = _build_extension_map()
        self._allowed_extensions = frozenset(
            self._file_config.include_extensions
        )
        # Wire up the allowlist file_patterns that already exist in config but were never read.  Store as a tuple for fast iteration; an empty tuple means "no path-level allowlisting" (zero overhead on the hot path when the field is not configured).
        self._allowlist_patterns: tuple[str, ...] = tuple(config.detection.allowlists.file_patterns)

    def scan(self, target: str) -> ScanResult:
        """
        Walk a directory and scan all matching files
        """
        result = ScanResult()
        target_path = Path(target)

        if target_path.is_file():
            self._scan_file(target_path, result)
            result.targets_scanned = 1
        elif target_path.is_dir():
            self._scan_directory(target_path, result)
        else:
            result.errors.append(f"Target not found: {target}")

        result.scan_completed_at = datetime.now(UTC)
        return result

    def _scan_directory(
        self,
        directory: Path,
        result: ScanResult,
    ) -> None:
        """
        Recursively walk a directory and scan matching files
        """
        max_bytes = (self._file_config.max_file_size_mb * MB_BYTES)
        iterator = (
            directory.rglob("*")
            if self._file_config.recursive else directory.glob("*")
        )

        for path in iterator:
            if not path.is_file():
                continue

            if self._is_excluded(path, directory):
                continue

            # Skip files whose relative path matches an allowlist pattern. This check happens after the exclude check so that exclusions (which are about scan scope) take priority over allowlists (which are about noise suppression)
            if self._is_allowlisted(path, directory):
                log.debug(
                    "file_allowlisted",
                    path    = str(path.relative_to(directory)),
                    patterns= list(self._allowlist_patterns),
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
                    path = str(path),
                    size = file_size,
                )
                continue

            if file_size == 0:
                continue

            self._scan_file(path, result)
            result.targets_scanned += 1

    def _scan_file(
        self,
        path: Path,
        result: ScanResult,
    ) -> None:
        """
        Extract text from a single file and run detection
        """
        # Guard the single-file entry point too.  When the user runs:
        #   dlp-scan file test_data.txt
        # …the path is passed straight here without going through
        # _scan_directory, so we need the allowlist check in both places.
        # For single-file scans we match against the file's own name because
        # there is no meaningful "base directory" to compute a relative path
        # from; patterns like "test_*" are always filename patterns anyway.
        if self._allowlist_patterns:
            if any(
                fnmatch.fnmatch(path.name, pat) for pat in self._allowlist_patterns
            ):
                log.debug(
                    "file_allowlisted",
                    path    = str(path),
                    patterns= list(self._allowlist_patterns),
                )
                return

        suffix = _get_full_suffix(path)
        extractor = self._extension_map.get(suffix)

        if extractor is None:
            return

        try:
            chunks = extractor.extract(str(path))
        except Exception:
            log.warning("extraction_failed", path = str(path))
            result.errors.append(f"Extraction failed: {path}")
            return

        min_confidence = (self._detection_config.min_confidence)

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
                )
                result.findings.append(finding)

    def _is_excluded(
        self,
        path: Path,
        base: Path,
    ) -> bool:
        """
        Check if a path matches any exclude pattern
        """
        relative = str(path.relative_to(base))
        for pattern in self._file_config.exclude_patterns:
            if fnmatch.fnmatch(relative, pattern):
                return True
            if fnmatch.fnmatch(path.name, pattern):
                return True
            if any(fnmatch.fnmatch(part, pattern) for part in path.parts):
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


         


def _build_extension_map() -> dict[str, Extractor]:
    """
    Build a mapping from file extension to extractor instance
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
    Get full suffix including compound extensions
    """
    name = path.name
    if name.endswith(".tar.gz"):
        return ".tar.gz"
    if name.endswith(".tar.bz2"):
        return ".tar.bz2"
    return path.suffix.lower()
