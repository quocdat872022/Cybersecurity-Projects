"""
©AngelaMos | 2026
test_handler.py

Each test class here maps directly to one "Gotcha" called out in
04-CHALLENGES.md's Challenge 8:

  TestScanEventHandlerRenameSemantics
      -> "Editor save operations often create temporary files, write
          to them, then rename... You need to scan the final file,
          not the intermediate temp files."

  TestWaitForStableSize
      -> "Large file copies trigger on_modified repeatedly as data is
          written. Debounce by waiting until the file size stabilizes."

  TestIsScannable
      -> "The watch mode should respect the same exclude patterns and
          extension filters as batch scanning."
"""


import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dlp_scanner.config import ScanConfig
from dlp_scanner.detectors.registry import DetectorRegistry
from dlp_scanner.watch.handler import (
    ScanEventHandler,
    is_scannable,
    scan_single_file,
    wait_for_stable_size,
)


pytestmark = pytest.mark.unit


@pytest.fixture
def config() -> ScanConfig:
    return ScanConfig()


@pytest.fixture
def registry() -> DetectorRegistry:
    return DetectorRegistry()


def _make_handler(
    tmp_path: Path,
    config: ScanConfig,
) -> tuple[ScanEventHandler, MagicMock]:
    debouncer = MagicMock()
    handler = ScanEventHandler(debouncer, tmp_path, config)
    return handler, debouncer


# ── Gotcha 3: exclude/extension filters must match batch scanning ──────────

class TestIsScannable:
    def test_allowed_extension_in_base_dir(
        self,
        tmp_path: Path,
        config: ScanConfig,
    ) -> None:
        f = tmp_path / "data.csv"
        f.write_text("hello")
        assert is_scannable(f, tmp_path, config) is True

    def test_disallowed_extension_rejected(
        self,
        tmp_path: Path,
        config: ScanConfig,
    ) -> None:
        f = tmp_path / "binary.exe"
        f.write_text("hello")
        assert is_scannable(f, tmp_path, config) is False

    def test_excluded_directory_rejected(
        self,
        tmp_path: Path,
        config: ScanConfig,
    ) -> None:
        pycache = tmp_path / "__pycache__"
        pycache.mkdir()
        f = pycache / "cached.txt"
        f.write_text("hello")
        assert is_scannable(f, tmp_path, config) is False

    def test_excluded_filename_pattern_rejected(
        self,
        tmp_path: Path,
        config: ScanConfig,
    ) -> None:
        config.file.exclude_patterns = ["test_*"]
        f = tmp_path / "test_fixture.txt"
        f.write_text("hello")
        assert is_scannable(f, tmp_path, config) is False

    def test_nonexistent_path_rejected(
        self,
        tmp_path: Path,
        config: ScanConfig,
    ) -> None:
        assert is_scannable(tmp_path / "gone.txt", tmp_path, config) is False

    def test_directory_rejected(
        self,
        tmp_path: Path,
        config: ScanConfig,
    ) -> None:
        d = tmp_path / "looks_like_a_file.txt"
        d.mkdir()
        assert is_scannable(d, tmp_path, config) is False

    def test_atomic_save_temp_extension_rejected(
        self,
        tmp_path: Path,
        config: ScanConfig,
    ) -> None:
        """
        A `.tmp` suffix from an atomic-save temp file must never pass
        the same include_extensions filter batch scanning uses.
        """
        temp = tmp_path / "report.csv.tmp"
        temp.write_text("in progress")
        assert is_scannable(temp, tmp_path, config) is False


# ── Gotcha 2: growing files must not be scanned mid-write ───────────────────

class TestWaitForStableSize:
    def test_returns_true_once_size_settles(
        self,
        tmp_path: Path,
    ) -> None:
        f = tmp_path / "growing.txt"
        f.write_text("x")

        def grow() -> None:
            time.sleep(0.1)
            f.write_text("x" * 100)

        threading.Thread(target = grow, daemon = True).start()

        started = time.monotonic()
        result = wait_for_stable_size(f, max_wait_seconds = 2.0)
        elapsed = time.monotonic() - started

        assert result is True
        # Must have actually waited through the growth event rather
        # than returning as soon as it saw the initial size.
        assert elapsed >= 0.1

    def test_gives_up_after_deadline_instead_of_stalling_forever(
        self,
        tmp_path: Path,
    ) -> None:
        """
        A file that never stops growing (e.g. an active log) must not
        block watch mode indefinitely -- past the deadline we scan
        best-effort with whatever is currently on disk.
        """
        f = tmp_path / "always_growing.log"
        f.write_text("x")
        stop = threading.Event()

        def keep_growing() -> None:
            n = 0
            while not stop.is_set():
                n += 1
                f.write_text("x" * n)
                time.sleep(0.05)

        t = threading.Thread(target = keep_growing, daemon = True)
        t.start()
        try:
            result = wait_for_stable_size(f, max_wait_seconds = 0.5)
            assert result is True
        finally:
            stop.set()
            t.join(timeout = 1)

    def test_missing_file_returns_false(
        self,
        tmp_path: Path,
    ) -> None:
        assert (
            wait_for_stable_size(tmp_path / "nope.txt", max_wait_seconds = 0.3)
            is False
        )


class TestScanSingleFile:
    def test_finds_ssn_in_plaintext_file(
        self,
        tmp_path: Path,
        registry: DetectorRegistry,
        config: ScanConfig,
    ) -> None:
        f = tmp_path / "employees.csv"
        f.write_text("name,ssn\nAlice,456-78-9012\n")

        result = scan_single_file(f, registry, config)

        assert result.targets_scanned == 1
        assert any(
            finding.rule_id == "PII_SSN" for finding in result.findings
        )

    def test_clean_file_has_no_findings(
        self,
        tmp_path: Path,
        registry: DetectorRegistry,
        config: ScanConfig,
    ) -> None:
        f = tmp_path / "clean.txt"
        f.write_text("nothing sensitive here")

        result = scan_single_file(f, registry, config)

        assert result.findings == []
        assert result.errors == []

    def test_unsupported_extension_returns_empty_result(
        self,
        tmp_path: Path,
        registry: DetectorRegistry,
        config: ScanConfig,
    ) -> None:
        f = tmp_path / "photo.png"
        f.write_bytes(b"\x89PNG\r\n")

        result = scan_single_file(f, registry, config)

        assert result.findings == []
        assert result.errors == []


# ── Gotcha 1: only the final renamed path should ever be scanned ───────────

class TestScanEventHandlerRenameSemantics:
    def test_on_moved_touches_destination_not_source(
        self,
        tmp_path: Path,
        config: ScanConfig,
    ) -> None:
        """
        Simulates the common editor pattern: write to a hidden temp
        file, then rename it over the real target. Only the rename
        *destination* should ever reach the debouncer.
        """
        handler, debouncer = _make_handler(tmp_path, config)

        final_path = tmp_path / "report.csv"
        final_path.write_text("data")

        event = MagicMock(is_directory = False)
        event.src_path = str(tmp_path / ".report.csv.tmp12345")
        event.dest_path = str(final_path)

        handler.on_moved(event)

        debouncer.touch.assert_called_once_with(final_path)

    def test_on_created_ignores_temp_extension(
        self,
        tmp_path: Path,
        config: ScanConfig,
    ) -> None:
        """
        The intermediate temp file created before a rename typically
        carries a non-scannable extension (.swp, .tmp, ~) and must
        never itself reach the debouncer via on_created.
        """
        handler, debouncer = _make_handler(tmp_path, config)

        temp_path = tmp_path / "draft.csv.swp"
        temp_path.write_text("wip")

        event = MagicMock(is_directory = False)
        event.src_path = str(temp_path)

        handler.on_created(event)

        debouncer.touch.assert_not_called()

    def test_on_modified_respects_exclude_patterns(
        self,
        tmp_path: Path,
        config: ScanConfig,
    ) -> None:
        config.file.exclude_patterns = ["*.log"]
        handler, debouncer = _make_handler(tmp_path, config)

        f = tmp_path / "app.log"
        f.write_text("noise")

        event = MagicMock(is_directory = False)
        event.src_path = str(f)

        handler.on_modified(event)

        debouncer.touch.assert_not_called()

    def test_directory_events_are_ignored(
        self,
        tmp_path: Path,
        config: ScanConfig,
    ) -> None:
        handler, debouncer = _make_handler(tmp_path, config)

        event = MagicMock(is_directory = True)
        event.src_path = str(tmp_path / "subdir")

        handler.on_created(event)
        handler.on_modified(event)

        debouncer.touch.assert_not_called()

    def test_scannable_created_file_reaches_debouncer(
        self,
        tmp_path: Path,
        config: ScanConfig,
    ) -> None:
        """
        Sanity check for the positive case: a normal, non-temp,
        non-excluded file must still make it to the debouncer.
        """
        handler, debouncer = _make_handler(tmp_path, config)

        f = tmp_path / "notes.txt"
        f.write_text("hello")

        event = MagicMock(is_directory = False)
        event.src_path = str(f)

        handler.on_created(event)

        debouncer.touch.assert_called_once_with(f)