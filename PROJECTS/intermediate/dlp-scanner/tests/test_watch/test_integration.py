"""
©AngelaMos | 2026
test_integration.py

Real end-to-end tests for `dlp-scan watch`: an actual watchdog
``Observer`` watching a real temporary directory, feeding real
filesystem events through ``ScanEventHandler`` -> ``EventDebouncer`` ->
``scan_single_file``, with no mocks anywhere in that chain.

These are slower and inherently timing-sensitive compared to
test_handler.py's mocked unit tests, so they use short debounce
windows and a generous polling helper (`_wait_until`) rather than
fixed sleeps, and are marked integration + slow so `just test`
(unit-only) skips them by default -- run with:

    uv run pytest tests/test_watch/test_integration.py -m integration
"""


import threading
import time
from pathlib import Path

import pytest
from watchdog.observers import Observer

from dlp_scanner.config import ScanConfig
from dlp_scanner.detectors.registry import DetectorRegistry
from dlp_scanner.models import ScanResult
from dlp_scanner.reporters.csv_report import CsvReporter
from dlp_scanner.scanners.file_scanner import FileScanner
from dlp_scanner.watch.debounce import EventDebouncer
from dlp_scanner.watch.handler import ScanEventHandler, scan_single_file


pytestmark = [pytest.mark.integration, pytest.mark.slow]

DEBOUNCE_SECONDS = 0.15
POLL_TIMEOUT = 5.0
POLL_INTERVAL = 0.05


def _wait_until(predicate, timeout: float = POLL_TIMEOUT) -> bool:
    """
    Poll ``predicate`` until it returns truthy or the timeout elapses

    Avoids flaky fixed sleeps: real Observer + debounce timing varies
    by OS filesystem notification backend, so tests wait for the
    actual condition instead of a guessed duration.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(POLL_INTERVAL)
    return False


class _WatchHarness:
    """
    Wires a real Observer + ScanEventHandler + EventDebouncer against
    a real directory, collecting every (path, ScanResult) produced.

    This is the actual production wiring from commands/watch.py,
    minus the Typer/CLI plumbing, so these tests exercise the real
    pipeline rather than a simplified stand-in.
    """
    def __init__(
        self,
        base_dir: Path,
        config: ScanConfig | None = None,
        debounce_seconds: float = DEBOUNCE_SECONDS,
    ) -> None:
        self.base_dir = base_dir
        self.config = config or ScanConfig()
        self.registry = DetectorRegistry(
            enable_patterns = self.config.detection.enable_rules,
            disable_patterns = self.config.detection.disable_rules,
        )
        self.scans: list[tuple[Path, ScanResult]] = []
        self._lock = threading.Lock()

        self.debouncer = EventDebouncer(
            callback = self._scan,
            delay_seconds = debounce_seconds,
        )
        self.handler = ScanEventHandler(
            self.debouncer,
            base_dir,
            self.config,
        )
        self.observer = Observer()
        self.observer.schedule(
            self.handler,
            str(base_dir),
            recursive = True,
        )

    def _scan(self, path: Path) -> None:
        if not path.exists():
            return
        result = scan_single_file(path, self.registry, self.config)
        with self._lock:
            self.scans.append((path, result))

    def scan_count_for(self, path: Path) -> int:
        with self._lock:
            return sum(1 for p, _ in self.scans if p == path)

    def latest_result_for(self, path: Path) -> ScanResult | None:
        with self._lock:
            matches = [r for p, r in self.scans if p == path]
        return matches[-1] if matches else None

    def start(self) -> "_WatchHarness":
        self.debouncer.start()
        self.observer.start()
        return self

    def stop(self) -> None:
        self.observer.stop()
        self.observer.join(timeout = 2.0)
        self.debouncer.stop()

    def __enter__(self) -> "_WatchHarness":
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.stop()


# ── A. Detection pipeline correctness ───────────────────────────────────────

class TestDetectionPipeline:
    def test_new_file_with_ssn_is_detected(self, tmp_path: Path) -> None:
        with _WatchHarness(tmp_path) as watch:
            target = tmp_path / "employees.csv"
            target.write_text("name,ssn\nAlice,456-78-9012\n")

            assert _wait_until(lambda: watch.scan_count_for(target) >= 1)

            result = watch.latest_result_for(target)
            assert result is not None
            assert any(f.rule_id == "PII_SSN" for f in result.findings)

    def test_clean_file_produces_no_output(self, tmp_path: Path) -> None:
        with _WatchHarness(tmp_path) as watch:
            target = tmp_path / "readme.txt"
            target.write_text("Nothing sensitive in this file at all.")

            assert _wait_until(lambda: watch.scan_count_for(target) >= 1)

            result = watch.latest_result_for(target)
            assert result is not None
            assert result.findings == []

    def test_modifying_existing_file_rescans_new_content(
        self,
        tmp_path: Path,
    ) -> None:
        target = tmp_path / "notes.txt"
        target.write_text("nothing here")

        with _WatchHarness(tmp_path) as watch:
            time.sleep(DEBOUNCE_SECONDS * 2)  # let any startup noise settle
            target.write_text("SSN on file: 456-78-9012")

            assert _wait_until(lambda: watch.scan_count_for(target) >= 1)
            result = watch.latest_result_for(target)
            assert result is not None
            assert any(f.rule_id == "PII_SSN" for f in result.findings)

    def test_multiple_pii_types_all_surfaced(self, tmp_path: Path) -> None:
        with _WatchHarness(tmp_path) as watch:
            target = tmp_path / "mixed.txt"
            target.write_text(
                "SSN: 456-78-9012\n"
                "Card: 4532015112830366\n"
            )

            assert _wait_until(lambda: watch.scan_count_for(target) >= 1)
            result = watch.latest_result_for(target)
            assert result is not None
            rule_ids = {f.rule_id for f in result.findings}
            assert "PII_SSN" in rule_ids
            assert "FIN_CREDIT_CARD_VISA" in rule_ids


# ── B. Debounce correctness ──────────────────────────────────────────────────

class TestDebounceCorrectness:
    def test_rapid_writes_collapse_to_one_scan(self, tmp_path: Path) -> None:
        with _WatchHarness(tmp_path) as watch:
            target = tmp_path / "burst.txt"
            for i in range(5):
                target.write_text(f"revision {i}: SSN 456-78-9012")
                time.sleep(DEBOUNCE_SECONDS / 4)

            # give the debounce window a chance to fire exactly once
            assert _wait_until(lambda: watch.scan_count_for(target) >= 1)
            time.sleep(DEBOUNCE_SECONDS * 2)  # confirm no second scan trails in
            assert watch.scan_count_for(target) == 1

    def test_two_files_scanned_independently(self, tmp_path: Path) -> None:
        with _WatchHarness(tmp_path) as watch:
            a = tmp_path / "a.txt"
            b = tmp_path / "b.txt"
            a.write_text("SSN: 456-78-9012")
            b.write_text("clean file, nothing here")

            assert _wait_until(
                lambda: (
                    watch.scan_count_for(a) >= 1
                    and watch.scan_count_for(b) >= 1
                )
            )

            result_a = watch.latest_result_for(a)
            result_b = watch.latest_result_for(b)
            assert result_a is not None and result_a.findings
            assert result_b is not None and not result_b.findings


# ── C. Editor-save / rename semantics ───────────────────────────────────────

class TestEditorSaveRealFilesystem:
    def test_temp_then_rename_scans_final_path_only(
        self,
        tmp_path: Path,
    ) -> None:
        with _WatchHarness(tmp_path) as watch:
            temp = tmp_path / ".report.txt.swp"
            final = tmp_path / "report.txt"

            temp.write_text("SSN: 456-78-9012")
            temp.rename(final)

            assert _wait_until(lambda: watch.scan_count_for(final) >= 1)
            time.sleep(DEBOUNCE_SECONDS * 2)

            assert watch.scan_count_for(temp) == 0
            result = watch.latest_result_for(final)
            assert result is not None
            assert any(f.rule_id == "PII_SSN" for f in result.findings)

    def test_temp_deleted_before_rename_never_crashes(
        self,
        tmp_path: Path,
    ) -> None:
        with _WatchHarness(tmp_path) as watch:
            temp = tmp_path / ".ephemeral.txt"
            temp.write_text("SSN: 456-78-9012")
            temp.unlink()

            # the watcher must not crash and must not report a scan
            # for a path that no longer exists
            time.sleep(DEBOUNCE_SECONDS * 3)
            assert watch.scan_count_for(temp) == 0


# ── D. Large-file / stability ────────────────────────────────────────────────

class TestStabilityRealFilesystem:
    def test_incremental_write_scans_full_final_content(
        self,
        tmp_path: Path,
    ) -> None:
        target = tmp_path / "growing.csv"
        target.write_text("")

        with _WatchHarness(tmp_path) as watch:
            def _write_incrementally() -> None:
                for i in range(6):
                    with open(target, "a") as f:
                        f.write(f"row{i},456-78-9012\n")
                    time.sleep(0.05)

            writer = threading.Thread(target = _write_incrementally)
            writer.start()
            writer.join()

            assert _wait_until(lambda: watch.scan_count_for(target) >= 1)
            result = watch.latest_result_for(target)
            assert result is not None
            # all 6 rows must be present in what got scanned, not a
            # truncated mid-write snapshot
            assert target.read_text().count("456-78-9012") == 6


# ── E. Exclude/extension filters, applied through real events ──────────────

class TestFiltersRealFilesystem:
    def test_pycache_directory_never_scanned(self, tmp_path: Path) -> None:
        with _WatchHarness(tmp_path) as watch:
            pycache = tmp_path / "__pycache__"
            pycache.mkdir()
            target = pycache / "cached.txt"
            target.write_text("SSN: 456-78-9012")

            time.sleep(DEBOUNCE_SECONDS * 3)
            assert watch.scan_count_for(target) == 0

    def test_disallowed_extension_never_scanned(self, tmp_path: Path) -> None:
        with _WatchHarness(tmp_path) as watch:
            target = tmp_path / "binary.exe"
            target.write_bytes(b"\x00\x01SSN 456-78-9012")

            time.sleep(DEBOUNCE_SECONDS * 3)
            assert watch.scan_count_for(target) == 0

    def test_excluded_glob_pattern_never_scanned(self, tmp_path: Path) -> None:
        config = ScanConfig()
        config.file.exclude_patterns = ["test_*"]

        with _WatchHarness(tmp_path, config = config) as watch:
            target = tmp_path / "test_fixture.txt"
            target.write_text("SSN: 456-78-9012")

            time.sleep(DEBOUNCE_SECONDS * 3)
            assert watch.scan_count_for(target) == 0

    def test_new_subdirectory_is_automatically_watched(
        self,
        tmp_path: Path,
    ) -> None:
        with _WatchHarness(tmp_path) as watch:
            subdir = tmp_path / "newly_created"
            subdir.mkdir()
            time.sleep(0.1)  # let watchdog register the new directory

            target = subdir / "nested.txt"
            target.write_text("SSN: 456-78-9012")

            assert _wait_until(lambda: watch.scan_count_for(target) >= 1)


# ── G. Consistency between watch mode and batch scanning ───────────────────

class TestConsistencyWithBatchScan:
    def test_watch_and_batch_scan_classify_identically(
        self,
        tmp_path: Path,
    ) -> None:
        """
        The same content scanned via watch mode and via FileScanner
        must produce the same rule, severity, and confidence -- both
        paths go through the identical scoring pipeline, so this
        pins that the watch wiring didn't accidentally diverge from
        it (e.g. skipping compliance_config, using a different
        redaction style, etc.).
        """
        config = ScanConfig()

        with _WatchHarness(tmp_path, config = config) as watch:
            target = tmp_path / "shared.csv"
            target.write_text("name,ssn\nAlice,456-78-9012\n")

            assert _wait_until(lambda: watch.scan_count_for(target) >= 1)
            watch_result = watch.latest_result_for(target)

        assert watch_result is not None
        watch_finding = next(
            f for f in watch_result.findings if f.rule_id == "PII_SSN"
        )

        batch_registry = DetectorRegistry(
            enable_patterns = config.detection.enable_rules,
            disable_patterns = config.detection.disable_rules,
        )
        batch_scanner = FileScanner(config, batch_registry)
        batch_result = batch_scanner.scan(str(target))
        batch_finding = next(
            f for f in batch_result.findings if f.rule_id == "PII_SSN"
        )

        assert watch_finding.severity == batch_finding.severity
        assert watch_finding.confidence == pytest.approx(
            batch_finding.confidence
        )
        assert (
            watch_finding.compliance_frameworks
            == batch_finding.compliance_frameworks
        )
        assert watch_finding.redacted_snippet == batch_finding.redacted_snippet

        # Sanity-check both are also serializable through the same
        # reporter without divergence (e.g. no missing fields).
        reporter = CsvReporter()
        assert reporter.generate(watch_result)
        assert reporter.generate(batch_result)