"""
©AngelaMos | 2026
engine.py

Challenge 4 change: ``scan_files`` now accepts a ``no_cache`` keyword
argument that is forwarded to ``FileScanner``.  All other behaviour is
unchanged.
"""


import structlog

from dlp_scanner.config import ScanConfig
from dlp_scanner.constants import OutputFormat
from dlp_scanner.detectors.registry import (
    DetectorRegistry,
)
from dlp_scanner.models import ScanResult
from dlp_scanner.reporters.console import (
    ConsoleReporter,
)
from dlp_scanner.reporters.csv_report import (
    CsvReporter,
)
from dlp_scanner.reporters.json_report import (
    JsonReporter,
)
from dlp_scanner.reporters.sarif import SarifReporter
from dlp_scanner.reporters.html_report import HtmlReporter

from dlp_scanner.scanners.db_scanner import (
    DatabaseScanner,
)
from dlp_scanner.scanners.file_scanner import (
    FileScanner,
)
from dlp_scanner.scanners.network_scanner import (
    NetworkScanner,
)


log = structlog.get_logger()

REPORTER_MAP: dict[str, type] = {
    "console": ConsoleReporter,
    "json": JsonReporter,
    "sarif": SarifReporter,
    "csv": CsvReporter,
    "html": HtmlReporter,
}


class ScanEngine:
    """
    Orchestrates the full scan pipeline.

    The :attr:`~dlp_scanner.config.ComplianceConfig.severity_overrides`
    mapping read from the config is forwarded to every scanner so that
    the severity floor is applied uniformly across file, database, and
    network scans.
    """

    def __init__(self, config: ScanConfig) -> None:
        self._config = config
        detection = config.detection
        allowlist_vals = detection.allowlists.values
        self._registry = DetectorRegistry(
            enable_patterns=detection.enable_rules,
            disable_patterns=detection.disable_rules,
            allowlist_values=(
                frozenset(allowlist_vals) if allowlist_vals else None
            ),
            context_window_tokens=(detection.context_window_tokens),
        )

        # Log active severity overrides at startup so operators can confirm the policy is loaded correctly.
        overrides = config.compliance.severity_overrides
        if overrides:
            log.info(
                "compliance_severity_overrides_loaded",
                overrides = overrides,
            )

    def scan_files(
        self,
        target: str,
        *,
        no_cache: bool = False,
    ) -> ScanResult:
        """
        Scan filesystem target for sensitive data.

        Parameters
        ----------
        target:
            File or directory path to scan.
        no_cache:
            When True, bypass the hash cache and force a full rescan.
            Results are still written back to the cache so future
            incremental runs benefit.
        """
        scanner = FileScanner(
            self._config,
            self._registry,
            no_cache=no_cache,
        )
        result = scanner.scan(target)
        log.info(
            "file_scan_complete",
            target=target,
            findings=len(result.findings),
            targets=result.targets_scanned,
            no_cache=no_cache,
        )
        return result

    def scan_database(self, target: str) -> ScanResult:
        """
        Scan database target for sensitive data.
        """
        scanner = DatabaseScanner(self._config, self._registry)
        result = scanner.scan(target)
        log.info(
            "database_scan_complete",
            target=target,
            findings=len(result.findings),
            targets=result.targets_scanned,
        )
        return result

    def scan_network(self, target: str) -> ScanResult:
        """
        Scan network capture file for sensitive data.
        """
        scanner = NetworkScanner(self._config, self._registry)
        result = scanner.scan(target)
        log.info(
            "network_scan_complete",
            target=target,
            findings=len(result.findings),
            targets=result.targets_scanned,
        )
        return result

    def generate_report(
        self,
        result: ScanResult,
        output_format: OutputFormat | None = None,
    ) -> str:
        """
        Generate report string in the requested format.
        """
        fmt = output_format or self._config.output.format
        reporter_cls = REPORTER_MAP[fmt]
        reporter = reporter_cls()
        output: str = reporter.generate(result)
        return output

    def display_console(
        self,
        result: ScanResult,
    ) -> None:
        """
        Display Rich-formatted results to console.
        """
        reporter = ConsoleReporter()
        reporter.display(result)

    def write_report(
        self,
        result: ScanResult,
        output_path: str,
        output_format: OutputFormat | None = None,
    ) -> None:
        """
        Generate report and write to file.
        """
        content = self.generate_report(result, output_format)
        with open(output_path, "w") as f:
            f.write(content)
        log.info(
            "report_written",
            path=output_path,
            format=output_format or self._config.output.format,
        )