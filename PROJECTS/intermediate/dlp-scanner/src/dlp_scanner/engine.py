"""
©AngelaMos | 2026
engine.py

Challenge 9 addition: ``send_to_siem`` dispatches a completed
ScanResult to whichever SIEM transport is configured under
``output.siem`` (syslog or Splunk HEC).
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
from dlp_scanner.reporters.splunk_hec_reporter import (
    SplunkHecReporter,
)
from dlp_scanner.reporters.syslog_reporter import SyslogReporter

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

REPORTER_MAP: dict[str,
                   type] = {
                       "console": ConsoleReporter,
                       "json": JsonReporter,
                       "sarif": SarifReporter,
                       "csv": CsvReporter,
                       "html": HtmlReporter,
                   }


class ScanEngine:
    """
    Orchestrates the full scan pipeline
    """
    def __init__(self, config: ScanConfig) -> None:
        self._config = config
        detection = config.detection
        allowlist_vals = detection.allowlists.values
        self._registry = DetectorRegistry(
            enable_patterns = detection.enable_rules,
            disable_patterns = detection.disable_rules,
            allowlist_values = (
                frozenset(allowlist_vals) if allowlist_vals else None
            ),
            context_window_tokens = (detection.context_window_tokens),
            custom_rules_dir = detection.custom_rules_dir or None,
        )

        # Log active severity overrides at startup so operators can confirm the policy is loaded correctly.
        overrides = config.compliance.severity_overrides
        if overrides:
            log.info(
                "compliance_severity_overrides_loaded",
                overrides = overrides,
            )
        log.info(
            "detector_registry_ready",
            rule_count = self._registry.rule_count,
            custom_rule_count = self._registry.custom_rule_count,
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
            target = target,
            findings = len(result.findings),
            targets = result.targets_scanned,
        )
        return result

    def scan_database(self, target: str) -> ScanResult:
        """
        Scan database target for sensitive data
        """
        scanner = DatabaseScanner(self._config, self._registry)
        result = scanner.scan(target)
        log.info(
            "database_scan_complete",
            target = target,
            findings = len(result.findings),
            targets = result.targets_scanned,
        )
        return result

    def scan_network(self, target: str) -> ScanResult:
        """
        Scan network capture file for sensitive data
        """
        scanner = NetworkScanner(self._config, self._registry)
        result = scanner.scan(target)
        log.info(
            "network_scan_complete",
            target = target,
            findings = len(result.findings),
            targets = result.targets_scanned,
        )
        return result

    def generate_report(
        self,
        result: ScanResult,
        output_format: OutputFormat | None = None,
    ) -> str:
        """
        Generate report string in the requested format
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
        Display Rich-formatted results to console
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
        Generate report and write to file
        """
        content = self.generate_report(result, output_format)
        with open(output_path, "w") as f:
            f.write(content)
        log.info(
            "report_written",
            path = output_path,
            format = output_format or self._config.output.format,
        )

    def send_to_siem(self, result: ScanResult) -> int:
        """
        Forward a completed scan result to the configured SIEM

        Reads ``output.siem`` from the loaded config to decide the
        transport (``"syslog"`` or ``"splunk_hec"``) and its connection
        details. Returns the number of messages/events successfully
        delivered. Raises ``ValueError`` if no SIEM is configured
        (``output.siem.type`` is unset), so callers should check
        ``self._config.output.siem.type`` first if forwarding is
        optional for their code path.
        """
        siem = self._config.output.siem

        if siem.type == "syslog":
            reporter = SyslogReporter(
                host = siem.host,
                port = siem.port,
                protocol = siem.protocol,
                batch_size = siem.batch_size,
                flush_interval = siem.flush_interval_seconds,
            )
            sent = reporter.send(result)

        elif siem.type == "splunk_hec":
            reporter = SplunkHecReporter(
                hec_url = siem.hec_url,
                hec_token = siem.hec_token,
                batch_size = siem.batch_size,
                flush_interval = siem.flush_interval_seconds,
                verify_ssl = siem.verify_ssl,
            )
            sent = reporter.send(result)

        else:
            raise ValueError(
                "No SIEM configured. Set output.siem.type to "
                "'syslog' or 'splunk_hec' in your config."
            )

        log.info(
            "siem_forward_complete",
            siem_type = siem.type,
            messages_sent = sent,
        )
        return sent