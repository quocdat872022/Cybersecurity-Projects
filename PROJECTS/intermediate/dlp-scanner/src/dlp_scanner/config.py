"""
©AngelaMos | 2026
config.py
"""


from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
from ruamel.yaml import YAML

from dlp_scanner.constants import (
    DEFAULT_CONTEXT_WINDOW_TOKENS,
    DEFAULT_DB_MAX_ROWS,
    DEFAULT_DB_SAMPLE_PERCENTAGE,
    DEFAULT_DB_TIMEOUT_SECONDS,
    DEFAULT_DNS_ENTROPY_THRESHOLD,
    DEFAULT_ENTROPY_THRESHOLD,
    DEFAULT_EXCLUDE_PATTERNS,
    DEFAULT_MAX_FILE_SIZE_MB,
    DEFAULT_MIN_CONFIDENCE,
    SCANNABLE_EXTENSIONS,
    SEVERITY_ORDER,
    OutputFormat,
    RedactionStyle,
    Severity,
)


class FileScanConfig(BaseModel):
    """
    Configuration for file scanning
    """
    max_file_size_mb: int = DEFAULT_MAX_FILE_SIZE_MB
    recursive: bool = True
    exclude_patterns: list[str] = Field(
        default_factory = lambda: list(DEFAULT_EXCLUDE_PATTERNS)
    )
    include_extensions: list[str] = Field(
        default_factory = lambda: sorted(SCANNABLE_EXTENSIONS)
    )


class DatabaseScanConfig(BaseModel):
    """
    Configuration for database scanning
    """
    sample_percentage: int = DEFAULT_DB_SAMPLE_PERCENTAGE
    max_rows_per_table: int = DEFAULT_DB_MAX_ROWS
    timeout_seconds: int = DEFAULT_DB_TIMEOUT_SECONDS
    exclude_tables: list[str] = Field(default_factory = list)
    include_tables: list[str] = Field(default_factory = list)


class NetworkScanConfig(BaseModel):
    """
    Configuration for network traffic scanning
    """
    bpf_filter: str = ""
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD
    dns_label_entropy_threshold: float = (DEFAULT_DNS_ENTROPY_THRESHOLD)
    max_packets: int = 0


class AllowlistConfig(BaseModel):
    """
    Allowlists for suppressing known false positives
    """
    values: list[str] = Field(default_factory = list)
    domains: list[str] = Field(default_factory = list)
    file_patterns: list[str] = Field(default_factory = list)


class DetectionConfig(BaseModel):
    """
    Configuration for detection behavior
    """
    min_confidence: float = DEFAULT_MIN_CONFIDENCE
    severity_threshold: Severity = "low"
    context_window_tokens: int = (DEFAULT_CONTEXT_WINDOW_TOKENS)
    enable_rules: list[str] = Field(default_factory = lambda: ["*"])
    disable_rules: list[str] = Field(default_factory = list)
    allowlists: AllowlistConfig = Field(default_factory = AllowlistConfig)


class ComplianceConfig(BaseModel):
    """
    Configuration for compliance framework mapping.

    ``severity_overrides`` maps a compliance framework name to a minimum
    severity floor.  Any finding whose compliance_frameworks list contains
    that framework will be elevated to at least that severity level,
    regardless of the confidence-derived severity.
 
    Example YAML::
 
        compliance:
          frameworks:
            - HIPAA
            - PCI_DSS
          severity_overrides:
            PCI_DSS: "high"   # any unencrypted PAN is at least high
            HIPAA: "medium"   # PHI findings are at least medium
    """
    frameworks: list[str] = Field(
        default_factory = lambda: [
            "HIPAA",
            "PCI_DSS",
            "GDPR",
            "CCPA",
            ]
    )
    severity_overrides: dict[str, Severity] = Field(
        default_factory = dict
    )
 
    def effective_severity(
        self,
        confidence_severity: Severity,
        compliance_frameworks: list[str],
    ) -> tuple[Severity, str | None]:
        """
        Return the effective severity and the framework that caused an
        override (or ``None`` if no override was applied).
 
        The severity returned is the *maximum* of the confidence-derived
        severity and the highest floor mandated by any framework in
        ``compliance_frameworks``.  "Maximum" is defined by
        :data:`~dlp_scanner.constants.SEVERITY_ORDER` where ``critical``
        (order 0) is highest and ``low`` (order 3) is lowest.
 
        :param confidence_severity:  Severity derived from the raw
            confidence score (e.g. ``"low"`` for a 0.35-confidence match).
        :param compliance_frameworks: Frameworks associated with the
            finding (e.g. ``["PCI_DSS", "GLBA"]``).
        :returns: A ``(severity, override_reason)`` pair.  If the severity
            was not overridden ``override_reason`` is ``None``; otherwise it
            is the name of the framework that imposed the floor
            (e.g. ``"PCI_DSS"``).
        """
        if not self.severity_overrides:
            return confidence_severity, None
 
        best_floor: Severity | None = None
        triggered_by: str | None = None
 
        for framework in compliance_frameworks:
            floor = self.severity_overrides.get(framework)
            if floor is None:
                continue
            if (
                best_floor is None
                or SEVERITY_ORDER[floor] < SEVERITY_ORDER[best_floor]
            ):
                best_floor = floor
                triggered_by = framework
 
        if best_floor is None:
            return confidence_severity, None
 
        if SEVERITY_ORDER[best_floor] < SEVERITY_ORDER[confidence_severity]:
            return best_floor, triggered_by
 
        return confidence_severity, None


class OutputConfig(BaseModel):
    """
    Configuration for output and reporting
    """
    format: OutputFormat = "console"
    output_file: str = ""
    redaction_style: RedactionStyle = "partial"
    verbose: bool = False
    color: bool = True


class LoggingConfig(BaseModel):
    """
    Configuration for logging behavior
    """
    level: str = "INFO"
    json_output: bool = False
    log_file: str = ""


class ScanConfig(BaseModel):
    """
    Root configuration model for the DLP scanner
    """
    file: FileScanConfig = Field(default_factory = FileScanConfig)
    database: DatabaseScanConfig = Field(
        default_factory = DatabaseScanConfig
    )
    network: NetworkScanConfig = Field(default_factory = NetworkScanConfig)
    detection: DetectionConfig = Field(default_factory = DetectionConfig)
    compliance: ComplianceConfig = Field(
        default_factory = ComplianceConfig
    )
    output: OutputConfig = Field(default_factory = OutputConfig)
    logging: LoggingConfig = Field(default_factory = LoggingConfig)


def load_config(path: Path | None = None) -> ScanConfig:
    """
    Load configuration from a YAML file or return defaults
    """
    if path is None:
        candidates = [
            Path(".dlp-scanner.yml"),
            Path(".dlp-scanner.yaml"),
            Path.home() / ".dlp-scanner.yml",
        ]
        for candidate in candidates:
            if candidate.exists():
                path = candidate
                break

    if path is None or not path.exists():
        return ScanConfig()

    yaml = YAML(typ = "safe")
    raw: dict[str, Any] = yaml.load(path) or {}

    scan_section = raw.get("scan", {})
    return ScanConfig(
        file = FileScanConfig(**scan_section.get("file",
                                                 {})),
        database = DatabaseScanConfig(**scan_section.get("database",
                                                         {})),
        network = NetworkScanConfig(**scan_section.get("network",
                                                       {})),
        detection = DetectionConfig(**raw.get("detection",
                                              {})),
        compliance = ComplianceConfig(**raw.get("compliance",
                                                {})),
        output = OutputConfig(**raw.get("output",
                                        {})),
        logging = LoggingConfig(**raw.get("logging",
                                          {})),
    )
