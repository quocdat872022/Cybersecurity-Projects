"""
©AngelaMos | 2026
syslog_reporter.py

Challenge 9: SIEM Integration via Syslog

Ships DLP findings to a SIEM (Splunk, Elastic, QRadar, ...) as RFC 5424
syslog messages over TCP or UDP. Implements the ``Reporter`` protocol
(``generate(result) -> str``) so it can be previewed/tested offline like
every other reporter, and additionally exposes ``send(result)`` which
opens a real socket and transmits the findings, batching writes so a
large finding set does not open/flush the connection once per message.

Usage (wire into engine.py and commands/scan.py -- see rules/README.md
style docstring in html_report.py for the pattern this follows):

    reporter = SyslogReporter(
        host = "siem.corp.com",
        port = 514,
        protocol = "tcp",
    )
    sent = reporter.send(result)

Message format
---------------
Each finding becomes one RFC 5424 message::

    <134>1 2026-04-08T10:30:00.123456Z scanner dlp-scan 4821 PII_SSN
    [finding@dlp rule_id="PII_SSN" severity="critical" confidence="0.92"
    uri="employees.csv"] US Social Security Number detected

  * PRI = facility * 8 + severity  (facility defaults to local0 = 16)
  * MSGID carries the rule_id so downstream systems can route/dedupe
    without parsing structured data
  * STRUCTURED-DATA carries every machine-readable field; MSG stays a
    short human-readable summary

A scan-level "summary" message is emitted first (clean or N findings),
so a SIEM search over a time window shows one row per scan even when
zero findings were produced.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from datetime import datetime, UTC
from enum import IntEnum
from os import getpid
from socket import gethostname
from typing import TYPE_CHECKING

import structlog

from dlp_scanner.constants import Severity

if TYPE_CHECKING:
    from dlp_scanner.models import Finding, ScanResult


log = structlog.get_logger()

NILVALUE: str = "-"
SD_ID: str = "finding@dlp"
DEFAULT_BATCH_SIZE: int = 50
DEFAULT_FLUSH_INTERVAL_SECONDS: float = 5.0
DEFAULT_PORT: int = 514
DEFAULT_TIMEOUT_SECONDS: float = 5.0


class SyslogFacility(IntEnum):
    """
    A small subset of RFC 5424 facility codes relevant to a scanner
    """
    USER = 1
    LOCAL0 = 16
    LOCAL1 = 17
    LOCAL2 = 18
    LOCAL3 = 19


# Finding severity -> RFC 5424 syslog severity (0 = Emergency, 7 = Debug)
_SEVERITY_MAP: dict[Severity, int] = {
    "critical": 2,   # Critical
    "high": 3,       # Error
    "medium": 4,     # Warning
    "low": 5,        # Notice
}
_CLEAN_SCAN_SEVERITY: int = 6  # Informational


class SyslogReporter:
    """
    Formats and optionally transmits findings as RFC 5424 syslog messages

    Implements the Reporter protocol via ``generate(result) -> str``.
    Call ``send(result)`` to actually open a socket and deliver the
    messages; ``generate`` alone never touches the network.
    """
    def __init__(
        self,
        host: str = "",
        port: int = DEFAULT_PORT,
        protocol: str = "tcp",
        *,
        facility: SyslogFacility = SyslogFacility.LOCAL0,
        app_name: str = "dlp-scan",
        hostname: str = "",
        batch_size: int = DEFAULT_BATCH_SIZE,
        flush_interval: float = DEFAULT_FLUSH_INTERVAL_SECONDS,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._host = host
        self._port = port
        self._protocol = protocol.lower()
        if self._protocol not in ("tcp", "udp"):
            raise ValueError(
                f"Unsupported syslog protocol: {protocol!r}. "
                f"Use 'tcp' or 'udp'."
            )
        self._facility = facility
        self._app_name = app_name
        self._hostname = hostname or gethostname()
        self._batch_size = max(1, batch_size)
        self._flush_interval = flush_interval
        self._timeout = timeout

    # ── Reporter protocol ────────────────────────────────────────────────

    def generate(self, result: "ScanResult") -> str:
        """
        Render every message that would be sent, one per line

        Never opens a socket; useful for previewing output, piping to a
        file for a syslog-ng/rsyslog test harness, or unit testing the
        formatting in isolation from the network.
        """
        lines = [self._format_summary(result)]
        for finding in result.findings:
            lines.append(self._format_finding(finding, result.scan_id))
        return "\n".join(lines)

    # ── Network delivery ─────────────────────────────────────────────────

    def send(self, result: "ScanResult") -> int:
        """
        Transmit the scan summary and every finding to the configured host

        Returns the number of messages successfully sent. Batches writes
        in groups of ``batch_size``, sleeping ``flush_interval`` seconds
        between batches so a large finding set does not overwhelm the
        SIEM ingestion pipeline. Connection failures are logged and
        raised; partial sends before a failure are reflected in the
        return value only when the caller catches the exception and
        inspects ``SyslogSendError.sent_count``.
        """
        if not self._host:
            raise ValueError(
                "SyslogReporter.send() requires a host; "
                "construct with host=<siem hostname or ip>"
            )

        messages = [self._format_summary(result)]
        messages.extend(
            self._format_finding(f, result.scan_id)
            for f in result.findings
        )

        sender = (
            self._send_tcp if self._protocol == "tcp" else self._send_udp
        )

        sent = 0
        try:
            for batch_start in range(0, len(messages), self._batch_size):
                batch = messages[
                    batch_start : batch_start + self._batch_size
                ]
                sender(batch)
                sent += len(batch)

                is_last_batch = (
                    batch_start + self._batch_size >= len(messages)
                )
                if not is_last_batch and self._flush_interval > 0:
                    time.sleep(self._flush_interval)

        except OSError as exc:
            log.warning(
                "syslog_send_failed",
                host = self._host,
                port = self._port,
                protocol = self._protocol,
                sent_before_failure = sent,
                error = str(exc),
            )
            raise SyslogSendError(sent_count = sent) from exc

        log.info(
            "syslog_send_complete",
            host = self._host,
            port = self._port,
            protocol = self._protocol,
            messages_sent = sent,
        )
        return sent

    def _send_tcp(self, batch: list[str]) -> None:
        """
        Send a batch of messages over a single TCP connection

        Uses non-transparent (newline-delimited) framing per RFC 6587,
        which is the framing every mainstream syslog receiver accepts
        by default; octet-counted framing is not used here to keep the
        wire format readable in a packet capture during setup.
        """
        with socket.create_connection(
            (self._host, self._port),
            timeout = self._timeout,
        ) as sock:
            payload = "".join(f"{msg}\n" for msg in batch)
            sock.sendall(payload.encode("utf-8"))

    def _send_udp(self, batch: list[str]) -> None:
        """
        Send a batch of messages as individual UDP datagrams

        Each RFC 5424 message is sent as its own datagram (never
        newline-joined) since UDP syslog receivers treat one datagram
        as exactly one message.
        """
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        ) as sock:
            sock.settimeout(self._timeout)
            for msg in batch:
                sock.sendto(
                    msg.encode("utf-8"),
                    (self._host, self._port),
                )

    # ── Message formatting ───────────────────────────────────────────────

    def _format_summary(self, result: "ScanResult") -> str:
        """
        Build a single scan-level summary message
        """
        by_sev = result.findings_by_severity
        total = len(result.findings)
        severity = (
            _CLEAN_SCAN_SEVERITY if total == 0
            else min(
                (
                    _SEVERITY_MAP[sev]
                    for sev, count in by_sev.items() if count > 0
                ),
                default = _CLEAN_SCAN_SEVERITY,
            )
        )

        sd_params = {
            "scan_id": result.scan_id,
            "total_findings": str(total),
            "targets_scanned": str(result.targets_scanned),
            "critical": str(by_sev.get("critical", 0)),
            "high": str(by_sev.get("high", 0)),
            "medium": str(by_sev.get("medium", 0)),
            "low": str(by_sev.get("low", 0)),
        }

        msg = (
            f"DLP scan {result.scan_id} complete: "
            f"{total} finding{'s' if total != 1 else ''} across "
            f"{result.targets_scanned} target"
            f"{'s' if result.targets_scanned != 1 else ''}"
        )

        return self._build_message(
            severity = severity,
            msgid = "SCAN_SUMMARY",
            sd_params = sd_params,
            msg = msg,
        )

    def _format_finding(self, finding: "Finding", scan_id: str) -> str:
        """
        Build a single RFC 5424 message for one finding
        """
        severity = _SEVERITY_MAP.get(finding.severity, 4)

        sd_params = {
            "scan_id": scan_id,
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "confidence": f"{finding.confidence:.4f}",
            "uri": finding.location.uri,
            "source_type": finding.location.source_type,
        }
        if finding.location.line is not None:
            sd_params["line"] = str(finding.location.line)
        if finding.location.table_name:
            sd_params["table_name"] = finding.location.table_name
        if finding.compliance_frameworks:
            sd_params["compliance"] = ",".join(
                finding.compliance_frameworks
            )

        msg = f"{finding.rule_name} detected in {finding.location.uri}"

        return self._build_message(
            severity = severity,
            msgid = finding.rule_id or NILVALUE,
            sd_params = sd_params,
            msg = msg,
        )

    def _build_message(
        self,
        *,
        severity: int,
        msgid: str,
        sd_params: dict[str, str],
        msg: str,
    ) -> str:
        """
        Assemble one RFC 5424 message from its component parts
        """
        pri = self._facility.value * 8 + severity
        timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[
            :-3
        ] + "Z"
        procid = str(getpid())
        structured_data = _build_structured_data(SD_ID, sd_params)

        return (
            f"<{pri}>1 {timestamp} {self._hostname} {self._app_name} "
            f"{procid} {msgid} {structured_data} {msg}"
        )


class SyslogSendError(RuntimeError):
    """
    Raised when a syslog send fails partway through a batch send
    """
    def __init__(self, sent_count: int) -> None:
        super().__init__(
            f"Syslog send failed after {sent_count} message(s) "
            f"were successfully delivered"
        )
        self.sent_count = sent_count


def _build_structured_data(
    sd_id: str,
    params: dict[str, str],
) -> str:
    """
    Render an RFC 5424 STRUCTURED-DATA element from a param dict

    Returns the nil value "-" when there are no params, per spec.
    """
    if not params:
        return NILVALUE

    rendered_params = " ".join(
        f'{key}="{_escape_sd_value(value)}"'
        for key, value in params.items()
    )
    return f"[{sd_id} {rendered_params}]"


def _escape_sd_value(value: str) -> str:
    """
    Escape a structured-data parameter value per RFC 5424 section 6.3.3

    Backslash, double-quote, and closing-bracket must be backslash
    escaped inside a PARAM-VALUE.
    """
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("]", "\\]")
    )