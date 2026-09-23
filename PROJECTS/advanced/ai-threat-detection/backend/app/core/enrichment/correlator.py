"""
©AngelaMos | 2026
correlator.py

Correlates access log entries with error log entries by
source IP and timestamp proximity (Challenge 5 extra
credit)

EventCorrelator keeps a short-lived, bounded ring buffer of
recently seen ParsedLogEntry objects keyed by source IP.
match_error looks up the buffer for the error entry's
client_ip (when present) and returns the closest access
entry within a configurable time window, giving analysts
the full request context (method, path, status, feature
vector) alongside the error detail nginx logged separately.
Stale entries are pruned lazily on each call so memory use
stays bounded without a background task

Connects to:
  core/ingestion/
    parsers         - ParsedLogEntry (access log side)
  core/ingestion/
    error_parsers   - ParsedErrorEntry (error log side)
  core/ingestion/
    error_pipeline  - calls match_error per error entry
  core/ingestion/
    pipeline        - Pipeline.on_parsed feeds record_access
"""

from dataclasses import dataclass, field
from datetime import datetime

from app.core.ingestion.error_parsers import ParsedErrorEntry
from app.core.ingestion.parsers import ParsedLogEntry

DEFAULT_WINDOW_SECONDS = 5.0
DEFAULT_MAX_PER_IP = 50


@dataclass(frozen=True, slots=True)
class CorrelatedEvent:
    """
    An error log entry paired with the closest matching access log entry.
    """

    error: ParsedErrorEntry
    access: ParsedLogEntry | None
    time_delta_seconds: float | None


@dataclass(slots=True)
class EventCorrelator:
    """
    Correlates error log entries with recent access log entries by IP.
    """

    window_seconds: float = DEFAULT_WINDOW_SECONDS
    max_per_ip: int = DEFAULT_MAX_PER_IP
    _by_ip: dict[str, list[ParsedLogEntry]] = field(default_factory=dict)

    def record_access(self, entry: ParsedLogEntry) -> None:
        """
        Record an access log entry for later correlation.
        """
        bucket = self._by_ip.setdefault(entry.ip, [])
        bucket.append(entry)
        if len(bucket) > self.max_per_ip:
            del bucket[: len(bucket) - self.max_per_ip]

    def match_error(self, error: ParsedErrorEntry) -> CorrelatedEvent:
        """
        Find the closest access log entry for an error entry's client IP.
        """
        if error.client_ip is None:
            return CorrelatedEvent(
                error=error, access=None, time_delta_seconds=None)

        self._prune(error.client_ip, error.timestamp)

        bucket = self._by_ip.get(error.client_ip, [])
        if not bucket:
            return CorrelatedEvent(
                error=error, access=None, time_delta_seconds=None)

        best: ParsedLogEntry | None = None
        best_delta = float("inf")
        for candidate in bucket:
            delta = abs(
                (error.timestamp - candidate.timestamp).total_seconds())
            if delta < best_delta:
                best = candidate
                best_delta = delta

        if best is None or best_delta > self.window_seconds:
            return CorrelatedEvent(
                error=error, access=None, time_delta_seconds=None)

        return CorrelatedEvent(
            error=error,
            access=best,
            time_delta_seconds=best_delta,
        )

    def _prune(self, ip: str, reference_time: datetime) -> None:
        """
        Drop access entries for an IP that fall outside the window.
        """
        bucket = self._by_ip.get(ip)
        if not bucket:
            return
        cutoff = self.window_seconds
        self._by_ip[ip] = [
            e for e in bucket
            if abs((reference_time - e.timestamp).total_seconds()) <= cutoff
        ]