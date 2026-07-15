"""
©AngelaMos | 2026
ScanMetric.py

MongoEngine model for API/request performance metrics

Stores per-request timing samples (endpoint, method, duration_ms,
status_code) so response time trends can be analyzed after the
fact. Provides query helpers used for percentile calculation and
baseline comparison to detect target slowdowns.

Key exports:
  ScanMetric - timing sample document with query helpers

Connects to:
  models/Base.py - extends BaseDocument
  core/metrics.py - init_metrics records samples via ScanMetric.record
  controllers/metrics_ctrl.py - reads aggregated metrics
"""

from typing import Any
from datetime import datetime, UTC

from mongoengine import (
    StringField,
    FloatField,
    IntField,
    DateTimeField,
)

from app.models.Base import BaseDocument


class ScanMetric(BaseDocument):
    """
    A single timing sample for a request/scan operation
    """
    meta: dict[str, Any] = {  # noqa: RUF012
        "collection": "scan_metrics",
        "ordering": ["-timestamp"],
        "indexes": [
            "timestamp",
            "endpoint",
            ("endpoint", "-timestamp"),
        ],
    }

    endpoint = StringField(required = True)
    method = StringField(required = True)
    duration_ms = FloatField(required = True)
    status_code = IntField()
    timestamp = DateTimeField(default = lambda: datetime.now(UTC))

    @classmethod
    def record(
        cls,
        endpoint: str,
        method: str,
        duration_ms: float,
        status_code: int | None = None,
    ) -> None:
        """
        Persist a single timing sample
        """
        cls(
            endpoint = endpoint,
            method = method,
            duration_ms = duration_ms,
            status_code = status_code,
        ).save()  # type: ignore[no-untyped-call]

    @classmethod
    def durations_since(
        cls,
        since: datetime,
        endpoint: str | None = None,
    ) -> list[float]:
        """
        Return raw duration_ms samples within a time window
        """
        qs = cls.objects(timestamp__gte = since)  # type: ignore[no-untyped-call]
        if endpoint:
            qs = qs.filter(endpoint = endpoint)
        return [doc.duration_ms for doc in qs.only("duration_ms")]

    @classmethod
    def distinct_endpoints(cls, since: datetime) -> list[str]:
        """
        Return endpoints that have samples within the window
        """
        return list(
            cls.objects(timestamp__gte = since).distinct("endpoint")  # type: ignore[no-untyped-call]
        )