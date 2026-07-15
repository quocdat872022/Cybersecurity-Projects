"""
©AngelaMos | 2026
metrics.py

Request timing capture, percentile calculation, and slowdown detection

init_metrics hooks before_request/after_request to time every API
call and persist samples via ScanMetric. percentile_summary wraps
numpy.percentile for p50/p95/p99. is_slowdown flags a target as
degrading when recent p95 latency exceeds a multiple of the
historical baseline median or an absolute threshold.

Key exports:
  init_metrics - attaches timing hooks to the Flask app
  percentile_summary - p50/p95/p99/min/max/mean/count for samples
  is_slowdown - bool flag comparing recent p95 against baseline

Connects to:
  models/ScanMetric.py - persists and reads duration_ms samples
  controllers/metrics_ctrl.py - calls percentile_summary, is_slowdown
  config.py - reads METRICS_SLOWDOWN_MULTIPLIER, METRICS_P95_ALERT_MS
  __init__.py - calls init_metrics
"""

import time
from typing import Any

import numpy as np
import structlog
from flask import Flask, Response, g, request

from app.config import settings

logger = structlog.get_logger()


def init_metrics(app: Flask) -> None:
    """
    Attach before/after request hooks that time every API call
    """
    @app.before_request
    def _start_timer() -> None:
        g._metrics_start = time.perf_counter()

    @app.after_request
    def _record_metrics(response: Response) -> Response:
        start = getattr(g, "_metrics_start", None)
        if start is not None and not request.path.endswith("/stream"):
            duration_ms = (time.perf_counter() - start) * 1000
            try:
                from app.models.ScanMetric import ScanMetric
                ScanMetric.record(
                    endpoint = request.path,
                    method = request.method,
                    duration_ms = duration_ms,
                    status_code = response.status_code,
                )
            except Exception:
                logger.exception("metrics_record_failed", path = request.path)
        return response


def percentile_summary(durations: list[float]) -> dict[str, Any]:
    """
    Compute summary statistics for a list of duration samples in ms
    """
    if not durations:
        return {
            "count": 0,
            "p50": None,
            "p95": None,
            "p99": None,
            "min": None,
            "max": None,
            "mean": None,
        }

    arr = np.array(durations)
    return {
        "count": len(durations),
        "p50": float(np.percentile(arr, 50)),
        "p95": float(np.percentile(arr, 95)),
        "p99": float(np.percentile(arr, 99)),
        "min": float(arr.min()),
        "max": float(arr.max()),
        "mean": float(arr.mean()),
    }


def is_slowdown(
    baseline_p50: float | None,
    recent_p95: float | None,
) -> bool:
    """
    Flag a slowdown when recent p95 exceeds the configured multiple
    of the historical baseline p50, or an absolute threshold
    """
    if recent_p95 is None:
        return False
    if recent_p95 >= settings.METRICS_P95_ALERT_MS:
        return True
    if baseline_p50 is None or baseline_p50 <= 0:
        return False
    return recent_p95 >= baseline_p50 * settings.METRICS_SLOWDOWN_MULTIPLIER