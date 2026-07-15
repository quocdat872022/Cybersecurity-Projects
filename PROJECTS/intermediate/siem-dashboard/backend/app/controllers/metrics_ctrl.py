"""
©AngelaMos | 2026
metrics_ctrl.py

Business logic for performance metrics aggregation

Computes percentile summaries (p50/p95/p99) per endpoint over a
recent window, compares against a longer-running baseline to flag
slowdowns, and returns bucketed timeline samples for charting.

Key exports:
  summary, timeline

Connects to:
  models/ScanMetric.py - reads duration samples
  core/metrics.py - percentile_summary, is_slowdown
  routes/metrics.py - called from route handlers
"""

from typing import Any
from datetime import datetime, timedelta, UTC

from flask import g

from app.core.metrics import percentile_summary, is_slowdown
from app.models.ScanMetric import ScanMetric


def summary() -> dict[str, Any]:
    """
    Return percentile summaries per endpoint with slowdown alerts
    """
    params = g.validated
    now = datetime.now(UTC)
    recent_since = now - timedelta(hours = params.hours)
    baseline_since = now - timedelta(hours = params.baseline_hours)

    endpoints = (
        [params.endpoint]
        if params.endpoint
        else ScanMetric.distinct_endpoints(baseline_since)
    )

    results = []
    for endpoint in endpoints:
        recent = percentile_summary(
            ScanMetric.durations_since(recent_since, endpoint)
        )
        baseline = percentile_summary(
            ScanMetric.durations_since(baseline_since, endpoint)
        )
        results.append({
            "endpoint": endpoint,
            "recent": recent,
            "baseline": baseline,
            "slowdown_alert": is_slowdown(baseline["p50"], recent["p95"]),
        })

    results.sort(key = lambda r: r["recent"]["p95"] or 0, reverse = True)
    return {
        "window_hours": params.hours,
        "baseline_hours": params.baseline_hours,
        "endpoints": results,
        "any_slowdown": any(r["slowdown_alert"] for r in results),
    }


def timeline() -> list[dict[str, Any]]:
    """
    Return 5-minute bucketed p50/p95/mean duration for charting
    """
    params = g.validated
    since = datetime.now(UTC) - timedelta(hours = params.hours)

    match_stage: dict[str, Any] = {"timestamp": {"$gte": since}}
    if params.endpoint:
        match_stage["endpoint"] = params.endpoint

    pipeline = [
        {"$match": match_stage},
        {
            "$group": {
                "_id": {
                    "$dateTrunc": {
                        "date": "$timestamp",
                        "unit": "minute",
                        "binSize": 5,
                    }
                },
                "durations": {"$push": "$duration_ms"},
                "count": {"$sum": 1},
            }
        },
        {"$sort": {"_id": 1}},
    ]

    buckets = []
    for doc in ScanMetric.objects.aggregate(pipeline):  # type: ignore[no-untyped-call]
        stats = percentile_summary(doc["durations"])
        buckets.append({
            "bucket": doc["_id"],
            "count": doc["count"],
            "p50": stats["p50"],
            "p95": stats["p95"],
            "mean": stats["mean"],
        })
    return buckets