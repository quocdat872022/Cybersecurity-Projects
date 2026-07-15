"""
©AngelaMos | 2026
metrics.py

Route handlers for the performance metrics API (/v1/metrics)

Mounts GET /summary (percentile summary + slowdown alerts) and
GET /timeline (bucketed p50/p95 series for charting).

Connects to:
  controllers/metrics_ctrl.py - business logic
  schemas/metrics.py - MetricsSummaryParams
  routes/__init__.py - metrics_bp registered here
"""

from typing import Any

from flask import Blueprint

from app.controllers import metrics_ctrl
from app.core.decorators import endpoint, S, R
from app.schemas.metrics import MetricsSummaryParams


metrics_bp = Blueprint("metrics", __name__)


@metrics_bp.get("/summary")
@endpoint()
@S(MetricsSummaryParams, source = "query")
@R()
def summary() -> Any:
    """
    Return percentile summaries per endpoint with slowdown alerts
    """
    return metrics_ctrl.summary()


@metrics_bp.get("/timeline")
@endpoint()
@S(MetricsSummaryParams, source = "query")
@R()
def timeline() -> Any:
    """
    Return bucketed p50/p95 timing series for charting
    """
    return metrics_ctrl.timeline()