"""
©AngelaMos | 2026
metrics.py

Pydantic schemas for the performance metrics endpoints

Key exports:
  MetricsSummaryParams - endpoint filter, recent window, baseline window
"""

from pydantic import BaseModel, Field


class MetricsSummaryParams(BaseModel):
    """
    Query params for percentile summary, timeline, and slowdown detection
    """
    endpoint: str | None = None
    hours: int = Field(default = 1, ge = 1, le = 168)
    baseline_hours: int = Field(default = 24, ge = 1, le = 720)