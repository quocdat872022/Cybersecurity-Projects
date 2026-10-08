"""
©AngelaMos | 2026
test_metrics.py

Tests the Prometheus /metrics endpoint and PipelineCollector

Connects to:
  api/metrics  - GET /metrics
  core/metrics - PipelineCollector
"""

import pytest
from prometheus_client import CollectorRegistry

from app.core.metrics import PipelineCollector
from tests.test_pipeline import VALID_LINE, _make_pipeline


@pytest.mark.asyncio
async def test_metrics_endpoint_serves_text_format(db_client) -> None:
    """
    GET /metrics returns Prometheus exposition text
    """
    response = await db_client.get("/metrics")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "vigil_inference_duration_seconds" in response.text


@pytest.mark.asyncio
async def test_collector_reports_stage_counts_and_queues() -> None:
    """
    Collector reflects pipeline stats and queue sizes at scrape time
    """
    results: list = []
    pipeline = await _make_pipeline(results)
    await pipeline.raw_queue.put(VALID_LINE)
    await pipeline.stop()

    registry = CollectorRegistry()
    registry.register(PipelineCollector(pipeline))

    ok = registry.get_sample_value(
        "vigil_requests_processed_total",
        {"stage": "dispatch", "outcome": "ok"},
    )
    depth = registry.get_sample_value("vigil_queue_depth", {"queue": "raw"})
    cap = registry.get_sample_value("vigil_queue_capacity", {"queue": "raw"})

    assert ok == 1.0
    assert depth == 0.0
    assert cap == 100.0