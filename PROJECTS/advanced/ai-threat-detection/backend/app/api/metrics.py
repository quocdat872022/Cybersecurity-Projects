"""
©AngelaMos | 2026
metrics.py

Prometheus exposition endpoint

GET /metrics renders the default registry (pipeline
collector, threat counter, inference histogram, plus the
built-in process and GC collectors) in Prometheus text
format

Connects to:
  core/metrics - metric definitions registered on the
                 default registry
"""

from fastapi import APIRouter, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

router = APIRouter()


@router.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    """
    Prometheus scrape endpoint
    """
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)