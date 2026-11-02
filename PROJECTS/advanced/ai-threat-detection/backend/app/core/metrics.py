"""
©AngelaMos | 2026
metrics.py

Prometheus metric definitions and the scrape-time pipeline
collector

THREATS_DETECTED counts every scored event by severity
(incremented in AlertDispatcher). INFERENCE_DURATION is a
histogram around InferenceEngine.predict. PipelineCollector
is a custom collector that, on each scrape, reads the
Pipeline stats dict and queue sizes, so per-stage counters
and queue depth gauges add zero cost to the hot path

Connects to:
  core/alerts/dispatcher  - THREATS_DETECTED
  core/ingestion/pipeline - INFERENCE_DURATION, stats,
                            queue_depths
  api/metrics             - exposes the default registry
  factory.py              - registers the collector
"""

from collections.abc import Iterable

from prometheus_client import REGISTRY, Counter, Histogram
from prometheus_client.core import (
    CounterMetricFamily,
    GaugeMetricFamily,
    Metric,
)
from prometheus_client.registry import Collector


from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app.core.ingestion.pipeline import Pipeline
    
THREATS_DETECTED = Counter(
    "vigil_threats_detected_total",
    "Scored requests by severity (LOW included)",
    ["severity"],
)

INFERENCE_DURATION = Histogram(
    "vigil_inference_duration_seconds",
    "ONNX ensemble inference latency per call",
    buckets=(0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5),
)

# stage -> (success stat key, error stat key)
_STAGE_STATS: dict[str, tuple[str, str]] = {
    "parse": ("parsed", "parse_errors"),
    "feature": ("enriched", "enrich_errors"),
    "detect": ("scored", "score_errors"),
    "dispatch": ("dispatched", "dispatch_errors"),
}


class PipelineCollector(Collector):
    """
    Exposes pipeline stage counters and queue gauges at scrape time
    """

    def __init__(self, pipeline: "Pipeline") -> None:
        self._pipeline = pipeline

    def collect(self) -> Iterable[Metric]:
        stats = self._pipeline.stats

        processed = CounterMetricFamily(
            "vigil_requests_processed",
            "Log lines processed per pipeline stage",
            labels=["stage", "outcome"],
        )
        for stage, (ok_key, err_key) in _STAGE_STATS.items():
            processed.add_metric([stage, "ok"], stats[ok_key])
            processed.add_metric([stage, "error"], stats[err_key])
        yield processed

        depth = GaugeMetricFamily(
            "vigil_queue_depth",
            "Items currently waiting in each pipeline queue",
            labels=["queue"],
        )
        capacity = GaugeMetricFamily(
            "vigil_queue_capacity",
            "Max size of each pipeline queue",
            labels=["queue"],
        )
        for name, (size, maxsize) in self._pipeline.queue_depths.items():
            depth.add_metric([name], size)
            capacity.add_metric([name], maxsize)
        yield depth
        yield capacity


def register_pipeline_collector(pipeline: "Pipeline") -> "PipelineCollector":
    collector = PipelineCollector(pipeline)
    REGISTRY.register(collector)
    return collector


def unregister_pipeline_collector(collector: PipelineCollector) -> None:
    REGISTRY.unregister(collector)