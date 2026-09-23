"""
©AngelaMos | 2026
error_pipeline.py

Single-stage async worker analyzing nginx error log lines
in parallel with the main 4-stage access log pipeline
(Challenge 5: Request Body Analysis via Error Logs)

ErrorLogPipeline pulls raw error log lines from a dedicated
queue, parses them via parse_error_line, extracts entropy/
attack-pattern features from the message text via
extract_body_features, attempts correlation with a recent
access log entry from the same IP via EventCorrelator, and
forwards an ErrorAnalysisResult to the on_result callback.
Runs alongside — not inside — the main Pipeline, since
error-log features are not part of the 35-dim ML feature
vector

Connects to:
  core/ingestion/
    error_parsers   - parse_error_line, ParsedErrorEntry
  core/features/
    body_features   - extract_body_features
  core/enrichment/
    correlator      - EventCorrelator.match_error
  core/ingestion/
    error_tailer    - DualLogTailer feeds the error_queue
  factory.py        - constructed and started alongside the
                      main Pipeline
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from app.core.enrichment.correlator import CorrelatedEvent, EventCorrelator
from app.core.features.body_features import extract_body_features
from app.core.ingestion.error_parsers import ParsedErrorEntry, parse_error_line

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ErrorAnalysisResult:
    """
    A parsed error entry enriched with body features and correlated context.
    """

    error: ParsedErrorEntry
    body_features: dict[str, int | float | bool]
    correlated: CorrelatedEvent


class ErrorLogPipeline:
    """
    Single-stage worker that analyzes nginx error log lines
    and correlates them with recent access log activity.
    """

    def __init__(
        self,
        error_queue: asyncio.Queue[str | None],
        correlator: EventCorrelator,
        on_result: (Callable[[ErrorAnalysisResult], Awaitable[None]]
                    | None) = None,
    ) -> None:
        self._error_queue = error_queue
        self._correlator = correlator
        self._on_result = on_result
        self._task: asyncio.Task[None] | None = None
        self._stats: dict[str, int] = {
            "parsed": 0,
            "parse_errors": 0,
            "correlated": 0,
            "dispatched": 0,
            "dispatch_errors": 0,
        }

    @property
    def stats(self) -> dict[str, int]:
        """
        Return a snapshot of processed/error counters.
        """
        return dict(self._stats)

    async def start(self) -> None:
        """
        Spawn the error log analysis worker task.
        """
        self._task = asyncio.create_task(self._worker(), name="error-analysis")
        logger.info("ErrorLogPipeline started")

    async def stop(self) -> None:
        """
        Send a poison pill and wait for the worker to exit.
        """
        await self._error_queue.put(None)
        if self._task is not None:
            await self._task
        logger.info("ErrorLogPipeline stopped")

    async def _worker(self) -> None:
        while True:
            line = await self._error_queue.get()
            if line is None:
                self._error_queue.task_done()
                break
            try:
                entry = parse_error_line(line)
                if entry is None:
                    self._error_queue.task_done()
                    continue
                self._stats["parsed"] += 1

                body_features = extract_body_features(entry.message)
                correlated = self._correlator.match_error(entry)
                if correlated.access is not None:
                    self._stats["correlated"] += 1

                result = ErrorAnalysisResult(
                    error=entry,
                    body_features=body_features,
                    correlated=correlated,
                )

                if self._on_result is not None:
                    await self._on_result(result)
                self._stats["dispatched"] += 1
            except Exception:
                self._stats["parse_errors"] += 1
                logger.exception("Error log analysis failed")
            self._error_queue.task_done()