"""
©AngelaMos | 2026
error_tailer.py

Runs an access-log LogTailer and an error-log LogTailer
side by side (Challenge 5: Request Body Analysis via Error
Logs)

DualLogTailer starts an access LogTailer feeding the
existing ingestion Pipeline's raw_queue unchanged, and a
second LogTailer feeding a dedicated error_queue consumed
by ErrorLogPipeline. Keeping the two log sources on
separate queues — rather than a single queue with a line
prefix — avoids touching Pipeline's raw_queue contract at
all, since LogTailer already accepts any generic queue

Connects to:
  core/ingestion/
    tailer          - LogTailer, reused unmodified for
                      both log sources
  core/ingestion/
    error_pipeline  - ErrorLogPipeline consumes the error
                      queue this class feeds
  factory.py        - constructed in lifespan alongside the
                      access-only tailer, when the nginx
                      error log path exists
"""

import asyncio
from pathlib import Path

from app.core.ingestion.tailer import LogTailer


class DualLogTailer:
    """
    Runs an access-log LogTailer and an error-log LogTailer together.
    """

    def __init__(
        self,
        access_log_path: str,
        error_log_path: str,
        access_queue: asyncio.Queue[str | None],
        error_queue: asyncio.Queue[str | None],
        loop: asyncio.AbstractEventLoop,
        access_position_path: Path | None = None,
        error_position_path: Path | None = None,
    ) -> None:
        self._access_tailer = LogTailer(
            access_log_path,
            access_queue,
            loop,
            position_path=access_position_path,
        )
        self._error_tailer = LogTailer(
            error_log_path,
            error_queue,
            loop,
            position_path=error_position_path,
        )

    def start(self) -> None:
        """
        Start tailing both the access and error log files.
        """
        self._access_tailer.start()
        self._error_tailer.start()

    def stop(self) -> None:
        """
        Stop tailing both log files.
        """
        self._access_tailer.stop()
        self._error_tailer.stop()

    @property
    def is_active(self) -> bool:
        """
        Whether both tailers are currently running.
        """
        return self._access_tailer.is_active and self._error_tailer.is_active