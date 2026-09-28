"""
©AngelaMos | 2026
debounce.py

Debounces rapid-fire filesystem events so that a single logical file
save (which editors often turn into several create/modify/rename
events within milliseconds) triggers exactly one scan, on a delay
after the *last* observed event for that path rather than the first.
"""


import threading
import time
from collections.abc import Callable
from pathlib import Path
from dlp_scanner.constants import DEFAULT_DEBOUNCE_SECONDS, POLL_INTERVAL_SECONDS

import structlog


log = structlog.get_logger()



class EventDebouncer:
    """
    Collapses bursts of filesystem events per-path into a single
    callback invocation after ``delay_seconds`` of inactivity on
    that path.

    Usage::

        debouncer = EventDebouncer(callback=scan_it, delay_seconds=0.5)
        debouncer.start()
        debouncer.touch(some_path)   # called from watchdog handler
        ...
        debouncer.stop()
    """
    def __init__(
        self,
        callback: Callable[[Path],
                           None],
        delay_seconds: float = DEFAULT_DEBOUNCE_SECONDS,
    ) -> None:
        self._callback = callback
        self._delay = delay_seconds
        self._pending: dict[Path,
                            float] = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def touch(self, path: Path) -> None:
        """
        Record that ``path`` had activity just now, resetting its timer
        """
        with self._lock:
            self._pending[path] = time.monotonic()

    def pending_count(self) -> int:
        """
        Return the number of paths currently awaiting their delay window

        Mostly useful for tests and diagnostics.
        """
        with self._lock:
            return len(self._pending)

    def start(self) -> None:
        """
        Start the background thread that flushes expired entries
        """
        if self._thread is not None:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target = self._run, daemon = True)
        self._thread.start()

    def stop(self) -> None:
        """
        Stop the background thread and wait for it to exit
        """
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout = 2.0)
            self._thread = None

    def flush(self) -> None:
        """
        Immediately fire the callback for every pending path, regardless
        of how long it has been waiting.

        Intended for tests and for a clean shutdown where any in-flight
        debounced events should still be processed.
        """
        with self._lock:
            ready = list(self._pending.keys())
            self._pending.clear()

        for path in ready:
            self._invoke(path)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            ready: list[Path] = []
            now = time.monotonic()

            with self._lock:
                for path, last_seen in list(self._pending.items()):
                    if now - last_seen >= self._delay:
                        ready.append(path)
                        del self._pending[path]

            for path in ready:
                self._invoke(path)

            time.sleep(POLL_INTERVAL_SECONDS)

    def _invoke(self, path: Path) -> None:
        try:
            self._callback(path)
        except Exception:
            log.warning("debounce_callback_failed", path = str(path))

    def __enter__(self) -> "EventDebouncer":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()