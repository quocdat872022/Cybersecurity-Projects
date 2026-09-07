"""
©AngelaMos | 2026
test_debounce.py
"""


import time
from pathlib import Path

import pytest

from dlp_scanner.watch.debounce import EventDebouncer


pytestmark = pytest.mark.unit


class TestEventDebouncer:
    def test_single_touch_fires_after_delay(self) -> None:
        seen: list[Path] = []
        debouncer = EventDebouncer(
            callback = seen.append,
            delay_seconds = 0.1,
        )
        debouncer.start()
        try:
            debouncer.touch(Path("a.txt"))
            time.sleep(0.05)
            assert seen == []

            time.sleep(0.2)
            assert seen == [Path("a.txt")]
        finally:
            debouncer.stop()

    def test_repeated_touches_collapse_to_one_call(self) -> None:
        seen: list[Path] = []
        debouncer = EventDebouncer(
            callback = seen.append,
            delay_seconds = 0.15,
        )
        debouncer.start()
        try:
            path = Path("burst.txt")
            for _ in range(5):
                debouncer.touch(path)
                time.sleep(0.03)

            time.sleep(0.3)
            assert seen == [path]
        finally:
            debouncer.stop()

    def test_different_paths_tracked_independently(self) -> None:
        seen: list[Path] = []
        debouncer = EventDebouncer(
            callback = seen.append,
            delay_seconds = 0.1,
        )
        debouncer.start()
        try:
            debouncer.touch(Path("one.txt"))
            debouncer.touch(Path("two.txt"))
            time.sleep(0.25)
            assert set(seen) == {Path("one.txt"), Path("two.txt")}
        finally:
            debouncer.stop()

    def test_pending_count_reflects_untouched_entries(self) -> None:
        debouncer = EventDebouncer(callback = lambda p: None, delay_seconds = 5.0)
        debouncer.touch(Path("still-pending.txt"))
        assert debouncer.pending_count() == 1

    def test_flush_fires_immediately_without_waiting(self) -> None:
        seen: list[Path] = []
        debouncer = EventDebouncer(
            callback = seen.append,
            delay_seconds = 999.0,
        )
        debouncer.touch(Path("urgent.txt"))
        debouncer.flush()
        assert seen == [Path("urgent.txt")]
        assert debouncer.pending_count() == 0

    def test_callback_exception_does_not_crash_loop(self) -> None:
        calls: list[Path] = []

        def flaky(path: Path) -> None:
            calls.append(path)
            if path == Path("bad.txt"):
                raise RuntimeError("boom")

        debouncer = EventDebouncer(callback = flaky, delay_seconds = 0.1)
        debouncer.start()
        try:
            debouncer.touch(Path("bad.txt"))
            debouncer.touch(Path("good.txt"))
            time.sleep(0.3)
            assert set(calls) == {Path("bad.txt"), Path("good.txt")}
        finally:
            debouncer.stop()

    def test_start_is_idempotent(self) -> None:
        debouncer = EventDebouncer(callback = lambda p: None)
        debouncer.start()
        first_thread = debouncer._thread
        debouncer.start()
        assert debouncer._thread is first_thread
        debouncer.stop()

    def test_context_manager_starts_and_stops(self) -> None:
        seen: list[Path] = []
        with EventDebouncer(callback = seen.append, delay_seconds = 0.05) as d:
            d.touch(Path("ctx.txt"))
            time.sleep(0.2)
        assert seen == [Path("ctx.txt")]