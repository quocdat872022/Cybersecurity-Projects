"""
©AngelaMos | 2026
test_cli.py (watch)

CLI-level checks for `dlp-scan watch`. The command's main loop blocks
on `observer.join()` until SIGINT, so only the fast-fail validation
paths (before the Observer ever starts) are exercised here via
Typer's CliRunner -- the same pattern used in tests/test_cli.py for
the other subcommands. The interactive watch loop itself is covered
by test_integration.py, which drives the real Observer/handler/
debouncer chain directly and stops it explicitly rather than relying
on process signals.
"""


import tempfile
from pathlib import Path
from collections.abc import Generator

import pytest
from typer.testing import CliRunner

from dlp_scanner.cli import app


pytestmark = pytest.mark.unit

runner = CliRunner()


@pytest.fixture
def empty_dir() -> Generator[Path, None, None]:
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


class TestWatchCliValidation:
    def test_watch_help_lists_command(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "watch" in result.output

    def test_watch_subcommand_help(self) -> None:
        result = runner.invoke(app, ["watch", "--help"])
        assert result.exit_code == 0
        assert "--debounce" in result.output
        assert "--initial-scan" in result.output

    def test_nonexistent_target_exits_1_before_starting_observer(
        self,
    ) -> None:
        """
        Check 17: an invalid target must fail fast with a clear
        message and must never reach Observer.start() -- if it did,
        this test would hang waiting on observer.join().
        """
        result = runner.invoke(app, ["watch", "/no/such/directory"])
        assert result.exit_code == 1
        assert "Not a directory" in result.output

    def test_file_path_instead_of_directory_rejected(
        self,
        empty_dir: Path,
    ) -> None:
        a_file = empty_dir / "not_a_dir.txt"
        a_file.write_text("hello")

        result = runner.invoke(app, ["watch", str(a_file)])
        assert result.exit_code == 1
        assert "Not a directory" in result.output