"""
©AngelaMos | 2026
test_progress.py
"""

from pathlib import Path

from rveng.api.store import IN_MEMORY_DB, InMemoryProgress, SqliteProgress


def test_sqlite_marks_and_reads_back(tmp_path: Path):
    progress = SqliteProgress(tmp_path / "p.db")
    progress.mark_solved("s1", "05-find-the-gate")
    assert progress.solved("s1") == {"05-find-the-gate"}


def test_sqlite_isolates_sessions(tmp_path: Path):
    progress = SqliteProgress(tmp_path / "p.db")
    progress.mark_solved("s1", "05-find-the-gate")
    progress.mark_solved("s2", "03-flip-the-gate")
    assert progress.solved("s1") == {"05-find-the-gate"}
    assert progress.solved("s2") == {"03-flip-the-gate"}


def test_sqlite_mark_is_idempotent(tmp_path: Path):
    progress = SqliteProgress(tmp_path / "p.db")
    progress.mark_solved("s1", "05-find-the-gate")
    progress.mark_solved("s1", "05-find-the-gate")
    assert progress.solved("s1") == {"05-find-the-gate"}


def test_sqlite_persists_across_instances(tmp_path: Path):
    db = tmp_path / "p.db"
    SqliteProgress(db).mark_solved("s1", "05-find-the-gate")
    reopened = SqliteProgress(db)
    assert reopened.solved("s1") == {"05-find-the-gate"}


def test_sqlite_unknown_session_is_empty(tmp_path: Path):
    progress = SqliteProgress(tmp_path / "p.db")
    assert progress.solved("nobody") == set()


def test_sqlite_in_memory_creates_no_file(tmp_path: Path):
    progress = SqliteProgress(IN_MEMORY_DB)
    progress.mark_solved("s1", "05-find-the-gate")
    assert progress.solved("s1") == {"05-find-the-gate"}
    assert not any(tmp_path.iterdir())


def test_in_memory_and_sqlite_share_the_protocol(tmp_path: Path):
    for progress in (InMemoryProgress(), SqliteProgress(tmp_path / "p.db")):
        progress.mark_solved("s1", "c1")
        assert progress.solved("s1") == {"c1"}
