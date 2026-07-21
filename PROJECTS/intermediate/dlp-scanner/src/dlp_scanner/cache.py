"""
©AngelaMos | 2026
cache.py

Incremental scan cache backed by SQLite.

Design
------
The cache stores one row per scanned file:

    file_path     TEXT  – absolute path of the scanned file
    content_hash  TEXT  – SHA-256 hex digest of file contents
    scan_time     TEXT  – ISO-8601 timestamp of when the file was scanned
    finding_count INT   – number of findings produced (informational)
    rule_set_hash TEXT  – SHA-256 of active rule IDs + min_confidence,
                          used to invalidate cached results when the
                          detection configuration changes

Cache invalidation strategy
---------------------------
Three independent signals can make a cached result stale:

1. **File content changed** – detected by comparing the stored
   content_hash with a freshly computed SHA-256 of the file.  Cost:
   one read of the file (unavoidable even for a "skip" decision).

2. **Detection configuration changed** – the rule set (enabled rule IDs
   sorted) and min_confidence are hashed together into a single
   ``rule_set_hash``.  If the current rule_set_hash differs from what is
   stored in the cache *metadata* table, the entire cache is invalidated
   before the scan begins.  This is the cheapest possible approach: one
   metadata row checked once per scan run.

3. **Cache bypassed** – the caller passes ``no_cache=True``; the scan
   still writes back to the cache so future runs benefit.

Edge cases handled
------------------
* Deleted files – ``get_cached()`` returns ``None`` for paths not in the
  cache; stale entries from deleted files are not returned as findings.
* First run – the SQLite file is created automatically; all files are
  treated as uncached and written after scanning.
* Concurrent access – SQLite's default journal mode provides
  read-your-writes consistency; ``check_same_thread=False`` is set so the
  object can be used from the main thread and any future worker threads
  without re-creating the connection.

Performance notes
-----------------
* ``hashlib.sha256`` is used instead of a streaming approach only for
  files already bounded by ``max_file_size_mb`` (default 100 MB), so
  peak memory is acceptable.
* All SQL is prepared once as module-level constants and reused via
  parameter binding – no f-string SQL.
* ``conn.execute("PRAGMA journal_mode=WAL")`` improves concurrent
  read performance at negligible write cost.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, UTC
from pathlib import Path
from typing import NamedTuple

import structlog


log = structlog.get_logger()

# ── SQL statements ──────────────────────────────────────────────────────────

_DDL_FILES = """
CREATE TABLE IF NOT EXISTS file_cache (
    file_path     TEXT    NOT NULL PRIMARY KEY,
    content_hash  TEXT    NOT NULL,
    scan_time     TEXT    NOT NULL,
    finding_count INTEGER NOT NULL DEFAULT 0,
    rule_set_hash TEXT    NOT NULL
)
"""

_DDL_META = """
CREATE TABLE IF NOT EXISTS cache_meta (
    key   TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
)
"""

_UPSERT = """
INSERT INTO file_cache
    (file_path, content_hash, scan_time, finding_count, rule_set_hash)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(file_path) DO UPDATE SET
    content_hash  = excluded.content_hash,
    scan_time     = excluded.scan_time,
    finding_count = excluded.finding_count,
    rule_set_hash = excluded.rule_set_hash
"""

_SELECT = """
SELECT content_hash, finding_count, rule_set_hash
FROM file_cache
WHERE file_path = ?
"""

_DELETE_ALL = "DELETE FROM file_cache"

_UPSERT_META = """
INSERT INTO cache_meta (key, value) VALUES (?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value
"""

_SELECT_META = "SELECT value FROM cache_meta WHERE key = ?"

_STATS = "SELECT COUNT(*), SUM(finding_count) FROM file_cache"

_DETAILED_STATS = """
SELECT
    COUNT(*)                                          AS total_files,
    COALESCE(SUM(finding_count), 0)                  AS total_findings,
    COALESCE(SUM(CASE WHEN finding_count  > 0
                      THEN 1 ELSE 0 END), 0)         AS files_with_findings,
    COALESCE(SUM(CASE WHEN finding_count  = 0
                      THEN 1 ELSE 0 END), 0)         AS clean_files,
    COALESCE(MIN(scan_time), '')                      AS oldest_scan,
    COALESCE(MAX(scan_time), '')                      AS newest_scan
FROM file_cache
"""

_PRUNE = "DELETE FROM file_cache WHERE file_path = ?"


# ── Public types ─────────────────────────────────────────────────────────────

class CacheEntry(NamedTuple):
    """
    A cache hit returned by ``ScanCache.get_cached``.
    """
    content_hash: str
    finding_count: int
    rule_set_hash: str


# ── Helpers ──────────────────────────────────────────────────────────────────

def _compute_file_hash(path: Path) -> str | None:
    """
    Return the SHA-256 hex digest of *path*, or ``None`` on I/O error.

    Reads the file in 64 KiB chunks to bound memory usage regardless of
    file size (the caller already enforces max_file_size_mb, but defence
    in depth is cheap).
    """
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as exc:
        log.warning("cache_hash_failed", path=str(path), error=str(exc))
        return None


def compute_rule_set_hash(
    rule_ids: list[str],
    min_confidence: float,
) -> str:
    """
    Deterministically hash the active detection configuration.

    Sorting rule_ids ensures that rule registration order does not
    affect the hash.  min_confidence is included so that lowering the
    threshold (which would surface previously-suppressed findings)
    triggers a full cache invalidation.
    """
    payload = json.dumps(
        {
            "rules": sorted(rule_ids),
            "min_confidence": round(min_confidence, 6),
        },
        sort_keys=True,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


# ── Main class ───────────────────────────────────────────────────────────────

class ScanCache:
    """
    Persistent file-scan cache backed by SQLite.

    Usage::

        cache = ScanCache(
            db_path=Path(".dlp-scanner-cache.db"),
            rule_set_hash=compute_rule_set_hash(rule_ids, min_confidence),
        )

        # Before scanning a file:
        entry = cache.get_cached(path)
        if entry is not None:
            # file unchanged and rules unchanged → skip
            ...

        # After scanning a file:
        cache.set_cached(path, content_hash, finding_count)

        cache.close()

    Thread safety
    -------------
    The underlying ``sqlite3.Connection`` is created with
    ``check_same_thread=False`` so the same ``ScanCache`` instance can be
    used from a thread pool without re-creating the connection.  SQLite's
    serialised threading mode ensures that concurrent writes are safe.
    """

    def __init__(
        self,
        db_path: Path,
        rule_set_hash: str,
    ) -> None:
        self._db_path = db_path
        self._current_rule_set_hash = rule_set_hash
        self._conn = self._open(db_path)
        self._maybe_invalidate()

    # ── Lifecycle ────────────────────────────────────────────────────────────

    @staticmethod
    def _open(db_path: Path) -> sqlite3.Connection:
        """
        Open (or create) the SQLite database and initialise the schema.
        """
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(
            str(db_path),
            check_same_thread=False,
            isolation_level=None,   # autocommit; we use explicit transactions
        )
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(_DDL_FILES)
        conn.execute(_DDL_META)
        return conn

    def close(self) -> None:
        """
        Flush and close the underlying database connection.
        """
        try:
            self._conn.close()
        except Exception:
            pass

    def __enter__(self) -> "ScanCache":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ── Invalidation ─────────────────────────────────────────────────────────

    def _maybe_invalidate(self) -> None:
        """
        Drop all cached entries when the detection configuration has changed.

        The stored rule_set_hash is compared to the one supplied at
        construction time.  On mismatch the entire ``file_cache`` table is
        cleared and the new hash is written to ``cache_meta``.

        This is called once at startup, before any files are checked.
        """
        row = self._conn.execute(
            _SELECT_META, ("rule_set_hash",)
        ).fetchone()

        stored_hash = row[0] if row else None

        if stored_hash != self._current_rule_set_hash:
            log.info(
                "cache_invalidated",
                reason="rule_set_or_config_changed",
                old_hash=stored_hash,
                new_hash=self._current_rule_set_hash,
            )
            with self._conn:
                self._conn.execute(_DELETE_ALL)
                self._conn.execute(
                    _UPSERT_META,
                    ("rule_set_hash", self._current_rule_set_hash),
                )
        else:
            log.debug(
                "cache_valid",
                rule_set_hash=self._current_rule_set_hash,
            )

    def invalidate_all(self) -> None:
        """
        Unconditionally clear every cached entry (e.g. ``--no-cache``).

        The rule_set_hash metadata is *not* cleared so that the next
        normal run does not trigger an extra invalidation message.
        """
        with self._conn:
            self._conn.execute(_DELETE_ALL)
        log.info("cache_cleared", reason="explicit_invalidation")

    # ── Public cache API ─────────────────────────────────────────────────────

    def get_cached(self, path: Path) -> CacheEntry | None:
        """
        Return a ``CacheEntry`` if *path* can be skipped, otherwise ``None``.

        A cache hit requires **all** of the following:

        1. The path exists in ``file_cache``.
        2. The stored ``content_hash`` matches the current SHA-256 of the
           file on disk.
        3. The stored ``rule_set_hash`` matches the current configuration
           hash (belt-and-suspenders: this should already be guaranteed by
           ``_maybe_invalidate``, but we check per-entry to be safe when
           ``no_cache=True`` writes are mixed with normal runs).

        Returns ``None`` when the file should be (re-)scanned.
        """
        row = self._conn.execute(_SELECT, (str(path),)).fetchone()
        if row is None:
            return None

        stored_content_hash, finding_count, stored_rule_hash = row

        # Belt-and-suspenders: per-entry rule_set_hash guard.
        if stored_rule_hash != self._current_rule_set_hash:
            return None

        # Compute the current file hash to detect content changes.
        current_hash = _compute_file_hash(path)
        if current_hash is None or current_hash != stored_content_hash:
            return None

        return CacheEntry(
            content_hash=stored_content_hash,
            finding_count=finding_count,
            rule_set_hash=stored_rule_hash,
        )

    def set_cached(
        self,
        path: Path,
        content_hash: str,
        finding_count: int,
    ) -> None:
        """
        Persist a scan result for *path*.

        Called after every file scan (whether or not it produced findings),
        including when ``no_cache=True`` so that the next normal run benefits
        from the cache.
        """
        now = datetime.now(UTC).isoformat()
        with self._conn:
            self._conn.execute(
                _UPSERT,
                (
                    str(path),
                    content_hash,
                    now,
                    finding_count,
                    self._current_rule_set_hash,
                ),
            )

    def prune_missing(self, paths: list[Path]) -> int:
        """
        Remove cache entries whose paths no longer exist on disk.

        Returns the number of rows deleted.  Calling this at the end of a
        scan keeps the database compact and prevents stale entries from
        inflating ``stats()``.
        """
        deleted = 0
        with self._conn:
            for path in paths:
                if not path.exists():
                    self._conn.execute(_PRUNE, (str(path),))
                    deleted += self._conn.execute(
                        "SELECT changes()"
                    ).fetchone()[0]
        if deleted:
            log.debug("cache_pruned_missing_files", count=deleted)
        return deleted

    def stats(self) -> dict[str, int]:
        """
        Return aggregate statistics from the cache.

        Example::

            {"cached_files": 1024, "total_cached_findings": 37}
        """
        row = self._conn.execute(_STATS).fetchone()
        count, total_findings = row
        return {
            "cached_files": count or 0,
            "total_cached_findings": int(total_findings or 0),
        }
    
    def detailed_stats(self) -> dict[str, object]:
        """
        Return richer cache statistics for human-readable display.
 
        Keys
        ----
        total_files          : int   – rows in file_cache
        total_findings       : int   – sum of all finding_count values
        files_with_findings  : int   – rows where finding_count > 0
        clean_files          : int   – rows where finding_count == 0
        oldest_scan          : str   – ISO-8601 timestamp of the earliest
                                       cached scan, or '' if the cache is empty
        newest_scan          : str   – ISO-8601 timestamp of the most recent
                                       cached scan, or '' if the cache is empty
        db_size_bytes        : int   – size of the SQLite file on disk
        rule_set_hash_prefix : str   – first 12 hex chars of the stored
                                       rule_set_hash, or '' if not yet set
        """
        row = self._conn.execute(_DETAILED_STATS).fetchone()
        (
            total_files,
            total_findings,
            files_with_findings,
            clean_files,
            oldest_scan,
            newest_scan,
        ) = row
 
        try:
            db_size = self._db_path.stat().st_size
        except OSError:
            db_size = 0
 
        meta_row = self._conn.execute(
            _SELECT_META, ("rule_set_hash",)
        ).fetchone()
        rule_hash_prefix = (meta_row[0][:12] + "…") if meta_row else ""
 
        return {
            "total_files": int(total_files or 0),
            "total_findings": int(total_findings or 0),
            "files_with_findings": int(files_with_findings or 0),
            "clean_files": int(clean_files or 0),
            "oldest_scan": oldest_scan or "",
            "newest_scan": newest_scan or "",
            "db_size_bytes": db_size,
            "rule_set_hash_prefix": rule_hash_prefix,
        }
 
    @property
    def db_path(self) -> Path:
        """The filesystem path of the SQLite cache database."""
        return self._db_path

    # ── Convenience ──────────────────────────────────────────────────────────

    @staticmethod
    def compute_file_hash(path: Path) -> str | None:
        """
        Public wrapper around ``_compute_file_hash`` for callers that need
        the hash independently (e.g. ``FileScanner`` when writing back after
        scanning a file it hashed during the skip-check decision).
        """
        return _compute_file_hash(path)