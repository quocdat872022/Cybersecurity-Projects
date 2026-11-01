"""
©AngelaMos | 2026
store.py

SQLite persistence for analyst feedback and the trained model.

    feedback(finding_id, rule_id, features_json, label, timestamp)
    meta(key, value)   -- model JSON, last retrain threshold
"""


from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dlp_scanner.models import Finding  # noqa: F401  (type context)

LABEL_TP = "true_positive"
LABEL_FP = "false_positive"

_DDL = (
    """
    CREATE TABLE IF NOT EXISTS feedback (
        finding_id    TEXT PRIMARY KEY,
        rule_id       TEXT NOT NULL,
        features_json TEXT NOT NULL,
        label         TEXT NOT NULL
            CHECK (label IN ('true_positive', 'false_positive')),
        timestamp     TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
)


class FeedbackStore:
    """
    Thin wrapper over the feedback database
    """
    def __init__(self, db_path: Path) -> None:
        self._path = db_path
        db_path.parent.mkdir(parents = True, exist_ok = True)
        self._conn = sqlite3.connect(str(db_path))
        for ddl in _DDL:
            self._conn.execute(ddl)
        self._conn.commit()

    def __enter__(self) -> FeedbackStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    @property
    def path(self) -> Path:
        return self._path

    def upsert(
        self,
        finding_id: str,
        rule_id: str,
        features: dict[str, Any],
        label: str,
    ) -> str | None:
        """
        Store a label. Returns the previous label if one existed
        (so callers can detect an analyst changing their mind)
        """
        row = self._conn.execute(
            "SELECT label FROM feedback WHERE finding_id = ?",
            (finding_id, ),
        ).fetchone()
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO feedback VALUES (?, ?, ?, ?, ?)",
                (
                    finding_id,
                    rule_id,
                    json.dumps(features, sort_keys = True),
                    label,
                    datetime.now(UTC).isoformat(),
                ),
            )
        return row[0] if row else None

    def counts(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT label, COUNT(*) FROM feedback GROUP BY label"
        ).fetchall()
        out = {LABEL_TP: 0, LABEL_FP: 0}
        out.update({label: n for label, n in rows})
        return out

    def examples(self) -> list[tuple[str, dict[str, Any], bool]]:
        rows = self._conn.execute(
            "SELECT finding_id, features_json, label FROM feedback "
            "ORDER BY timestamp"
        ).fetchall()
        return [(fid, json.loads(fj), label == LABEL_FP)
                for fid, fj, label in rows]

    def get_meta(self, key: str) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = ?", (key, )
        ).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, value)
            )