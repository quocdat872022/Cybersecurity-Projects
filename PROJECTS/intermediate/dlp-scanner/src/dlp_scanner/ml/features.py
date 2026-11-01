"""
©AngelaMos | 2026
features.py

Feature extraction for the false-positive classifier.

Features are derived from a finished ``Finding`` (plus a little
scan-level context) so that analyst feedback given against a saved JSON
report can be turned into training data without re-running the scan.

Severity is deliberately NOT a feature: the classifier demotes severity,
so using it as an input would create a feedback loop. Confidence already
encodes the checksum, context-keyword and co-occurrence boosts.
"""


from __future__ import annotations

import functools
from collections.abc import Iterable
from pathlib import PurePath
from typing import Any

from dlp_scanner.detectors.entropy import shannon_entropy_str
from dlp_scanner.models import Finding


_CATEGORY_EXTENSIONS: dict[str, frozenset[str]] = {
    "structured": frozenset(
        {".csv", ".tsv", ".json", ".xml", ".yaml", ".yml", ".parquet", ".avro"}
    ),
    "office": frozenset({".pdf", ".docx", ".xlsx", ".xls"}),
    "text": frozenset({".txt", ".log", ".md", ".rst", ".html", ".htm"}),
    "code": frozenset(
        {
            ".py", ".js", ".ts", ".go", ".rb", ".java", ".c", ".cpp",
            ".h", ".hpp", ".rs", ".sh", ".bat", ".ps1",
        }
    ),
    "config": frozenset(
        {".cfg", ".ini", ".conf", ".toml", ".env", ".tf", ".hcl"}
    ),
    "email": frozenset({".eml", ".msg"}),
    "archive": frozenset({".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2"}),
}

_EXT_TO_CATEGORY: dict[str, str] = {
    ext: category
    for category, exts in _CATEGORY_EXTENSIONS.items()
    for ext in exts
}


def file_extension(uri: str) -> str:
    """
    Extension of the scanned file, resolving archive members
    (``a.zip!b.log`` -> ``.log``) and compound tar suffixes
    """
    target = uri.rsplit("!", 1)[-1]
    name = PurePath(target).name.lower()
    if name.endswith(".tar.gz"):
        return ".tar.gz"
    if name.endswith(".tar.bz2"):
        return ".tar.bz2"
    return PurePath(name).suffix


@functools.lru_cache(maxsize=1)
def _rule_keywords() -> dict[str, tuple[str, ...]]:
    """
    Context keywords per built-in rule (lazy import avoids a cycle)
    """
    from dlp_scanner.detectors.registry import ALL_RULES

    return {
        r.rule_id: tuple(k.lower() for k in r.context_keywords)
        for r in ALL_RULES
    }


def cooccurrence_counts(findings: Iterable[Finding]) -> dict[str, int]:
    """
    For each finding, how many OTHER rule types were found in the same
    file / table. Mirrors the scanner's co-occurrence boost.
    """
    items = list(findings)
    groups: dict[tuple[str, str | None], set[str]] = {}
    for f in items:
        key = (f.location.uri, f.location.table_name)
        groups.setdefault(key, set()).add(f.rule_id)

    return {
        f.finding_id: len(groups[(f.location.uri, f.location.table_name)]) - 1
        for f in items
    }


def extract_features(
    finding: Finding,
    cooccurrence: int = 0,
) -> dict[str, Any]:
    """
    Build a JSON-serializable feature dict for one finding
    """
    snippet = finding.redacted_snippet or ""
    lowered = snippet.lower()
    keywords = _rule_keywords().get(finding.rule_id, ())
    keyword_hits = sum(1 for k in keywords if k in lowered)
    digits = sum(1 for c in snippet if c.isdigit())

    ext = (
        file_extension(finding.location.uri)
        if finding.location.source_type == "file" else ""
    )

    return {
        "rule_id": finding.rule_id,
        "source_type": finding.location.source_type,
        "extension": ext,
        "file_category": _EXT_TO_CATEGORY.get(ext, "other"),
        "confidence": round(finding.confidence, 4),
        "context_keyword_hits": keyword_hits,
        "cooccurrence_count": cooccurrence,
        "snippet_entropy": (
            round(shannon_entropy_str(snippet), 4) if snippet else 0.0
        ),
        "snippet_length": len(snippet),
        "digit_ratio": round(digits / len(snippet), 4) if snippet else 0.0,
        "has_column_signal": int(finding.column_signal is not None),
        "framework_count": len(finding.compliance_frameworks),
    }