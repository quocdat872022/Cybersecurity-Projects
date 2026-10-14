"""
©AngelaMos | 2026
test_method_anomaly.py

Tests the METHOD_ANOMALY threshold rule (Challenge 2: Add
Request Method Anomaly Detection) added to the rule engine

Validates that method_entropy_5m above 1.5 fires
METHOD_ANOMALY at 0.30 score, that entropy at or below the
threshold does not fire it, that it stacks with other
matched rules via the boost mechanism, and that it doesn't
fire on windowed feature dicts missing the key entirely
(defensive default handling).

Connects to:
  core/detection/rules - RuleEngine, METHOD_ANOMALY rule
"""

from datetime import datetime, UTC

from app.core.detection.rules import RuleEngine
from app.core.ingestion.parsers import ParsedLogEntry


def _make_entry(
    path: str = "/api/v1/users",
    query_string: str = "",
    method: str = "GET",
) -> ParsedLogEntry:
    """
    Build a ParsedLogEntry with sensible defaults for rule engine testing.
    """
    return ParsedLogEntry(
        ip="93.184.216.34",
        timestamp=datetime(2026, 2, 11, 14, 30, 0, tzinfo=UTC),
        method=method,
        path=path,
        query_string=query_string,
        status_code=200,
        response_size=1234,
        referer="",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        raw_line="",
    )


def _windowed(method_entropy_5m: float = 0.0) -> dict[str, float]:
    """
    Windowed features for a quiet IP with a configurable method entropy.
    """
    return {
        "req_count_1m": 1.0,
        "req_count_5m": 3.0,
        "req_count_10m": 5.0,
        "error_rate_5m": 0.0,
        "unique_paths_5m": 2.0,
        "unique_uas_10m": 1.0,
        "method_entropy_5m": method_entropy_5m,
        "avg_response_size_5m": 1024.0,
        "status_diversity_5m": 1.0,
        "path_depth_variance_5m": 0.0,
        "inter_request_time_mean": 5000.0,
        "inter_request_time_std": 1000.0,
    }


ENGINE = RuleEngine()


def test_high_method_entropy_fires_rule() -> None:
    """
    method_entropy_5m above 1.5 fires METHOD_ANOMALY with score 0.30.
    """
    result = ENGINE.score_request(_windowed(method_entropy_5m=2.0), _make_entry())
    assert "METHOD_ANOMALY" in result.matched_rules
    assert result.component_scores["METHOD_ANOMALY"] == 0.30
    assert result.threat_score > 0.0


def test_low_method_entropy_does_not_fire() -> None:
    """
    method_entropy_5m at or below 1.5 does not fire METHOD_ANOMALY.
    """
    at_threshold = ENGINE.score_request(
        _windowed(method_entropy_5m=1.5), _make_entry())
    below_threshold = ENGINE.score_request(
        _windowed(method_entropy_5m=0.9), _make_entry())

    assert "METHOD_ANOMALY" not in at_threshold.matched_rules
    assert "METHOD_ANOMALY" not in below_threshold.matched_rules


def test_normal_get_heavy_traffic_is_low_severity() -> None:
    """
    A quiet IP with low method entropy stays LOW severity overall.
    """
    result = ENGINE.score_request(_windowed(method_entropy_5m=0.1), _make_entry())
    assert result.severity == "LOW"
    assert result.matched_rules == []


def test_method_anomaly_stacks_with_other_rules() -> None:
    """
    METHOD_ANOMALY combines with a pattern rule match via the boost mechanism.
    """
    entry = _make_entry(path="/users", query_string="id=1' OR 1=1--")

    sqli_only = ENGINE.score_request(_windowed(method_entropy_5m=0.0), entry)
    combined = ENGINE.score_request(_windowed(method_entropy_5m=2.0), entry)

    assert combined.threat_score > sqli_only.threat_score
    assert "METHOD_ANOMALY" in combined.matched_rules
    assert "SQL_INJECTION" in combined.matched_rules


def test_missing_feature_key_does_not_crash() -> None:
    """
    A windowed feature dict missing method_entropy_5m defaults safely
    and does not fire the rule.
    """
    windowed = _windowed()
    del windowed["method_entropy_5m"]
    result = ENGINE.score_request(windowed, _make_entry())
    assert "METHOD_ANOMALY" not in result.matched_rules