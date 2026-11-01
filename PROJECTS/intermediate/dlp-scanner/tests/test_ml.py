"""
©AngelaMos | 2026
test_ml.py
"""


import random
from pathlib import Path

import pytest

from dlp_scanner.config import FalsePositiveConfig
from dlp_scanner.ml.features import (
    cooccurrence_counts,
    extract_features,
    file_extension,
)
from dlp_scanner.ml.feedback import (
    FalsePositiveFilter,
    FeedbackManager,
    demote,
    due_threshold,
)
from dlp_scanner.ml.store import FeedbackStore
from dlp_scanner.models import Finding, Location, ScanResult


pytestmark = pytest.mark.unit


def _finding(i: int, is_fp: bool) -> Finding:
    rng = random.Random(i)  # noqa: S311
    if is_fp:
        return Finding(
            finding_id = f"f{i:04d}",
            rule_id = "PII_SSN",
            rule_name = "US Social Security Number",
            severity = "medium",
            confidence = 0.2 + rng.random() * 0.25,
            location = Location("file", f"/build/out_{i}.log"),
            redacted_snippet = "...serial ***-**-7890 batch...",
        )
    return Finding(
        finding_id = f"f{i:04d}",
        rule_id = "PII_SSN",
        rule_name = "US Social Security Number",
        severity = "critical",
        confidence = 0.8 + rng.random() * 0.2,
        location = Location("file", f"/hr/emp_{i}.csv"),
        redacted_snippet = "...SSN: ***-**-7890 on file...",
        compliance_frameworks = ["HIPAA", "GDPR"],
    )


def _train(store: FeedbackStore, n: int) -> FeedbackManager:
    manager = FeedbackManager(store)
    for i in range(n):
        manager.submit(_finding(i, is_fp = i % 2 == 0),
                       is_false_positive = i % 2 == 0)
    return manager


class TestFeatures:
    def test_extension_resolves_archive_member(self) -> None:
        assert file_extension("/a/b.zip!inner/x.LOG") == ".log"
        assert file_extension("/a/b.tar.gz") == ".tar.gz"

    def test_feature_values(self) -> None:
        feats = extract_features(_finding(1, is_fp = False), cooccurrence = 2)
        assert feats["extension"] == ".csv"
        assert feats["file_category"] == "structured"
        assert feats["context_keyword_hits"] >= 1
        assert feats["cooccurrence_count"] == 2
        assert feats["framework_count"] == 2

    def test_cooccurrence_counts_other_rules_only(self) -> None:
        a = _finding(1, False)
        b = _finding(2, False)
        b.rule_id = "PII_EMAIL"
        b.location = a.location
        counts = cooccurrence_counts([a, b])
        assert counts[a.finding_id] == 1


class TestPolicy:
    def test_due_threshold(self) -> None:
        assert due_threshold(49, 0) is None
        assert due_threshold(50, 0) == 50
        assert due_threshold(120, 50) == 100
        assert due_threshold(1500, 1000) is None
        assert due_threshold(2000, 1000) == 2000

    def test_demote_never_below_low(self) -> None:
        assert demote("critical", 2) == "medium"
        assert demote("low", 2) == "low"


class TestTraining:
    def test_no_model_below_minimum(self, tmp_path: Path) -> None:
        with FeedbackStore(tmp_path / "fb.db") as store:
            manager = _train(store, 20)
            assert manager.load_model() is None

    def test_trains_at_threshold_and_updates_online(
        self, tmp_path: Path
    ) -> None:
        with FeedbackStore(tmp_path / "fb.db") as store:
            manager = _train(store, 60)
            model = manager.load_model()
            assert model is not None
            out = manager.submit(_finding(999, True), is_false_positive = True)
            assert out.action == "online_update"

    def test_relabel_triggers_retrain(self, tmp_path: Path) -> None:
        with FeedbackStore(tmp_path / "fb.db") as store:
            manager = _train(store, 60)
            out = manager.submit(_finding(0, True), is_false_positive = False)
            assert out.action == "retrained"
            assert out.total == 60

    def test_holdout_evaluation(self, tmp_path: Path) -> None:
        with FeedbackStore(tmp_path / "fb.db") as store:
            manager = _train(store, 200)
            report = manager.evaluate(threshold = 0.8)
            assert report.fp_reduction >= 0.30
            assert report.tp_recall >= 0.90


class TestFilter:
    def test_demotes_but_never_removes(self, tmp_path: Path) -> None:
        db = tmp_path / "fb.db"
        with FeedbackStore(db) as store:
            _train(store, 100)

        flt = FalsePositiveFilter(FalsePositiveConfig(db_path = str(db)))
        assert flt.ready

        fp, tp = _finding(5001, True), _finding(5002, False)
        result = ScanResult(findings = [fp, tp])
        demoted = flt.apply(result)

        assert len(result.findings) == 2
        assert demoted == 1
        assert fp.suppressed and fp.original_severity == "medium"
        assert fp.severity == "low"
        assert not tp.suppressed and tp.severity == "critical"
        assert result.suppressed_findings == [fp]

    def test_inactive_without_database(self, tmp_path: Path) -> None:
        cfg = FalsePositiveConfig(db_path = str(tmp_path / "missing.db"))
        flt = FalsePositiveFilter(cfg)
        result = ScanResult(findings = [_finding(1, True)])
        assert flt.apply(result) == 0
        assert not result.findings[0].suppressed