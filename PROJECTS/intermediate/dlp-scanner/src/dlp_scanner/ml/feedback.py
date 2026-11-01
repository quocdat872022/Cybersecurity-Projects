"""
©AngelaMos | 2026
feedback.py

Ties the pieces together:

  * ``FeedbackManager``      Phase 1+2: record labels, train / retrain
  * ``FalsePositiveFilter``  Phase 3:   demote likely false positives

Training policy
---------------
* Nothing trains until there are FP_MIN_TRAIN_EXAMPLES labels with at
  least FP_MIN_PER_CLASS of each class.
* A full retrain from scratch runs when the label count first crosses
  50, 100, 500, 1000 (then every further 1000), or when an analyst flips
  an earlier label.
* Every other new label is folded in with a cheap online update.

Safety policy
-------------
* The filter NEVER removes a finding. It lowers severity, sets
  ``suppressed = True`` and keeps ``original_severity`` so reporters can
  show a separate, auditable "suppressed" section.
* Confidence is never modified.
"""


from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import structlog

from dlp_scanner.config import FalsePositiveConfig
from dlp_scanner.constants import (
    FEEDBACK_DB_FILENAME,
    FP_MIN_PER_CLASS,
    FP_MIN_TRAIN_EXAMPLES,
    FP_RETRAIN_INTERVAL,
    FP_RETRAIN_THRESHOLDS,
    SEVERITY_ORDER,
    Severity,
)
from dlp_scanner.ml.features import cooccurrence_counts, extract_features
from dlp_scanner.ml.model import EvaluationReport, FPModel, evaluate_holdout
from dlp_scanner.ml.store import LABEL_FP, LABEL_TP, FeedbackStore
from dlp_scanner.models import Finding, ScanResult


log = structlog.get_logger()

META_MODEL = "model"
META_LAST_RETRAIN = "last_retrain_total"


def default_feedback_db_path() -> Path:
    """
    Next to the config file if present, otherwise the working directory
    """
    for candidate in (Path(".dlp-scanner.yml"), Path(".dlp-scanner.yaml")):
        if candidate.exists():
            return candidate.parent / FEEDBACK_DB_FILENAME
    return Path(FEEDBACK_DB_FILENAME)


def due_threshold(total: int, last_retrain: int) -> int | None:
    """
    Highest retrain milestone reached since the last retrain, if any
    """
    candidates = [t for t in FP_RETRAIN_THRESHOLDS if last_retrain < t <= total]
    top = FP_RETRAIN_THRESHOLDS[-1]
    candidates += [
        t for t in range(top + FP_RETRAIN_INTERVAL, total + 1,
                         FP_RETRAIN_INTERVAL) if t > last_retrain
    ]
    return max(candidates) if candidates else None


def demote(severity: Severity, levels: int) -> Severity:
    """
    Lower a severity by N levels, never below 'low'
    """
    ranked: list[Severity] = sorted(SEVERITY_ORDER, key = SEVERITY_ORDER.get)  # type: ignore[arg-type]
    idx = min(len(ranked) - 1, ranked.index(severity) + levels)
    return ranked[idx]


@dataclass(frozen = True)
class FeedbackOutcome:
    """
    What happened when a label was submitted
    """
    total: int
    true_positives: int
    false_positives: int
    action: str  # stored | online_update | retrained
    detail: str = ""


class FeedbackManager:
    """
    Records analyst labels and keeps the model up to date
    """
    def __init__(self, store: FeedbackStore) -> None:
        self._store = store

    def load_model(self) -> FPModel | None:
        raw = self._store.get_meta(META_MODEL)
        if not raw:
            return None
        try:
            return FPModel.from_dict(json.loads(raw))
        except (ValueError, KeyError, TypeError):
            log.warning("fp_model_unreadable")
            return None

    def _save_model(self, model: FPModel) -> None:
        self._store.set_meta(META_MODEL, json.dumps(model.to_dict()))

    def retrain(self) -> tuple[bool, str]:
        """
        Full retrain from every stored label
        """
        examples = self._store.examples()
        n_fp = sum(1 for _, _, y in examples if y)
        n_tp = len(examples) - n_fp

        if len(examples) < FP_MIN_TRAIN_EXAMPLES:
            return False, (
                f"need {FP_MIN_TRAIN_EXAMPLES} labels, have {len(examples)}"
            )
        if min(n_fp, n_tp) < FP_MIN_PER_CLASS:
            return False, (
                f"need >= {FP_MIN_PER_CLASS} of each class "
                f"(TP={n_tp}, FP={n_fp})"
            )

        model = FPModel()
        model.fit([(f, y) for _, f, y in examples])
        self._save_model(model)
        log.info("fp_model_retrained", examples = len(examples))
        return True, f"trained on {len(examples)} labels"

    def submit(
        self,
        finding: Finding,
        *,
        is_false_positive: bool,
        cooccurrence: int = 0,
    ) -> FeedbackOutcome:
        """
        Store a label, then retrain or update online as policy dictates
        """
        label = LABEL_FP if is_false_positive else LABEL_TP
        features = extract_features(finding, cooccurrence)
        previous = self._store.upsert(
            finding.finding_id, finding.rule_id, features, label
        )

        counts = self._store.counts()
        total = counts[LABEL_TP] + counts[LABEL_FP]
        last = int(self._store.get_meta(META_LAST_RETRAIN) or 0)
        due = due_threshold(total, last)
        model = self.load_model()
        relabeled = previous is not None and previous != label

        def outcome(action: str, detail: str = "") -> FeedbackOutcome:
            return FeedbackOutcome(
                total, counts[LABEL_TP], counts[LABEL_FP], action, detail
            )

        if due is not None or (relabeled and model is not None):
            trained, detail = self.retrain()
            if trained and due is not None:
                self._store.set_meta(META_LAST_RETRAIN, str(due))
            return outcome("retrained" if trained else "stored", detail)

        if model is not None and previous is None:
            model.partial_fit(features, is_false_positive)
            self._save_model(model)
            return outcome("online_update")

        return outcome("stored")

    def evaluate(self, threshold: float) -> EvaluationReport:
        return evaluate_holdout(self._store.examples(), threshold)


class FalsePositiveFilter:
    """
    Post-filter: demotes (never deletes) likely false positives
    """
    def __init__(self, config: FalsePositiveConfig) -> None:
        self._threshold = config.suppress_threshold
        self._levels = config.demote_levels
        self._model: FPModel | None = None

        db_path = (
            Path(config.db_path) if config.db_path
            else default_feedback_db_path()
        )
        if config.enabled and db_path.exists():
            with FeedbackStore(db_path) as store:
                self._model = FeedbackManager(store).load_model()
        log.debug(
            "fp_filter_ready",
            active = self._model is not None,
            db = str(db_path),
        )

    @property
    def ready(self) -> bool:
        return self._model is not None

    def apply(self, result: ScanResult) -> int:
        """
        Score every finding; demote those above the threshold.
        Returns the number of findings demoted.
        """
        if self._model is None or not result.findings:
            return 0

        cooc = cooccurrence_counts(result.findings)
        demoted = 0
        for f in result.findings:
            if f.suppressed:
                continue
            p = self._model.predict_proba(
                extract_features(f, cooc.get(f.finding_id, 0))
            )
            f.fp_probability = round(p, 4)
            if p >= self._threshold:
                f.original_severity = f.severity
                f.severity = demote(f.severity, self._levels)
                f.suppressed = True
                demoted += 1

        log.info("fp_filter_applied", demoted = demoted,
                 total = len(result.findings))
        return demoted