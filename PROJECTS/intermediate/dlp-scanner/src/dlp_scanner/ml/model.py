"""
©AngelaMos | 2026
model.py

Dependency-free online logistic regression for false-positive detection.

Why not scikit-learn + ONNX? The feature space is tiny (8 numeric
features plus hashed categoricals) and the training sets are hundreds to
a few thousand analyst labels. Pure Python trains in well under a second
and keeps the scanner's install footprint unchanged. The model is exposed
through ``predict_proba`` / ``fit`` / ``partial_fit``, so swapping in a
scikit-learn estimator later only touches this module.

Target: y = 1 means "false positive". Class weights make a wrongly
demoted true positive cost more than a missed false positive.
"""


from __future__ import annotations

import hashlib
import math
import random
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from dlp_scanner.constants import FP_HASH_BUCKETS, FP_TP_CLASS_WEIGHT


CATEGORICAL_FEATURES: tuple[str, ...] = (
    "rule_id",
    "source_type",
    "extension",
    "file_category",
)
N_NUMERIC: int = 8
DIM: int = N_NUMERIC + FP_HASH_BUCKETS
MODEL_VERSION: int = 1

SparseVector = dict[int, float]
Example = tuple[dict[str, Any], bool]  # (features, is_false_positive)
LabeledExample = tuple[str, dict[str, Any], bool]  # (finding_id, ...)


def _num(features: dict[str, Any], key: str) -> float:
    try:
        return float(features.get(key) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _bucket(token: str) -> int:
    digest = hashlib.md5(token.encode(), usedforsecurity = False).digest()
    return N_NUMERIC + int.from_bytes(digest[: 4], "big") % FP_HASH_BUCKETS


def vectorize(features: dict[str, Any]) -> SparseVector:
    """
    Turn a feature dict into a sparse vector (numeric + hashed one-hot)
    """
    x: SparseVector = {
        0: min(max(_num(features, "confidence"), 0.0), 1.0),
        1: min(_num(features, "context_keyword_hits"), 3.0) / 3.0,
        2: min(_num(features, "cooccurrence_count"), 5.0) / 5.0,
        3: min(_num(features, "snippet_entropy") / 8.0, 1.0),
        4: min(_num(features, "snippet_length") / 100.0, 1.0),
        5: min(max(_num(features, "digit_ratio"), 0.0), 1.0),
        6: 1.0 if _num(features, "has_column_signal") else 0.0,
        7: min(_num(features, "framework_count"), 4.0) / 4.0,
    }
    for name in CATEGORICAL_FEATURES:
        value = features.get(name)
        if value in (None, ""):
            continue
        idx = _bucket(f"{name}={value}")
        x[idx] = x.get(idx, 0.0) + 1.0
    return x


def _sigmoid(z: float) -> float:
    z = max(-30.0, min(30.0, z))
    return 1.0 / (1.0 + math.exp(-z))


@dataclass
class FPModel:
    """
    Logistic regression over ``vectorize`` output
    """
    weights: list[float] = field(default_factory = lambda: [0.0] * DIM)
    bias: float = 0.0
    n_seen: int = 0

    def _proba(self, x: SparseVector) -> float:
        z = self.bias + sum(self.weights[i] * v for i, v in x.items())
        return _sigmoid(z)

    def predict_proba(self, features: dict[str, Any]) -> float:
        """
        Probability that the finding is a false positive
        """
        return self._proba(vectorize(features))

    def _step(
        self,
        x: SparseVector,
        is_fp: bool,
        lr: float,
        l2: float,
    ) -> None:
        y = 1.0 if is_fp else 0.0
        weight = 1.0 if is_fp else FP_TP_CLASS_WEIGHT
        err = (self._proba(x) - y) * weight
        for i, v in x.items():
            self.weights[i] -= lr * (err * v + l2 * self.weights[i])
        self.bias -= lr * err

    def partial_fit(
        self,
        features: dict[str, Any],
        is_false_positive: bool,
        lr: float = 0.05,
        l2: float = 1e-4,
    ) -> None:
        """
        Online update from a single new label (no retraining)
        """
        self._step(vectorize(features), is_false_positive, lr, l2)
        self.n_seen += 1

    def fit(
        self,
        examples: Sequence[Example],
        *,
        epochs: int = 60,
        lr: float = 0.1,
        l2: float = 1e-4,
        seed: int = 7,
    ) -> None:
        """
        Train from scratch with SGD and a decaying learning rate
        """
        self.weights = [0.0] * DIM
        self.bias = 0.0
        self.n_seen = 0

        data = [(vectorize(f), y) for f, y in examples]
        rng = random.Random(seed)  # noqa: S311
        for epoch in range(epochs):
            rng.shuffle(data)
            rate = lr / (1.0 + 0.05 * epoch)
            for x, y in data:
                self._step(x, y, rate, l2)
        self.n_seen = len(data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": MODEL_VERSION,
            "dim": DIM,
            "weights": [round(w, 6) for w in self.weights],
            "bias": round(self.bias, 6),
            "n_seen": self.n_seen,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FPModel:
        if data.get("version") != MODEL_VERSION or data.get("dim") != DIM:
            raise ValueError("Incompatible model; retrain required")
        return cls(
            weights = [float(w) for w in data["weights"]],
            bias = float(data["bias"]),
            n_seen = int(data.get("n_seen", 0)),
        )


@dataclass(frozen = True)
class EvaluationReport:
    """
    Held-out evaluation of the demotion policy
    """
    train_size: int
    test_size: int
    fp_total: int
    fp_demoted: int
    tp_total: int
    tp_demoted: int
    note: str = ""

    @property
    def fp_reduction(self) -> float:
        """
        Share of false positives the filter moves out of the main list
        """
        return self.fp_demoted / self.fp_total if self.fp_total else 0.0

    @property
    def tp_recall(self) -> float:
        """
        Share of true positives that stay in the main list
        """
        if not self.tp_total:
            return 0.0
        return (self.tp_total - self.tp_demoted) / self.tp_total


def _is_holdout(finding_id: str) -> bool:
    digest = hashlib.md5(finding_id.encode(), usedforsecurity = False)
    return int(digest.hexdigest()[: 8], 16) % 5 == 0


def evaluate_holdout(
    examples: Sequence[LabeledExample],
    threshold: float,
) -> EvaluationReport:
    """
    Train on ~80% (deterministic split by finding_id), score the other 20%
    """
    train: list[Example] = []
    test: list[Example] = []
    for fid, feats, is_fp in examples:
        (test if _is_holdout(fid) else train).append((feats, is_fp))

    if len({y for _, y in train}) < 2 or not test:
        return EvaluationReport(
            len(train), len(test), 0, 0, 0, 0,
            note = "Not enough labeled data of both classes to evaluate",
        )

    model = FPModel()
    model.fit(train)

    fp_total = fp_demoted = tp_total = tp_demoted = 0
    for feats, is_fp in test:
        demoted = model.predict_proba(feats) >= threshold
        if is_fp:
            fp_total += 1
            fp_demoted += int(demoted)
        else:
            tp_total += 1
            tp_demoted += int(demoted)

    return EvaluationReport(
        len(train), len(test), fp_total, fp_demoted, tp_total, tp_demoted
    )