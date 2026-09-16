#!/usr/bin/env python3
"""
©AngelaMos | 2026
compare.py

Compares the logistic regression model's session rankings against
the existing heuristic threat_score. Applies the trained model to
ALL exported sessions (labeled or not), ranks both scorers, and
reports Spearman rank correlation plus the sessions where the two
scorers disagree most (candidates for manual review or heuristic
weight tuning).
"""

import pickle
import sys

import pandas as pd
from scipy.stats import spearmanr

LABEL_ORDER = ["benign", "suspicious", "malicious"]
LABEL_TO_SCORE = {"benign": 0, "suspicious": 1, "malicious": 2}


def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "labels.csv"
    df = pd.read_csv(csv_path)

    with open("model.pkl", "rb") as f:
        bundle = pickle.load(f)
    model, scaler, features = (
        bundle["model"], bundle["scaler"], bundle["features"]
    )

    X = df[features].fillna(0)
    X_scaled = scaler.transform(X)

    proba = model.predict_proba(X_scaled)
    class_idx = {c: i for i, c in enumerate(model.classes_)}
    df["model_malicious_proba"] = proba[:, class_idx.get("malicious", -1)]
    df["model_prediction"] = model.predict(X_scaled)

    corr, pvalue = spearmanr(
        df["heuristic_threat_score"], df["model_malicious_proba"]
    )
    print(f"Spearman rank correlation (heuristic vs. model): "
          f"{corr:.3f} (p={pvalue:.4f})")
    print(f"  Interpretation: {'strong' if abs(corr) > 0.7 else 'moderate' if abs(corr) > 0.4 else 'weak'} "
          f"agreement between scorers on relative ordering.\n")

    df["heuristic_rank"] = df["heuristic_threat_score"].rank(ascending=False)
    df["model_rank"] = df["model_malicious_proba"].rank(ascending=False)
    df["rank_disagreement"] = (df["heuristic_rank"] - df["model_rank"]).abs()

    print("--- Top 10 disagreements (heuristic vs. model ranking) ---")
    cols = [
        "session_id", "label", "heuristic_threat_score",
        "model_malicious_proba", "model_prediction", "rank_disagreement",
    ]
    print(
        df.sort_values("rank_disagreement", ascending=False)[cols]
        .head(10)
        .to_string(index=False)
    )

    if "label" in df and df["label"].isin(LABEL_ORDER).any():
        labeled = df[df["label"].isin(LABEL_ORDER)].copy()
        labeled["label_ordinal"] = labeled["label"].map(LABEL_TO_SCORE)
        agree, _ = spearmanr(
            labeled["label_ordinal"], labeled["heuristic_threat_score"]
        )
        print(f"\nHeuristic vs. human label correlation: {agree:.3f}")
        agree_model, _ = spearmanr(
            labeled["label_ordinal"], labeled["model_malicious_proba"]
        )
        print(f"Model vs. human label correlation:     {agree_model:.3f}")


if __name__ == "__main__":
    main()