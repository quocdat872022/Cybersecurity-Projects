#!/usr/bin/env python3
"""
©AngelaMos | 2026
train.py

Trains a multinomial logistic regression classifier on manually
labeled honeypot sessions (benign / suspicious / malicious) using
engineered features, then reports classification performance and
saves the fitted model + feature scaler for use by compare.py.
"""

import pickle
import sys

import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

FEATURE_COLUMNS = [
    "command_count",
    "unique_commands",
    "duration_seconds",
    "auth_attempts",
    "mitre_technique_count",
    "mean_command_gap",
    "std_command_gap",
    "has_tool_transfer",
    "has_persistence",
    "login_success",
]

LABEL_ORDER = ["benign", "suspicious", "malicious"]


def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "labels.csv"
    df = pd.read_csv(csv_path)

    labeled = df[df["label"].isin(LABEL_ORDER)].copy()
    if len(labeled) < 20:
        print(
            f"Only {len(labeled)} labeled rows found; label at least "
            "50 sessions in labels.csv before training.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"Training on {len(labeled)} labeled sessions "
          f"({labeled['label'].value_counts().to_dict()})")

    X = labeled[FEATURE_COLUMNS].fillna(0)
    y = labeled["label"]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.25, random_state=42, stratify=y
        if labeled["label"].value_counts().min() >= 2 else None,
    )

    model = LogisticRegression(
        multi_class="multinomial",
        max_iter=1000,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\n--- Classification report (held-out test set) ---")
    print(classification_report(y_test, y_pred, zero_division=0))

    print("--- Feature coefficients (per class, standardized scale) ---")
    coef_df = pd.DataFrame(
        model.coef_, columns=FEATURE_COLUMNS, index=model.classes_
    )
    print(coef_df.round(3).to_string())

    with open("model.pkl", "wb") as f:
        pickle.dump({"model": model, "scaler": scaler,
                     "features": FEATURE_COLUMNS}, f)

    print("\nSaved model.pkl")


if __name__ == "__main__":
    main()