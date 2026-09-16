#!/usr/bin/env python3
"""
©AngelaMos | 2026
match_labels.py

Fills the `label` column in an exported sessions CSV by matching
each session to the closest manifest entry (same service_type,
nearest timestamp within a tolerance window). Sessions with no
manifest match within the window are left unlabeled.
"""

import sys
from datetime import datetime, timezone

import pandas as pd

TOLERANCE_SECONDS = 10


def parse_ts(value):
    dt = pd.to_datetime(value, utc=True)
    return dt.to_pydatetime()


def main():
    labels_path = sys.argv[1] if len(sys.argv) > 1 else "labels.csv"
    manifest_path = sys.argv[2] if len(sys.argv) > 2 else "manifest.csv"
    out_path = sys.argv[3] if len(sys.argv) > 3 else "labels.csv"

    sessions = pd.read_csv(labels_path)
    manifest = pd.read_csv(manifest_path)

    sessions["started_at_dt"] = sessions["started_at"].apply(parse_ts)
    manifest["timestamp_dt"] = manifest["timestamp"].apply(parse_ts)

    matched = 0
    for idx, row in sessions.iterrows():
        candidates = manifest[manifest["service"] == row["service_type"]]
        if candidates.empty:
            continue

        deltas = (candidates["timestamp_dt"] - row["started_at_dt"]).abs()
        best_idx = deltas.idxmin()
        best_delta = deltas.loc[best_idx].total_seconds()

        if best_delta <= TOLERANCE_SECONDS:
            sessions.at[idx, "label"] = manifest.at[best_idx, "label"]
            matched += 1

    sessions = sessions.drop(columns=["started_at_dt"])
    sessions.to_csv(out_path, index=False)

    print(f"Matched {matched}/{len(sessions)} sessions to manifest labels.")
    print(sessions["label"].value_counts(dropna=False))


if __name__ == "__main__":
    main()