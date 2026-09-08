"""Preprocess an IoT network-intrusion CSV for AI models."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

LABEL_NAMES = ("is_attack", "attack", "label", "class", "category")
TYPE_NAMES = ("attack_type", "attack_category", "attack_name", "class_name")
RISK_NAMES = ("risk_score", "risk", "severity", "confidence")
IDENTIFIER_PARTS = ("id", "ip", "address", "timestamp", "time", "date", "uuid", "name")
TEXT_PARTS = ("protocol", "service", "state", "flag", "method", "path", "device_type")


def find_column(columns: list[str], names: tuple[str, ...]) -> str | None:
    normalized = {str(column).strip().lower().replace(" ", "_"): column for column in columns}
    for name in names:
        if name in normalized:
            return normalized[name]
    return None


def preprocess(dataset: str | Path, output: str | Path, limit: int | None = None) -> dict[str, object]:
    frame = pd.read_csv(dataset, nrows=limit)
    columns = list(frame.columns)
    attack_column = find_column(columns, LABEL_NAMES)
    type_column = find_column(columns, TYPE_NAMES)
    risk_column = find_column(columns, RISK_NAMES)

    numeric_columns = frame.select_dtypes(include=["number"]).columns.tolist()
    excluded = {column for column in (attack_column, risk_column) if column}
    feature_columns = [column for column in numeric_columns if column not in excluded]

    # Remove identifier-like numeric fields that would cause the model to
    # memorize records instead of learning traffic behavior.
    feature_columns = [
        column for column in feature_columns
        if not any(part in str(column).lower() for part in IDENTIFIER_PARTS)
    ]
    if not feature_columns:
        raise ValueError("No usable numeric network-flow features were found.")

    features = frame[feature_columns].apply(pd.to_numeric, errors="coerce")
    features = features.replace([np.inf, -np.inf], np.nan)
    medians = features.median().fillna(0)
    features = features.fillna(medians)
    means = features.mean()
    stds = features.std().replace(0, 1).fillna(1)
    scaled = ((features - means) / stds).astype(np.float32)

    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    scaled.to_csv(output_path / "network_features.csv", index=False)

    if attack_column:
        frame[attack_column].fillna(0).to_csv(output_path / "is_attack.csv", index=False, header=["is_attack"])
    if type_column:
        frame[type_column].fillna("unknown").astype(str).to_csv(output_path / "attack_type.csv", index=False, header=["attack_type"])
    if risk_column:
        pd.to_numeric(frame[risk_column], errors="coerce").fillna(0).to_csv(output_path / "risk_score.csv", index=False, header=["risk_score"])

    metadata = {
        "source": str(Path(dataset).resolve()),
        "rows": len(frame),
        "feature_columns": feature_columns,
        "attack_column": attack_column,
        "attack_type_column": type_column,
        "risk_column": risk_column,
        "feature_count": len(feature_columns),
        "outputs": ["network_features.csv", "is_attack.csv", "attack_type.csv", "risk_score.csv"],
        "means": means.to_dict(),
        "stds": stds.to_dict(),
    }
    (output_path / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description="Preprocess IoT network intrusion data")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--output", default="processed_network")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()
    print(json.dumps(preprocess(args.dataset, args.output, args.limit), indent=2))


if __name__ == "__main__":
    main()
