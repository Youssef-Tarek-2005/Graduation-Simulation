"""Preprocess HITL-IoT camera and sensor data for model training.

Outputs separate camera and sensor feature matrices plus a combined matrix,
with metadata describing the selected columns and label encoding.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd


LABEL_PATTERNS = ("label", "class", "attack", "category", "target", "is_attack")
CAMERA_PATTERNS = ("camera", "cam", "image", "frame", "jpeg", "snapshot", "video", "vision", "pixel", "rgb")
SENSOR_PATTERNS = ("sensor", "temperature", "humidity", "pressure", "motion", "light", "sound", "voltage", "current", "accel", "gyro", "magnetic", "gas", "co2", "air", "battery")
META_PATTERNS = ("id", "time", "date", "timestamp", "ip", "address", "port", "protocol", "device", "source", "path", "method")


def matches(column: str, patterns: tuple[str, ...]) -> bool:
    name = str(column).strip().lower().replace(" ", "_")
    return any(pattern in name for pattern in patterns)


def normalize_label(value: object) -> str:
    if pd.isna(value):
        return "unknown"
    text = str(value).strip()
    return text or "unknown"


def clean_numeric(frame: pd.DataFrame, columns: list[str]) -> tuple[pd.DataFrame, dict[str, float]]:
    if not columns:
        return pd.DataFrame(index=frame.index), {}
    values = frame[columns].apply(pd.to_numeric, errors="coerce")
    values = values.replace([np.inf, -np.inf], np.nan)
    medians = values.median(numeric_only=True).fillna(0)
    values = values.fillna(medians)
    mean = values.mean()
    std = values.std().replace(0, 1).fillna(1)
    scaled = (values - mean) / std
    return scaled.astype(np.float32), {"means": mean.to_dict(), "stds": std.to_dict()}


def preprocess(csv_path: str | Path, output_dir: str | Path, limit: int | None = None) -> dict[str, object]:
    frame = pd.read_csv(csv_path, nrows=limit)
    numeric_columns = frame.select_dtypes(include=["number"]).columns.tolist()
    label_column = next((column for column in frame.columns if matches(column, LABEL_PATTERNS)), None)
    if label_column in numeric_columns:
        numeric_columns.remove(label_column)

    camera_columns = [column for column in numeric_columns if matches(column, CAMERA_PATTERNS)]
    sensor_columns = [column for column in numeric_columns if matches(column, SENSOR_PATTERNS) and column not in camera_columns]
    assigned = set(camera_columns) | set(sensor_columns)
    other_columns = [column for column in numeric_columns if column not in assigned and not matches(column, META_PATTERNS)]

    # Preserve unclassified numeric measurements with sensor features because
    # IoT datasets often use short names such as f1/f2 for sensor channels.
    sensor_columns.extend(other_columns)
    sensor_columns = list(dict.fromkeys(sensor_columns))
    if not camera_columns and not sensor_columns:
        raise ValueError("No numeric camera or sensor features were found.")

    camera_values, camera_stats = clean_numeric(frame, camera_columns)
    sensor_values, sensor_stats = clean_numeric(frame, sensor_columns)
    combined_values = pd.concat([camera_values, sensor_values], axis=1)

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    camera_values.to_csv(output / "camera_features.csv", index=False)
    sensor_values.to_csv(output / "sensor_features.csv", index=False)
    combined_values.to_csv(output / "combined_features.csv", index=False)

    labels = frame[label_column].map(normalize_label) if label_column else pd.Series(["unknown"] * len(frame))
    labels.to_frame("label").to_csv(output / "labels.csv", index=False)
    metadata = {
        "source": str(Path(csv_path).resolve()),
        "rows": len(frame),
        "label_column": label_column,
        "camera_columns": camera_columns,
        "sensor_columns": sensor_columns,
        "camera_stats": camera_stats,
        "sensor_stats": sensor_stats,
        "outputs": ["camera_features.csv", "sensor_features.csv", "combined_features.csv", "labels.csv"],
    }
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description="Preprocess camera and sensor features")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--output", default="processed_data")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()
    print(json.dumps(preprocess(args.dataset, args.output, args.limit), indent=2))


if __name__ == "__main__":
    main()
