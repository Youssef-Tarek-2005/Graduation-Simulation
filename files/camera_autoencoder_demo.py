"""Fast camera-focused autoencoder demo.

The autoencoder learns normal numeric behavior and scores one selected attack
row by reconstruction error. It is intentionally small for quick iteration.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch import nn


class CameraAutoencoder(nn.Module):
    def __init__(self, feature_count: int) -> None:
        super().__init__()
        hidden = max(4, min(32, feature_count * 2))
        latent = max(2, min(8, feature_count))
        self.encoder = nn.Sequential(nn.Linear(feature_count, hidden), nn.ReLU(), nn.Linear(hidden, latent))
        self.decoder = nn.Sequential(nn.Linear(latent, hidden), nn.ReLU(), nn.Linear(hidden, feature_count))

    def forward(self, values: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(values))


def find_column(frame: pd.DataFrame, names: tuple[str, ...]) -> str | None:
    normalized = {str(column).strip().lower().replace(" ", "_"): column for column in frame.columns}
    for name in names:
        if name in normalized:
            return normalized[name]
    return None


def is_normal(values: pd.Series) -> pd.Series:
    numeric = pd.to_numeric(values, errors="coerce")
    if numeric.notna().mean() > 0.8:
        return numeric.fillna(1).eq(0)
    text = values.fillna("unknown").astype(str).str.lower()
    return text.isin({"normal", "benign", "legitimate", "0", "false"})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--row", type=int, default=1, help="One-based event row to score")
    parser.add_argument("--attack", default=None, help="Attack text to find; defaults to first attack row")
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--output", default="artifacts/camera_autoencoder.pt")
    args = parser.parse_args()

    frame = pd.read_csv(args.dataset)
    label_column = find_column(frame, ("is_attack", "attack_type", "attack", "label", "class", "category"))
    if label_column is None:
        raise ValueError("Could not find an attack label column.")

    numeric = frame.select_dtypes(include=["number"]).replace([np.inf, -np.inf], np.nan).fillna(0)
    if numeric.shape[1] == 0:
        raise ValueError("The dataset has no numeric columns for the autoencoder.")

    normal_mask = is_normal(frame[label_column])
    normal_rows = numeric[normal_mask]
    attack_rows = numeric[~normal_mask]
    if normal_rows.empty or attack_rows.empty:
        raise ValueError("Need both normal rows and attack rows.")

    row_position = args.row - 1
    if row_position < 0 or row_position >= len(frame):
        raise ValueError(f"--row must be between 1 and {len(frame)}")
    selected_index = frame.index[row_position]
    if normal_mask.loc[selected_index]:
        raise ValueError(f"Event {args.row} is labeled normal; choose a labeled attack event.")
    if args.attack:
        matches = frame.loc[~normal_mask, label_column].astype(str).str.contains(args.attack, case=False, na=False)
        if matches.any():
            selected_index = frame.index[matches][0]

    mean = normal_rows.mean()
    scale = normal_rows.std().replace(0, 1).fillna(1)
    normal_tensor = torch.tensor(((normal_rows - mean) / scale).to_numpy(dtype=np.float32))
    attack_tensor = torch.tensor(((numeric.loc[[selected_index]] - mean) / scale).to_numpy(dtype=np.float32))

    model = CameraAutoencoder(normal_tensor.shape[1])
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    model.train()
    for epoch in range(args.epochs):
        reconstruction = model(normal_tensor)
        loss = nn.functional.mse_loss(reconstruction, normal_tensor)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        print(f"epoch {epoch + 1}/{args.epochs} loss={loss.item():.6f}", flush=True)

    model.eval()
    with torch.no_grad():
        normal_error = ((model(normal_tensor) - normal_tensor) ** 2).mean(dim=1)
        attack_error = ((model(attack_tensor) - attack_tensor) ** 2).mean().item()

    threshold = float(torch.quantile(normal_error, 0.95))
    result = {
        "model": "camera_autoencoder",
        "label_column": str(label_column),
        "attack_row_index": int(selected_index),
        "event_number": args.row,
        "attack_label": str(frame.loc[selected_index, label_column]),
        "normal_rows": int(len(normal_rows)),
        "attack_rows": int(len(attack_rows)),
        "feature_count": int(numeric.shape[1]),
        "attack_reconstruction_error": round(attack_error, 6),
        "normal_95th_percentile": round(threshold, 6),
        "anomalous": bool(attack_error > threshold),
        "features": list(numeric.columns),
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    torch.save({"state_dict": model.state_dict(), "mean": mean.to_dict(), "scale": scale.to_dict(), "features": list(numeric.columns)}, output)
    output.with_suffix(".json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
