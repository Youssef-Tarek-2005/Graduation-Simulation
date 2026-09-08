"""Train and save the three HITL-IoT AI models.

Usage:
    python train_models.py --dataset ..\data\HITL-IoT_dataset.csv --epochs 10
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import torch

from model_pipeline import prepare_dataset, train_classifier, train_graph_predictor, train_lstm_vae


def main() -> None:
    parser = argparse.ArgumentParser(description="Train HoneyIoT model artifacts")
    parser.add_argument("--dataset", required=True, help="Path to the HITL-IoT CSV")
    parser.add_argument("--output", default="artifacts", help="Directory for model artifacts")
    parser.add_argument("--limit", type=int, default=None, help="Optional row limit for a quick run")
    parser.add_argument("--epochs", type=int, default=10)
    args = parser.parse_args()

    data = prepare_dataset(args.dataset, limit=args.limit)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    anomaly_model = train_lstm_vae(data, epochs=args.epochs)
    classifier = train_classifier(data, epochs=args.epochs)
    graph_model = train_graph_predictor(data, epochs=args.epochs)

    torch.save(anomaly_model.state_dict(), output / "lstm_vae.pt")
    torch.save(classifier.state_dict(), output / "attack_classifier.pt")
    torch.save(graph_model.state_dict(), output / "graph_predictor.pt")
    (output / "metadata.json").write_text(json.dumps({
        "dataset": str(Path(args.dataset).resolve()),
        "rows": len(data.features),
        "feature_names": data.feature_names,
        "classes": data.label_encoder.classes_.tolist(),
        "models": ["lstm_vae", "attack_classifier", "graph_predictor"],
    }, indent=2), encoding="utf-8")
    print(f"Saved three model artifacts to {output.resolve()}")


if __name__ == "__main__":
    main()
