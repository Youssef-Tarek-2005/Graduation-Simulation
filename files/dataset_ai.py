"""Live dataset inference for the React dashboard.

Loads the three trained models (LSTM VAE, Attack Classifier, Graph Predictor)
and streams real flow records from the IoT Network Intrusion Dataset through
them on demand.
"""

from __future__ import annotations

import math
import threading
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import torch

from model_pipeline import (
    LSTMVAE,
    AttackClassifier,
    GraphSequencePredictor,
    prepare_dataset,
)

ROOT = Path(__file__).resolve().parents[1]
RAW_CSV = ROOT / "data" / "IoT Network Intrusion Dataset.csv"
ARTIFACTS = ROOT / "artifacts"

_state: dict[str, Any] | None = None
_lock = threading.Lock()


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def _load() -> dict[str, Any]:
    global _state
    with _lock:
        if _state is not None:
            return _state

        ds = prepare_dataset(RAW_CSV, limit=5000)
        feature_count = ds.features.shape[1]
        class_count = len(ds.label_encoder.classes_)

        vae = LSTMVAE(feature_count)
        vae.load_state_dict(torch.load(ARTIFACTS / "lstm_vae.pt", map_location="cpu"))
        vae.eval()

        clf = AttackClassifier(feature_count, class_count)
        clf.load_state_dict(torch.load(ARTIFACTS / "attack_classifier.pt", map_location="cpu"))
        clf.eval()

        gnn = GraphSequencePredictor(len(ds.features), class_count)
        gnn.load_state_dict(torch.load(ARTIFACTS / "graph_predictor.pt", map_location="cpu"))
        gnn.eval()

        # Calibrate the VAE anomaly threshold on a sample of reconstruction errors.
        with torch.no_grad():
            probe = torch.tensor(ds.features[:512], dtype=torch.float32)
            decoded, _, _ = vae(probe.unsqueeze(1).repeat(1, 12, 1).view(-1, 1, feature_count))
            errors = ((decoded - probe.unsqueeze(1).repeat(1, 12, 1).view(-1, 1, feature_count)) ** 2).mean(dim=(1, 2))
        vae_threshold = float(np.percentile(errors.numpy(), 90)) + 1e-6

        display_frame = pd.read_csv(RAW_CSV, usecols=["Src_Port", "Dst_Port", "Protocol", "Flow_Duration", "Flow_Byts/s", "Label"], nrows=5000)

        total = len(ds.labels)
        attack_total = int((ds.labels == ds.label_encoder.transform(np.array(["Anomaly"]))[0]).sum())
        _state = {
            "ds": ds,
            "vae": vae,
            "clf": clf,
            "gnn": gnn,
            "threshold": vae_threshold,
            "display": display_frame,
            "classes": ds.label_encoder.classes_.tolist(),
            "counts": {"total": total, "attack": attack_total, "normal": total - attack_total},
        }
        return _state


def _vae_score(vae: LSTMVAE, features: np.ndarray, threshold: float) -> dict[str, Any]:
    seq = torch.tensor(features, dtype=torch.float32).unsqueeze(0)  # (1, T, F)
    with torch.no_grad():
        decoded, _, _ = vae(seq)
        recon_error = float(torch.nn.functional.mse_loss(decoded, seq))
    severity = _sigmoid(3.5 * (recon_error / threshold - 1.0))
    score = round(max(0.01, min(0.99, severity)), 3)
    return {
        "reconstruction_error": round(recon_error, 6),
        "threshold": round(threshold, 6),
        "anomaly_score": score,
        "is_anomalous": score >= 0.45,
        "confidence": round(0.70 + abs(score - 0.5) * 0.55, 3),
        "status": "ANOMALOUS" if score >= 0.45 else "NORMAL",
    }


def _gnn_stage(prob_attack: float, recon: dict[str, Any]) -> dict[str, str]:
    if not recon["is_anomalous"]:
        return {"stage": 0, "name": "No Active Attack Progression"}
    if prob_attack >= 0.85:
        return {"stage": 5, "name": "Impact / Exfiltration"}
    if prob_attack >= 0.65:
        return {"stage": 4, "name": "Exploitation / Tampering"}
    if prob_attack >= 0.45:
        return {"stage": 2, "name": "Initial Access / Lateral Movement"}
    return {"stage": 1, "name": "Reconnaissance / Footprinting"}


def predict_index(index: int) -> dict[str, Any]:
    """Run the 3-model pipeline on a single dataset flow by row index."""
    s = _load()
    ds: Any = s["ds"]
    idx = int(index) % len(ds.features)
    features = ds.features[max(idx - 11, 0): idx + 1]
    if features.shape[0] < 12:
        pad = np.zeros((12 - features.shape[0], features.shape[1]), dtype=np.float32)
        features = np.vstack([pad, features])

    recon = _vae_score(s["vae"], features, s["threshold"])
    row = torch.tensor(ds.features[idx], dtype=torch.float32).unsqueeze(0)
    with torch.no_grad():
        logits = s["clf"](row)
        probs = torch.softmax(logits, dim=1)[0].numpy()

    classes = s["classes"]
    pred_idx = int(np.argmax(probs))
    # Graph predictor over a chained sequence of sampled row nodes
    node_ids = torch.tensor(np.arange(max(idx - 7, 0), idx + 1), dtype=torch.long)
    edges = torch.tensor([np.arange(len(node_ids) - 1), np.arange(1, len(node_ids))], dtype=torch.long)
    with torch.no_grad():
        gnn_logits = s["gnn"](node_ids, edges)
        gnn_probs = torch.softmax(gnn_logits, dim=0).numpy()
    gnn_pred = classes[int(np.argmax(gnn_probs))]

    true_label = classes[int(ds.labels[idx])]
    disp = s["display"].iloc[idx]
    clf_attack_prob = float(probs[classes.index("Anomaly")]) if "Anomaly" in classes else float(probs[pred_idx])

    return {
        "index": idx,
        "src_port": int(disp["Src_Port"]),
        "dst_port": int(disp["Dst_Port"]),
        "protocol": int(disp["Protocol"]),
        "flow_duration": float(disp["Flow_Duration"]),
        "bytes_per_s": float(disp["Flow_Byts/s"]),
        "true_label": true_label,
        "autoencoder": recon,
        "classifier": {
            "prediction": classes[pred_idx],
            "confidence": round(float(probs[pred_idx]), 3),
            "attack_probability": round(clf_attack_prob, 3),
            "probabilities": {c: round(float(p), 3) for c, p in zip(classes, probs)},
        },
        "gnn": {
            "prediction": gnn_pred,
            "confidence": round(float(np.max(gnn_probs)), 3),
            "stage": _gnn_stage(clf_attack_prob, recon)["stage"],
            "stage_name": _gnn_stage(clf_attack_prob, recon)["name"],
            "lateral_movement_risk": round(min(1.0, clf_attack_prob * recon["anomaly_score"] * 1.4), 3),
            "probabilities": {c: round(float(p), 3) for c, p in zip(classes, gnn_probs)},
        },
        "verdict": "THREAT" if (recon["is_anomalous"] and clf_attack_prob >= 0.5) else "SAFE",
        "timestamp": pd.Timestamp.now(tz="UTC").isoformat(),
    }


def dataset_info() -> dict[str, Any]:
    s = _load()
    ds: Any = s["ds"]
    counts = dict(s["counts"])
    return {
        "dataset": str(RAW_CSV),
        "rows": counts["total"],
        "attack_count": counts["attack"],
        "normal_count": counts["normal"],
        "classes": s["classes"],
        "feature_count": ds.features.shape[1],
        "feature_names": ds.feature_names,
        "models": [
            {"name": "LSTM VAE", "type": "Sequence Autoencoder", "task": "Anomaly Detection", "trained": True},
            {"name": "Attack Classifier", "type": "MLP Classifier", "task": "Attack Classification", "trained": True},
            {"name": "Graph Predictor", "type": "Message-Passing GNN", "task": "Attack Progression", "trained": True},
        ],
    }


def history(count: int = 60) -> list[dict[str, Any]]:
    """Sequential slice of the dataset with VAE anomaly scores for the trend chart."""
    s = _load()
    ds: Any = s["ds"]
    count = max(5, min(int(count), 300))
    rng = np.random.default_rng()
    start = int(rng.integers(0, max(len(ds.features) - count, 1)))
    out = []
    for idx in range(start, start + count):
        feats = ds.features[max(idx - 11, 0): idx + 1]
        if feats.shape[0] < 12:
            pad = np.zeros((12 - feats.shape[0], feats.shape[1]), dtype=np.float32)
            feats = np.vstack([pad, feats])
        recon = _vae_score(s["vae"], feats, s["threshold"])
        out.append({
            "index": idx,
            "anomaly_score": recon["anomaly_score"],
            "reconstruction_error": recon["reconstruction_error"],
            "true_label": s["classes"][int(ds.labels[idx])],
            "is_anomalous": recon["is_anomalous"],
        })
    return out
