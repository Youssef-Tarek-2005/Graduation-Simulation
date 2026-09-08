"""Trainable AI models for the HITL-IoT dataset.

The three models share the same numeric feature matrix and can be trained from
one command. They intentionally do not run during Flask requests; training and
inference artifacts are kept separate from the web service.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import torch
from torch import Tensor, nn
from torch.utils.data import DataLoader, TensorDataset


class LabelEncoder:
    def fit(self, values: np.ndarray) -> "LabelEncoder":
        self.classes_ = np.array(sorted(set(values.tolist())), dtype=object)
        self._index = {value: index for index, value in enumerate(self.classes_)}
        return self

    def transform(self, values: np.ndarray) -> np.ndarray:
        return np.array([self._index[value] for value in values], dtype=np.int64)


class StandardScaler:
    def fit(self, values: np.ndarray) -> "StandardScaler":
        self.mean_ = values.mean(axis=0)
        self.scale_ = values.std(axis=0)
        self.scale_[self.scale_ == 0] = 1.0
        return self

    def transform(self, values: np.ndarray) -> np.ndarray:
        return (values - self.mean_) / self.scale_


LABEL_COLUMNS = ("label", "class", "category", "attack", "attack_type", "target")


def find_column(frame: pd.DataFrame, candidates: tuple[str, ...]) -> str | None:
    normalized = {str(column).strip().lower().replace(" ", "_"): column for column in frame.columns}
    for candidate in candidates:
        if candidate in normalized:
            return normalized[candidate]
    return None


@dataclass
class PreparedDataset:
    features: np.ndarray
    labels: np.ndarray
    label_encoder: LabelEncoder
    scaler: StandardScaler
    feature_names: list[str]


def prepare_dataset(csv_path: str | Path, limit: int | None = None) -> PreparedDataset:
    frame = pd.read_csv(csv_path, nrows=limit)
    label_column = find_column(frame, LABEL_COLUMNS)
    if label_column is None:
        raise ValueError(f"No label column found. Expected one of: {', '.join(LABEL_COLUMNS)}")

    numeric = frame.select_dtypes(include=["number"]).copy()
    numeric = numeric.replace([np.inf, -np.inf], np.nan).fillna(0)
    if numeric.empty:
        raise ValueError("The dataset contains no numeric feature columns.")

    labels = frame[label_column].fillna("unknown").astype(str).to_numpy()
    label_encoder = LabelEncoder().fit(labels)
    scaler = StandardScaler().fit(numeric.to_numpy(dtype=np.float32))
    features = scaler.transform(numeric.to_numpy(dtype=np.float32)).astype(np.float32)
    return PreparedDataset(features, label_encoder.transform(labels), label_encoder, scaler, list(numeric.columns))


class LSTMVAE(nn.Module):
    """Sequence autoencoder with variational latent representation."""

    def __init__(self, feature_count: int, hidden_size: int = 64, latent_size: int = 16):
        super().__init__()
        self.encoder = nn.LSTM(feature_count, hidden_size, batch_first=True)
        self.mu = nn.Linear(hidden_size, latent_size)
        self.logvar = nn.Linear(hidden_size, latent_size)
        self.decoder_input = nn.Linear(latent_size, hidden_size)
        self.decoder = nn.LSTM(hidden_size, hidden_size, batch_first=True)
        self.output = nn.Linear(hidden_size, feature_count)

    def forward(self, sequence: Tensor) -> tuple[Tensor, Tensor, Tensor]:
        _, (hidden, _) = self.encoder(sequence)
        latent_mu = self.mu(hidden[-1])
        latent_logvar = self.logvar(hidden[-1])
        std = torch.exp(0.5 * latent_logvar)
        latent = latent_mu + torch.randn_like(std) * std
        decoder_seed = self.decoder_input(latent).unsqueeze(1).repeat(1, sequence.size(1), 1)
        decoded, _ = self.decoder(decoder_seed)
        return self.output(decoded), latent_mu, latent_logvar


def vae_loss(decoded: Tensor, target: Tensor, mu: Tensor, logvar: Tensor) -> Tensor:
    reconstruction = nn.functional.mse_loss(decoded, target)
    kl = -0.5 * torch.mean(1 + logvar - mu.pow(2) - logvar.exp())
    return reconstruction + 0.01 * kl


class AttackClassifier(nn.Module):
    def __init__(self, feature_count: int, class_count: int):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(feature_count, 128),
            nn.ReLU(),
            nn.Dropout(0.15),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, class_count),
        )

    def forward(self, features: Tensor) -> Tensor:
        return self.network(features)


class GraphSequencePredictor(nn.Module):
    """Small graph message-passing model for attacker/device/technique nodes."""

    def __init__(self, node_count: int, class_count: int, embedding_size: int = 32):
        super().__init__()
        self.node_embedding = nn.Embedding(node_count, embedding_size)
        self.message = nn.Linear(embedding_size, embedding_size)
        self.classifier = nn.Linear(embedding_size, class_count)

    def forward(self, nodes: Tensor, edges: Tensor) -> Tensor:
        embeddings = self.node_embedding(nodes)
        source, target = edges
        messages = self.message(embeddings[source])
        aggregated = torch.zeros_like(embeddings).index_add_(0, target, messages)
        graph_state = (embeddings + aggregated).mean(dim=0)
        return self.classifier(graph_state)


def make_sequences(features: np.ndarray, sequence_length: int = 12) -> Tensor:
    if len(features) < sequence_length:
        padded = np.pad(features, ((0, sequence_length - len(features)), (0, 0)))
        features = padded
    sequences = [features[index:index + sequence_length] for index in range(len(features) - sequence_length + 1)]
    return torch.tensor(np.asarray(sequences), dtype=torch.float32)


def train_lstm_vae(data: PreparedDataset, epochs: int = 10, batch_size: int = 64) -> LSTMVAE:
    model = LSTMVAE(data.features.shape[1])
    sequences = make_sequences(data.features)
    loader = DataLoader(TensorDataset(sequences), batch_size=batch_size, shuffle=True)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    model.train()
    for _ in range(epochs):
        for (batch,) in loader:
            decoded, mu, logvar = model(batch)
            loss = vae_loss(decoded, batch, mu, logvar)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
    return model


def train_classifier(data: PreparedDataset, epochs: int = 20, batch_size: int = 128) -> AttackClassifier:
    model = AttackClassifier(data.features.shape[1], len(data.label_encoder.classes_))
    loader = DataLoader(TensorDataset(torch.tensor(data.features), torch.tensor(data.labels)), batch_size=batch_size, shuffle=True)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = nn.CrossEntropyLoss()
    model.train()
    for _ in range(epochs):
        for features, labels in loader:
            loss = loss_fn(model(features), labels)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
    return model


def train_graph_predictor(data: PreparedDataset, epochs: int = 20) -> GraphSequencePredictor:
    node_count = len(data.labels)
    if node_count < 2:
        raise ValueError("At least two rows are required to train the graph predictor.")
    model = GraphSequencePredictor(node_count, len(data.label_encoder.classes_))
    nodes = torch.arange(node_count, dtype=torch.long)
    edges = torch.tensor([np.arange(max(node_count - 1, 1)), np.arange(1, node_count)], dtype=torch.long)
    target = torch.tensor(int(data.labels[-1]), dtype=torch.long)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    for _ in range(epochs):
        loss = nn.functional.cross_entropy(model(nodes, edges).unsqueeze(0), target.unsqueeze(0))
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
    return model
