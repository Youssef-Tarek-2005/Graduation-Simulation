import React, { useEffect, useMemo, useRef, useState } from "react";

const COLORS = { accent: "#00d4ff", good: "#00ff88", warn: "#ffaa00", bad: "#ff4444" };

export function AnomalyChart({ data }) {
  if (!data || data.length === 0) return <div className="loading">Loading trend...</div>;
  const w = 800, h = 180, pad = 24;
  const step = (w - pad * 2) / (data.length - 1 || 1);
  const y = (v) => h - pad - v * (h - pad * 2);
  const points = data.map((d, i) => `${pad + i * step},${y(d.anomaly_score)}`).join(" ");
  const areaPts = `${pad},${h - pad} ${points} ${pad + (data.length - 1) * step},${h - pad}`;
  const color = (v) => (v >= 0.45 ? COLORS.bad : v >= 0.25 ? COLORS.warn : COLORS.good);
  return (
    <svg viewBox={`0 0 ${w} ${h}`} style={{ width: "100%", background: "rgba(0,0,0,0.25)", borderRadius: 8 }}>
      <defs>
        <linearGradient id="grad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={COLORS.accent} stopOpacity="0.45" />
          <stop offset="100%" stopColor={COLORS.accent} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon points={areaPts} fill="url(#grad)" />
      <polyline points={points} fill="none" stroke={COLORS.accent} strokeWidth="2" />
      <line x1={pad} x2={w - pad} y1={y(0.45)} y2={y(0.45)} stroke={COLORS.bad} strokeDasharray="4 4" strokeWidth="1" opacity="0.7" />
      {data.map((d, i) =>
        d.is_anomalous ? <circle key={i} cx={pad + i * step} cy={y(d.anomaly_score)} r="3.5" fill={COLORS.bad} /> : null
      )}
      <text x={pad} y={16} fill="#888" fontSize="11">anomaly score (threshold 0.45, red = attack flagged)</text>
    </svg>
  );
}

export function FlowTable({ flows }) {
  if (!flows.length) return <div className="loading">Waiting for live flows...</div>;
  return (
    <table>
      <thead>
        <tr>
          <th>#</th><th>Src Port</th><th>Dst Port</th><th>Proto</th><th>True Label</th>
          <th>AE Score</th><th>Classifier</th><th>GNN Stage</th><th>Verdict</th>
        </tr>
      </thead>
      <tbody>
        {flows.map((f) => (
          <tr key={f.index + "-" + f.timestamp} className={f.verdict === "THREAT" ? "threat-row" : ""}>
            <td>{f.index}</td>
            <td>{f.src_port}</td>
            <td>{f.dst_port}</td>
            <td>{f.protocol}</td>
            <td><span className={`pill ${f.true_label === "Anomaly" ? "attack" : "normal-l"}`}>{f.true_label}</span></td>
            <td>{f.autoencoder.anomaly_score}</td>
            <td>{f.classifier.prediction} ({f.classifier.confidence})</td>
            <td>{f.gnn.stage_name}</td>
            <td><span className={`pill ${f.verdict === "THREAT" ? "threat" : "safe"}`}>{f.verdict}</span></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function ModelResult({ result }) {
  if (!result) return <div className="loading">Run a sample to see model output...</div>;
  const ae = result.autoencoder, clf = result.classifier, gnn = result.gnn;
  const isThreat = result.verdict === "THREAT";
  return (
    <div className="results">
      <div className="result-item">
        <span className="result-label">Flow #:</span><span>{result.index}</span>
        <span className="result-label">True Label:</span>
        <span className={`pill ${result.true_label === "Anomaly" ? "attack" : "normal-l"}`}>{result.true_label}</span>
        <span className="result-label">Verdict:</span>
        <span className={`dot ${isThreat ? "threat" : "safe"}`} />
        <span style={{ color: isThreat ? COLORS.bad : COLORS.good, fontWeight: "bold" }}>{result.verdict}</span>
      </div>
      <div className="result-item">
        <span className="result-label">🔮 LSTM VAE:</span>
        <span>recon_err={ae.reconstruction_error} | thr={ae.threshold}</span>
        <span className={`dot ${ae.is_anomalous ? "anomaly" : "normal"}`} />
        <span>score={ae.anomaly_score} ({ae.status})</span>
      </div>
      <div className="result-item">
        <span className="result-label">🎯 Classifier:</span>
        <span>{clf.prediction}</span>
        {Object.entries(clf.probabilities).map(([k, v]) => (
          <span key={k} className="metric" style={{ display: "inline-block", padding: "2px 8px" }}>
            {k}: {(v * 100).toFixed(1)}%
          </span>
        ))}
      </div>
      <div className="result-item">
        <span className="result-label">🕸️ GNN:</span>
        <span>stage {gnn.stage} — {gnn.stage_name} | lateral risk: {gnn.lateral_movement_risk}</span>
      </div>
      <div className="metrics">
        <div className="metric"><div className="metric-value">{result.src_port}</div><div className="metric-label">Src Port</div></div>
        <div className="metric"><div className="metric-value">{result.dst_port}</div><div className="metric-label">Dst Port</div></div>
        <div className="metric"><div className="metric-value">{result.protocol}</div><div className="metric-label">Protocol</div></div>
        <div className="metric"><div className="metric-value">{(result.bytes_per_s / 1e6).toFixed(2)}M</div><div className="metric-label">Bytes/s</div></div>
      </div>
    </div>
  );
}
