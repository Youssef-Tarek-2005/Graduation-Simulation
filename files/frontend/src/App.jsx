import React, { useCallback, useEffect, useRef, useState } from "react";
import { AnomalyChart, FlowTable, ModelResult } from "./components.jsx";

const POLL_MS = 2500;

export default function App() {
  const [info, setInfo] = useState(null);
  const [flows, setFlows] = useState([]);
  const [trend, setTrend] = useState(null);
  const [selected, setSelected] = useState(null);
  const [live, setLive] = useState(false);
  const [simResult, setSimResult] = useState(null);
  const [preset, setPreset] = useState("video_exfiltration");
  const [presets, setPresets] = useState({});
  const [error, setError] = useState(null);
  const timer = useRef(null);

  useEffect(() => {
    fetch("/api/dataset/info").then(r => r.json()).then(setInfo).catch(e => setError(String(e)));
    fetch("/api/dataset/history?count=80").then(r => r.json()).then(setTrend).catch(e => setError(String(e)));
    fetch("/api/simulation-presets").then(r => r.json()).then(setPresets).catch(() => {});
  }, []);

  const streamOnce = useCallback(async (count = 6) => {
    try {
      const res = await fetch(`/api/dataset/stream?count=${count}`);
      const batch = await res.json();
      setFlows(prev => [...batch, ...prev].slice(0, 60));
      setSelected(batch[0]);
    } catch (e) { setError(String(e)); }
  }, []);

  useEffect(() => {
    streamOnce(8);
  }, [streamOnce]);

  useEffect(() => {
    if (live) {
      timer.current = setInterval(() => streamOnce(3), POLL_MS);
    }
    return () => clearInterval(timer.current);
  }, [live, streamOnce]);

  const runSimulation = async () => {
    setSimResult(null);
    try {
      const res = await fetch(`/api/simulate-behavior?preset=${preset}`);
      setSimResult(await res.json());
    } catch (e) { setError(String(e)); }
  };

  const threatCount = flows.filter(f => f.verdict === "THREAT").length;
  const detectRate = flows.length ? ((threatCount / flows.length) * 100).toFixed(1) : "0.0";
  const llm = simResult?.llm_analysis;
  const threatColors = { LOW: "#00ff88", MEDIUM: "#ffaa00", HIGH: "#ff4444", CRITICAL: "#ff0000" };

  return (
    <div className="container">
      <h1>🤖 AI Models Dashboard — Live IoT Dataset</h1>
      <p className="subtitle">
        Real flows from the IoT Network Intrusion Dataset streamed through 3 trained models
        (LSTM VAE · Attack Classifier · Graph Predictor)
      </p>
      <div className="badges">
        {(info?.models || []).map(m => (
          <span key={m.name} className="badge">✓ {m.name} Trained</span>
        ))}
        <span className="badge" style={{ background: live ? "#00d4ff" : "#888" }}>
          {live ? "● LIVE MONITORING" : "○ PAUSED"}
        </span>
      </div>

      {error && <div className="error-text">⚠ {error}</div>}

      <div className="stat-grid">
        <div className="stat-card"><div className="stat-value">{info?.rows ?? "—"}</div><div className="stat-label">Dataset Flows</div></div>
        <div className="stat-card"><div className="stat-value" style={{ color: "#ff4444" }}>{info?.attack_count ?? "—"}</div><div className="stat-label">Anomaly Flows</div></div>
        <div className="stat-card"><div className="stat-value" style={{ color: "#00ff88" }}>{info?.normal_count ?? "—"}</div><div className="stat-label">Normal Flows</div></div>
        <div className="stat-card"><div className="stat-value">{flows.length}</div><div className="stat-label">Flows Analyzed</div></div>
        <div className="stat-card"><div className="stat-value" style={{ color: threatCount ? "#ff4444" : "#00ff88" }}>{detectRate}%</div><div className="stat-label">Threat Rate</div></div>
      </div>

      <div className="grid-2">
        <div className="card">
          <h3>📈 Live Anomaly Trend — LSTM VAE on Real Dataset Flows</h3>
          <AnomalyChart data={trend} />
        </div>
        <div className="card">
          <h3>🔬 Inspect a Sample Flow (all 3 models)</h3>
          <div className="controls">
            <button onClick={() => streamOnce(1)}>🎲 Random Sample</button>
            <button className={`ghost ${live ? "running" : ""}`} onClick={() => setLive(v => !v)}>
              {live ? "⏸ Stop Live" : "▶ Start Live Stream"}
            </button>
          </div>
          <ModelResult result={selected} />
        </div>
      </div>

      <div className="card" style={{ marginBottom: 24 }}>
        <h3>🌐 Live Flow Feed — Real Dataset Traffic</h3>
        <FlowTable flows={flows} />
      </div>

      <div className="card">
        <h3>🚀 Simulation Pipeline (camera/sensor presets)</h3>
        <div className="controls">
          <select value={preset} onChange={e => setPreset(e.target.value)}>
            {Object.values(presets).map(p => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
          <button onClick={runSimulation}>Run Complete Pipeline</button>
        </div>
        {llm ? (
          <div className="results">
            <div className="result-item">
              <span className="result-label">THREAT LEVEL:</span>
              <span style={{ color: threatColors[llm.threat_level] || "#888", fontWeight: "bold", fontSize: 16 }}>{llm.threat_level}</span>
            </div>
            <div className="result-item"><span className="result-label">Summary:</span><span>{llm.executive_summary}</span></div>
            <div className="result-item"><span className="result-label">MITRE ATT&CK:</span><span>{llm.mitre.technique} ({llm.mitre.technique_id})</span></div>
            <div className="result-item"><span className="result-label">OWASP IoT:</span><span>{llm.owasp_iot.category} ({llm.owasp_iot.id})</span></div>
            <div className="result-item"><span className="result-label">Playbook:</span><span>{llm.response_playbook.join(" · ")}</span></div>
          </div>
        ) : (
          <div className="loading">Select a preset and run the pipeline...</div>
        )}
      </div>

      <footer>
        Dataset: {info?.dataset || "IoT Network Intrusion Dataset"} · Features: {info?.feature_count ?? "—"} · Flask + React + PyTorch
      </footer>
    </div>
  );
}
