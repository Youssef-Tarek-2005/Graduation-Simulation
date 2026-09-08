import { useEffect, useState, useMemo, useCallback } from 'react'
import './App.css'

// Default fallback simulation presets for immediate offline resilience
const DEFAULT_PRESETS = {
  normal_surveillance: {
    id: 'normal_surveillance',
    name: 'Normal Video Surveillance',
    badge: 'Benign Baseline',
    type: 'normal',
    description: 'Standard 28 FPS video stream with typical ambient sensor telemetry',
    features: {
      fps: 28.0,
      bandwidth_kbps: 420.0,
      request_rate: 4.0,
      frame_drop_rate: 0.4,
      stream_active_sessions: 1.0,
      jpeg_payload_size_kb: 42.0,
      temperature_c: 24.2,
      humidity_pct: 46.5,
      sampling_interval_sec: 10.0,
      baseline_deviation: 0.15,
      packet_rate: 12.0,
      tamper_flag: 0.0,
    },
  },
  normal_sensor_poll: {
    id: 'normal_sensor_poll',
    name: 'Normal Sensor Telemetry',
    badge: 'Benign Telemetry',
    type: 'normal',
    description: 'Routine temperature & humidity updates with camera in standby',
    features: {
      fps: 24.0,
      bandwidth_kbps: 390.0,
      request_rate: 3.0,
      frame_drop_rate: 0.2,
      stream_active_sessions: 1.0,
      jpeg_payload_size_kb: 39.0,
      temperature_c: 23.5,
      humidity_pct: 50.0,
      sampling_interval_sec: 10.0,
      baseline_deviation: 0.12,
      packet_rate: 11.0,
      tamper_flag: 0.0,
    },
  },
  video_exfiltration: {
    id: 'video_exfiltration',
    name: 'Video Stream Exfiltration',
    badge: 'Camera Attack',
    type: 'attack',
    description: 'Multiple unauthorized MJPEG streams siphoning high-bandwidth feed',
    features: {
      fps: 35.0,
      bandwidth_kbps: 4600.0,
      request_rate: 45.0,
      frame_drop_rate: 4.5,
      stream_active_sessions: 6.0,
      jpeg_payload_size_kb: 85.0,
      temperature_c: 27.8,
      humidity_pct: 44.0,
      sampling_interval_sec: 10.0,
      baseline_deviation: 0.4,
      packet_rate: 45.0,
      tamper_flag: 0.0,
    },
  },
  camera_dos_flood: {
    id: 'camera_dos_flood',
    name: 'Camera MJPEG Buffer DoS',
    badge: 'Camera Attack',
    type: 'attack',
    description: 'High-frequency HTTP flood causing massive frame drops & buffer starvation',
    features: {
      fps: 4.0,
      bandwidth_kbps: 120.0,
      request_rate: 185.0,
      frame_drop_rate: 82.0,
      stream_active_sessions: 12.0,
      jpeg_payload_size_kb: 12.0,
      temperature_c: 31.5,
      humidity_pct: 42.0,
      sampling_interval_sec: 3.0,
      baseline_deviation: 1.8,
      packet_rate: 190.0,
      tamper_flag: 0.0,
    },
  },
  sensor_false_data: {
    id: 'sensor_false_data',
    name: 'Sensor False Data Injection',
    badge: 'Sensor Attack',
    type: 'attack',
    description: 'Manipulated sensor packets spoofing extreme temperature and high baseline divergence',
    features: {
      fps: 25.0,
      bandwidth_kbps: 400.0,
      request_rate: 5.0,
      frame_drop_rate: 0.8,
      stream_active_sessions: 1.0,
      jpeg_payload_size_kb: 41.0,
      temperature_c: 88.5,
      humidity_pct: 98.0,
      sampling_interval_sec: 0.5,
      baseline_deviation: 7.4,
      packet_rate: 110.0,
      tamper_flag: 0.0,
    },
  },
  mirai_udp_flood: {
    id: 'mirai_udp_flood',
    name: 'Mirai Botnet UDP Flooding',
    badge: 'Mirai Botnet',
    type: 'attack',
    description: 'Volumetric UDP packet storm (150K pkts/s) saturating video bandwidth & starving heap',
    features: {
      fps: 3.5,
      bandwidth_kbps: 4800.0,
      request_rate: 210.0,
      frame_drop_rate: 88.0,
      stream_active_sessions: 14.0,
      jpeg_payload_size_kb: 10.0,
      temperature_c: 34.2,
      humidity_pct: 39.0,
      sampling_interval_sec: 1.0,
      baseline_deviation: 4.8,
      packet_rate: 220.0,
      tamper_flag: 0.0,
    },
  },
  dos_synflood: {
    id: 'dos_synflood',
    name: 'DoS TCP SYN Flooding',
    badge: 'DoS Attack',
    type: 'attack',
    description: 'TCP SYN queue exhaustion forcing camera connection timeouts and dropped frame buffers',
    features: {
      fps: 6.0,
      bandwidth_kbps: 180.0,
      request_rate: 195.0,
      frame_drop_rate: 76.0,
      stream_active_sessions: 16.0,
      jpeg_payload_size_kb: 14.0,
      temperature_c: 32.0,
      humidity_pct: 41.5,
      sampling_interval_sec: 2.0,
      baseline_deviation: 3.2,
      packet_rate: 190.0,
      tamper_flag: 0.0,
    },
  },
  scan_port_os: {
    id: 'scan_port_os',
    name: 'Port Scanning & OS Recon',
    badge: 'Reconnaissance',
    type: 'attack',
    description: 'Rapid adversarial port sweeps and protocol probing across ports 9020, 554, 8080',
    features: {
      fps: 23.0,
      bandwidth_kbps: 340.0,
      request_rate: 85.0,
      frame_drop_rate: 14.0,
      stream_active_sessions: 3.0,
      jpeg_payload_size_kb: 38.0,
      temperature_c: 25.8,
      humidity_pct: 48.0,
      sampling_interval_sec: 2.5,
      baseline_deviation: 2.8,
      packet_rate: 92.0,
      tamper_flag: 0.0,
    },
  },
  mirai_host_bruteforce: {
    id: 'mirai_host_bruteforce',
    name: 'Mirai Host Brute-Force',
    badge: 'Credential Access',
    type: 'attack',
    description: 'Automated credential stuffing and dictionary attack targeting IoT administration ports',
    features: {
      fps: 21.0,
      bandwidth_kbps: 380.0,
      request_rate: 120.0,
      frame_drop_rate: 18.0,
      stream_active_sessions: 4.0,
      jpeg_payload_size_kb: 36.0,
      temperature_c: 27.5,
      humidity_pct: 45.0,
      sampling_interval_sec: 1.5,
      baseline_deviation: 3.5,
      packet_rate: 105.0,
      tamper_flag: 0.0,
    },
  },
  hardware_tampering: {
    id: 'hardware_tampering',
    name: 'Firmware / Hardware Tampering',
    badge: 'Hardware Attack',
    type: 'attack',
    description: 'Enclosure tamper trip activated with unauthorized flash memory write attempt',
    features: {
      fps: 18.0,
      bandwidth_kbps: 260.0,
      request_rate: 22.0,
      frame_drop_rate: 8.0,
      stream_active_sessions: 2.0,
      jpeg_payload_size_kb: 35.0,
      temperature_c: 38.0,
      humidity_pct: 32.0,
      sampling_interval_sec: 2.0,
      baseline_deviation: 5.2,
      packet_rate: 65.0,
      tamper_flag: 1.0,
    },
  },
  multi_vector_recon: {
    id: 'multi_vector_recon',
    name: 'Coordinated Multi-Vector Recon',
    badge: 'Hybrid Attack',
    type: 'attack',
    description: 'Probing camera HTTP endpoints and sensor telemetry channels simultaneously',
    features: {
      fps: 22.0,
      bandwidth_kbps: 320.0,
      request_rate: 78.0,
      frame_drop_rate: 12.0,
      stream_active_sessions: 3.0,
      jpeg_payload_size_kb: 40.0,
      temperature_c: 26.0,
      humidity_pct: 49.0,
      sampling_interval_sec: 2.0,
      baseline_deviation: 2.9,
      packet_rate: 85.0,
      tamper_flag: 0.0,
    },
  },
}

const fallbackIntelligence = {
  model: { name: 'Explainable baseline', version: '0.1' },
  anomaly: { score: 0, confidence: 0.55, status: 'NORMAL' },
  classification: { label: 'No events yet', confidence: 0, evidence: 'Waiting for event data' },
  prediction: { next_likely_action: 'Awaiting observed behavior', confidence: 0 },
  mitre: { tactic: 'None', technique: 'No technique mapped', technique_id: 'N/A' },
  owasp_iot: { id: 'N/A', category: 'No OWASP IoT risk mapped', rationale: 'No suspicious behavior is currently classified.' },
  vulnerability: 'No targeted weakness identified',
  risk: { score: 0, level: 'LOW' },
  recommendations: ['Start the Flask event service', 'Connect the research dataset when available'],
  features: { event_count: 0, sequence: [] },
  dataset: { rows_loaded: 0, source: 'HITL-IoT_dataset.csv' },
}

function App() {
  const [activeTab, setActiveTab] = useState('lab') // 'lab' or 'overview'
  const [presets, setPresets] = useState(DEFAULT_PRESETS)
  const [activePresetKey, setActivePresetKey] = useState('video_exfiltration')
  const [features, setFeatures] = useState(DEFAULT_PRESETS.video_exfiltration.features)
  const [evaluation, setEvaluation] = useState(null)
  const [evaluating, setEvaluating] = useState(false)
  const [apiStatus, setApiStatus] = useState('Checking')

  const [selectedGnnNodeId, setSelectedGnnNodeId] = useState('node-2')

  // Honeypot Live Overview state
  const [overviewIntel, setOverviewIntel] = useState(fallbackIntelligence)
  const [overviewUpdated, setOverviewUpdated] = useState('Waiting')

  // Fetch presets and initial evaluation on mount
  useEffect(() => {
    fetch('http://localhost:5000/api/simulation-presets')
      .then((res) => (res.ok ? res.json() : Promise.reject()))
      .then((data) => {
        setPresets(data)
        setApiStatus('Connected')
      })
      .catch(() => {
        setApiStatus('Offline / Local Engine')
      })
  }, [])

  // Evaluate current features against backend API
  const evaluateCurrent = useCallback((featurePayload) => {
    setEvaluating(true)
    fetch('http://localhost:5000/api/simulate-behavior', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(featurePayload),
    })
      .then((res) => (res.ok ? res.json() : Promise.reject()))
      .then((data) => {
        setEvaluation(data)
        setApiStatus('Connected')
        setEvaluating(false)
      })
      .catch(() => {
        // High-fidelity local simulation fallback
        const isExfil = (featurePayload.bandwidth_kbps || 0) > 2000
        const isDos = (featurePayload.request_rate || 0) > 60 || (featurePayload.frame_drop_rate || 0) > 30
        const isSensorSpoof = Math.abs((featurePayload.temperature_c || 24) - 24) > 20 || (featurePayload.baseline_deviation || 0) > 3
        const isTamper = (featurePayload.tamper_flag || 0) > 0.5
        const isRecon = (featurePayload.request_rate || 0) > 40 && !isDos && !isExfil
        const isAnom = isExfil || isDos || isSensorSpoof || isTamper || isRecon

        const dominant = isSensorSpoof ? 'Sensor' : 'Camera'
        const score = isAnom ? (isTamper ? 0.99 : isExfil ? 0.98 : isDos ? 0.95 : isSensorSpoof ? 0.96 : 0.82) : 0.18

        let pattern = 'Normal Telemetry & Surveillance'
        let stage = { stage: 1, name: 'Reconnaissance & Footprinting', description: 'Attacker discovering active HTTP endpoints and metadata' }
        let criticalPath = 'Attacker (192.168.1.105) --> Gateway :8080 --> ESP32-CAM Core Server'
        let lateralRisk = 0.12
        let rankedActions = [
          { action: 'Routine Periodic Telemetry Polling', probability: 0.94 },
          { action: 'Scheduled Camera Keep-Alive Ping', probability: 0.04 },
          { action: 'Ambient Sensor Trend Logging', probability: 0.02 },
        ]
        let threatLevel = 'LOW'

        if (isTamper) {
          pattern = 'Firmware / Hardware Tampering'
          stage = { stage: 6, name: 'Impact, Exfiltration & C2 Persistence', description: 'Hardware tamper trip active; firmware override' }
          criticalPath = 'Attacker --> Gateway :8080 --> Core /update --> Flash Firmware Override --> C2 Backdoor'
          lateralRisk = 0.89
          rankedActions = [
            { action: 'Persistent Backdoor Installation via Malicious /update POST', probability: 0.91 },
            { action: 'Extracting Flash Keys and WiFi PSK from SPI Dump', probability: 0.06 },
            { action: 'Disabling Physical Enclosure Tamper Interrupt Handler', probability: 0.03 },
          ]
          threatLevel = 'CRITICAL'
        } else if (isExfil) {
          pattern = 'Video Stream Hijacking & Exfiltration'
          stage = { stage: 6, name: 'Impact, Exfiltration & C2 Persistence', description: 'Unauthorized high-bandwidth MJPEG stream exfiltration' }
          criticalPath = 'Attacker --> Gateway :8080 --> Camera Core --> Video FIFO Buffer --> C2 Exfiltration'
          lateralRisk = 0.64
          rankedActions = [
            { action: 'Continuous Video Frame Scraping to External C2', probability: 0.88 },
            { action: 'Internal Network Pivot from Video Pipeline to LAN', probability: 0.08 },
            { action: 'Extracting Embedded Frame Timestamp Metadata', probability: 0.04 },
          ]
          threatLevel = 'HIGH'
        } else if (isDos) {
          pattern = 'MJPEG Buffer Exhaustion / Camera DoS'
          stage = { stage: 5, name: 'Parameter Manipulation & Buffer Starvation', description: 'High-frequency request flood causing memory exhaustion' }
          criticalPath = 'Attacker --> [High-Freq Flood] --> Camera Core Server --> Memory Starvation & Drop'
          lateralRisk = 0.45
          rankedActions = [
            { action: 'Triggering ESP32 FreeRTOS Heap Panic Reboot', probability: 0.85 },
            { action: 'Saturating Gateway Socket Connection Pool', probability: 0.10 },
            { action: 'Disrupting Ambient Sensor Alert Transmissions', probability: 0.05 },
          ]
          threatLevel = 'HIGH'
        } else if (isSensorSpoof) {
          pattern = 'Sensor Telemetry Spoofing / False Data Injection'
          stage = { stage: 5, name: 'Parameter Manipulation & Buffer Starvation', description: 'Manipulated environmental sensor packets with high Z-score' }
          criticalPath = 'Attacker --> Gateway :8080 --> I2C Telemetry Bus --> False Data Injection'
          lateralRisk = 0.58
          rankedActions = [
            { action: 'Masking Physical Environmental Intrusion with Fake Baseline', probability: 0.89 },
            { action: 'Injecting Corrupted Parity Frames into I2C Sensor Bus', probability: 0.07 },
            { action: 'Overwriting Sensor Calibration Offsets in Flash', probability: 0.04 },
          ]
          threatLevel = 'HIGH'
        } else if (isRecon) {
          pattern = 'Coordinated Multi-Vector IoT Reconnaissance'
          stage = { stage: 2, name: 'Initial Gateway Access', description: 'Probing endpoints across HTTP and sensor channels' }
          criticalPath = 'Attacker --> Gateway :8080 --> [Multi-Port Probe] --> Camera & Sensor Handlers'
          lateralRisk = 0.38
          rankedActions = [
            { action: 'Targeted Credential Brute-Force on /config & /admin', probability: 0.82 },
            { action: 'Enumerating Undocumented Debug Handlers and Endpoints', probability: 0.12 },
            { action: 'Correlating Sensor Event Timing with Video Activity', probability: 0.06 },
          ]
          threatLevel = 'MEDIUM'
        }

        const localResult = {
          evaluated_features: featurePayload,
          autoencoder: {
            anomaly_score: score,
            reconstruction_loss: isAnom ? 4.821 : 0.142,
            status: isAnom ? 'ANOMALOUS' : 'NORMAL',
            is_anomalous: isAnom,
            confidence: 0.94,
            dominant_subsystem: dominant,
            camera_error_share: dominant === 'Camera' ? 78.4 : 21.6,
            sensor_error_share: dominant === 'Sensor' ? 84.2 : 15.8,
            feature_contributions: [
              { feature: isSensorSpoof ? 'temperature_c' : isExfil ? 'bandwidth_kbps' : 'request_rate', subsystem: dominant, contribution_pct: 64.2, error: isAnom ? 12.8 : 0.05, actual_value: isSensorSpoof ? featurePayload.temperature_c : isExfil ? featurePayload.bandwidth_kbps : featurePayload.request_rate },
              { feature: isSensorSpoof ? 'baseline_deviation' : isExfil ? 'stream_active_sessions' : 'frame_drop_rate', subsystem: dominant, contribution_pct: 22.1, error: isAnom ? 4.2 : 0.03, actual_value: isSensorSpoof ? featurePayload.baseline_deviation : isExfil ? featurePayload.stream_active_sessions : featurePayload.frame_drop_rate },
              { feature: 'fps', subsystem: 'Camera', contribution_pct: 7.2, error: 0.4, actual_value: featurePayload.fps },
              { feature: 'humidity_pct', subsystem: 'Sensor', contribution_pct: 6.5, error: 0.3, actual_value: featurePayload.humidity_pct },
            ],
          },
          gnn: {
            pattern,
            confidence: 0.93,
            lifecycle_stage: stage,
            next_predicted_action: rankedActions[0].action,
            next_action_confidence: rankedActions[0].probability,
            ranked_next_actions: rankedActions,
            critical_attack_path: criticalPath,
            lateral_movement_risk: lateralRisk,
            graph_metrics: {
              node_count: 7,
              edge_count: 9,
              active_threat_edges: isAnom ? 4 : 1,
              graph_density: 0.214,
              attacker_centrality: isAnom ? 0.78 : 0.15,
            },
            graph_topology: {
              nodes: [
                { id: 'node-0', index: 0, name: 'Attacker Entity', type: 'attacker', subsystem: 'External Network', ip: '192.168.1.105', pos: { x: 55, y: 130 }, threat_score: isAnom ? 0.95 : 0.1, active: isAnom, highlighted: isAnom },
                { id: 'node-1', index: 1, name: 'Gateway / Reverse Proxy', type: 'gateway', subsystem: 'Perimeter', ip: ':8080 / TCP', pos: { x: 190, y: 130 }, threat_score: isAnom ? 0.85 : 0.2, active: true, highlighted: isAnom },
                { id: 'node-2', index: 2, name: 'ESP32-CAM Core Server', type: 'core', subsystem: 'Honeypot Core', ip: 'ESP32 Task Loop', pos: { x: 340, y: 80 }, threat_score: isAnom && dominant === 'Camera' ? 0.92 : 0.25, active: true, highlighted: isAnom && dominant === 'Camera' },
                { id: 'node-3', index: 3, name: 'Video Frame Buffer', type: 'camera', subsystem: 'OV2640 DMA FIFO', ip: '/stream & /snapshot', pos: { x: 510, y: 55 }, threat_score: isExfil || isDos ? 0.94 : 0.15, active: isExfil || isDos, highlighted: isExfil },
                { id: 'node-4', index: 4, name: 'Telemetry Sensor Bus', type: 'sensor', subsystem: 'I2C Sensor Controller', ip: '/status & Telemetry', pos: { x: 340, y: 195 }, threat_score: isSensorSpoof ? 0.93 : 0.18, active: isSensorSpoof || !isAnom, highlighted: isSensorSpoof },
                { id: 'node-5', index: 5, name: 'Device Configuration & Flash', type: 'storage', subsystem: 'SPI Flash / NVS', ip: '/config & /update', pos: { x: 510, y: 180 }, threat_score: isTamper ? 0.98 : 0.12, active: isTamper, highlighted: isTamper },
                { id: 'node-6', index: 6, name: 'Exfiltration & C2 Sink', type: 'c2', subsystem: 'Adversary Infrastructure', ip: 'Simulated C2 Drop', pos: { x: 660, y: 120 }, threat_score: isExfil || isTamper ? 0.96 : 0.05, active: isExfil || isTamper, highlighted: isExfil || isTamper },
              ],
              edges: [
                { id: 'edge-0', from: 'node-0', to: 'node-1', from_index: 0, to_index: 1, label: 'Ingress Probe', protocol: 'HTTP / RTSP', attention_weight: isAnom ? 0.88 : 0.15, alert: isAnom, critical: isAnom },
                { id: 'edge-1', from: 'node-1', to: 'node-2', from_index: 1, to_index: 2, label: 'HTTP Dispatch', protocol: 'GET /stream', attention_weight: isExfil || isDos ? 0.92 : 0.2, alert: isExfil || isDos, critical: isExfil },
                { id: 'edge-2', from: 'node-1', to: 'node-4', from_index: 1, to_index: 4, label: 'Telemetry Poll', protocol: 'GET /status', attention_weight: isSensorSpoof ? 0.91 : 0.18, alert: isSensorSpoof, critical: isSensorSpoof },
                { id: 'edge-3', from: 'node-2', to: 'node-3', from_index: 2, to_index: 3, label: 'Frame Capture', protocol: 'DMA FIFO', attention_weight: isExfil ? 0.95 : 0.25, alert: isExfil, critical: isExfil },
                { id: 'edge-4', from: 'node-2', to: 'node-5', from_index: 2, to_index: 5, label: 'Config / Update', protocol: 'POST /update', attention_weight: isTamper ? 0.97 : 0.1, alert: isTamper, critical: isTamper },
                { id: 'edge-5', from: 'node-3', to: 'node-6', from_index: 3, to_index: 6, label: 'Video Stream Sink', protocol: 'MPEG-TS Out', attention_weight: isExfil ? 0.96 : 0.05, alert: isExfil, critical: isExfil },
                { id: 'edge-6', from: 'node-4', to: 'node-2', from_index: 4, to_index: 2, label: 'Sensor Trigger', protocol: 'I2C Alert', attention_weight: isSensorSpoof ? 0.85 : 0.1, alert: isSensorSpoof, critical: false },
                { id: 'edge-7', from: 'node-5', to: 'node-6', from_index: 5, to_index: 6, label: 'C2 Beacon', protocol: 'TCP Outbound', attention_weight: isTamper ? 0.98 : 0.05, alert: isTamper, critical: isTamper },
                { id: 'edge-8', from: 'node-0', to: 'node-2', from_index: 0, to_index: 2, label: 'Direct Flood', protocol: 'SYN / GET Flood', attention_weight: isDos ? 0.94 : 0.05, alert: isDos, critical: isDos },
              ],
            },
          },
          llm_analysis: {
            threat_level: threatLevel,
            executive_summary: isAnom
              ? `ADVERSARIAL ALERT: ${pattern} detected on connected IoT endpoints. Autoencoder flagged anomalous reconstruction divergence (${dominant} subsystem), and GNN isolated active ${stage.name}.`
              : 'NORMAL OPERATION: Telemetry from both the ESP32-CAM video pipeline and ambient environmental sensors conforms to safe baseline distributions.',
            telemetry_diagnostic: `Camera: ${featurePayload.fps} FPS at ${featurePayload.bandwidth_kbps} KB/s (${featurePayload.request_rate} req/min). Sensor: ${featurePayload.temperature_c}°C at ${featurePayload.humidity_pct}% RH with Z-score deviation ${featurePayload.baseline_deviation}.`,
            mitre: {
              tactic: isExfil ? 'Exfiltration' : isDos ? 'Impact' : isSensorSpoof ? 'Data Manipulation' : isTamper ? 'Persistence' : isRecon ? 'Discovery' : 'None',
              technique: isExfil ? 'Exfiltration Over Web Service' : isDos ? 'Endpoint Denial of Service' : isSensorSpoof ? 'Transmitted Data Manipulation' : isTamper ? 'Firmware Corruption' : isRecon ? 'Network Service Scanning' : 'Normal Operation',
              technique_id: isExfil ? 'T1567.002' : isDos ? 'T1499.002' : isSensorSpoof ? 'T1565.001' : isTamper ? 'T1542.001' : isRecon ? 'T1046' : 'N/A',
            },
            owasp_iot: {
              id: isAnom ? (isTamper ? 'I4' : isSensorSpoof ? 'I7' : 'I2') : 'N/A',
              category: isAnom ? (isTamper ? 'Lack of Secure Update & Enclosure' : isSensorSpoof ? 'Insecure Data Transfer' : 'Insecure Network Services') : 'Baseline Telemetry',
              rationale: isAnom ? 'Telemetry metrics severely deviated from physical operational bounds.' : 'No anomalies detected.',
            },
            attacker_stage: stage,
            predicted_progression: nextAction,
            response_playbook: isAnom
              ? [
                  'Isolate targeted device IP on IoT gateway firewall rules',
                  'Terminate unauthorized active HTTP/MJPEG streaming sessions',
                  'Enable sensor integrity validation checks in ingestion pipeline',
                  'Verify ESP32 firmware signature and configuration parameters',
                ]
              : ['Maintain routine polling', 'Keep camera credentials rotated'],
            timestamp: new Date().toISOString(),
          },
        }

        setEvaluation(localResult)
        setEvaluating(false)
      })
  }, [])

  // Evaluate on load or when features change
  useEffect(() => {
    evaluateCurrent(features)
  }, [features, evaluateCurrent])

  // Select a preset
  const handleSelectPreset = (key) => {
    setActivePresetKey(key)
    const preset = presets[key] || DEFAULT_PRESETS[key]
    if (preset) {
      setFeatures({ ...preset.features })
    }
  }

  // Update a single feature slider
  const handleFeatureChange = (key, val) => {
    const num = parseFloat(val)
    setFeatures((prev) => ({ ...prev, [key]: num }))
    setActivePresetKey('custom')
  }

  // Live Honeypot Overview poller
  useEffect(() => {
    let active = true
    const loadOverview = () => {
      fetch('http://localhost:5000/api/dataset-intelligence')
        .then((res) => (res.ok ? res.json() : Promise.reject()))
        .then((result) => {
          if (!active) return
          setOverviewIntel(result)
          setOverviewUpdated(new Date().toLocaleTimeString())
        })
        .catch(() => {
          if (!active) return
          setOverviewIntel(fallbackIntelligence)
        })
    }
    loadOverview()
    const timer = setInterval(loadOverview, 6000)
    return () => {
      active = false
      clearInterval(timer)
    }
  }, [])

  const autoencoder = evaluation?.autoencoder
  const gnn = evaluation?.gnn
  const llm = evaluation?.llm_analysis

  return (
    <main className="ai-console">
      {/* Top Header & Lab Navigation */}
      <header className="ai-header">
        <div>
          <div className="ai-header-badge-row">
            <span className="ai-eyebrow">IoT Threat Intelligence Platform</span>
            <span className={`service-status-pill ${apiStatus.includes('Connected') ? 'online' : 'offline'}`}>
              <i className="status-dot" /> {apiStatus}
            </span>
          </div>
          <h1>Camera &amp; Sensor Behavioral AI Studio</h1>
          <p className="ai-description">
            Multivariate Anomaly Detection (Autoencoder) • Relational Graph Pattern Tracking (GNN) • Security Threat Briefing (LLM)
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="tab-switcher">
          <button
            type="button"
            className={`tab-btn ${activeTab === 'lab' ? 'active' : ''}`}
            onClick={() => setActiveTab('lab')}
          >
            <span className="tab-icon">🔬</span>
            <span>Camera &amp; Sensor AI Lab</span>
          </button>
          <button
            type="button"
            className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            <span className="tab-icon">📡</span>
            <span>Live Honeypot Overview</span>
          </button>
        </div>
      </header>

      {/* ========================================================================= */}
      {/* TAB 1: CAMERA & SENSOR BEHAVIORAL AI LAB                                  */}
      {/* ========================================================================= */}
      {activeTab === 'lab' && (
        <div className="lab-container">
          {/* Preset Scenario Selector */}
          <section className="scenario-selector-section">
            <div className="section-title-row">
              <h3>Behavioral Test Scenarios</h3>
              <span className="hint-label">Select a calibrated scenario or fine-tune sliders below</span>
            </div>

            <div className="preset-chips-grid">
              {Object.entries(presets).map(([key, preset]) => {
                const isSelected = activePresetKey === key
                const isAttack = preset.type === 'attack'
                return (
                  <button
                    key={key}
                    type="button"
                    className={`preset-chip ${isSelected ? 'selected' : ''} ${isAttack ? 'attack' : 'normal'}`}
                    onClick={() => handleSelectPreset(key)}
                  >
                    <div className="chip-header">
                      <span className={`chip-badge ${isAttack ? 'danger' : 'safe'}`}>
                        {preset.badge || (isAttack ? 'Attack' : 'Benign')}
                      </span>
                      {isSelected && <span className="chip-active-indicator">ACTIVE</span>}
                    </div>
                    <strong>{preset.name}</strong>
                    <p>{preset.description}</p>
                  </button>
                )
              })}
            </div>
          </section>

          {/* Interactive Testing Fields (Camera vs Sensors) */}
          <section className="telemetry-control-deck">
            {/* Camera Controls Deck */}
            <div className="deck-card camera-deck">
              <div className="deck-header">
                <div className="deck-title">
                  <span className="deck-icon">📹</span>
                  <div>
                    <h4>ESP32-CAM Video Pipeline</h4>
                    <small>Streaming, frame encoding, &amp; HTTP traffic</small>
                  </div>
                </div>
                <span className="deck-tag">CAMERA SUBSYSTEM</span>
              </div>

              <div className="control-grid">
                <div className="control-item">
                  <div className="control-label-row">
                    <span>Frame Rate (FPS)</span>
                    <b>{features.fps} fps</b>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="60"
                    step="1"
                    value={features.fps}
                    onChange={(e) => handleFeatureChange('fps', e.target.value)}
                  />
                  <div className="slider-hints"><span>0 (Idle)</span><span>Nominal: 25-30</span><span>60 (Burst)</span></div>
                </div>

                <div className="control-item">
                  <div className="control-label-row">
                    <span>Bandwidth Throughput</span>
                    <b>{features.bandwidth_kbps} KB/s</b>
                  </div>
                  <input
                    type="range"
                    min="50"
                    max="6000"
                    step="50"
                    value={features.bandwidth_kbps}
                    onChange={(e) => handleFeatureChange('bandwidth_kbps', e.target.value)}
                  />
                  <div className="slider-hints"><span>50 KB/s</span><span>Nominal: 420 KB/s</span><span>6000 KB/s (Exfil)</span></div>
                </div>

                <div className="control-item">
                  <div className="control-label-row">
                    <span>HTTP Request Rate</span>
                    <b>{features.request_rate} req/min</b>
                  </div>
                  <input
                    type="range"
                    min="1"
                    max="200"
                    step="1"
                    value={features.request_rate}
                    onChange={(e) => handleFeatureChange('request_rate', e.target.value)}
                  />
                  <div className="slider-hints"><span>1 req/m</span><span>Nominal: 2-8</span><span>200 req/m (Flood)</span></div>
                </div>

                <div className="control-item">
                  <div className="control-label-row">
                    <span>Frame Drop Rate</span>
                    <b className={features.frame_drop_rate > 25 ? 'text-danger' : ''}>{features.frame_drop_rate}%</b>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    step="0.5"
                    value={features.frame_drop_rate}
                    onChange={(e) => handleFeatureChange('frame_drop_rate', e.target.value)}
                  />
                  <div className="slider-hints"><span>0%</span><span>Nominal: &lt;2%</span><span>100% (Starvation)</span></div>
                </div>

                <div className="control-item">
                  <div className="control-label-row">
                    <span>Active Stream Sessions</span>
                    <b>{features.stream_active_sessions} client(s)</b>
                  </div>
                  <input
                    type="range"
                    min="1"
                    max="15"
                    step="1"
                    value={features.stream_active_sessions}
                    onChange={(e) => handleFeatureChange('stream_active_sessions', e.target.value)}
                  />
                  <div className="slider-hints"><span>1 Client</span><span>Nominal: 1</span><span>15 Clients (Hijack)</span></div>
                </div>

                <div className="control-item">
                  <div className="control-label-row">
                    <span>Avg JPEG Frame Size</span>
                    <b>{features.jpeg_payload_size_kb} KB</b>
                  </div>
                  <input
                    type="range"
                    min="5"
                    max="150"
                    step="1"
                    value={features.jpeg_payload_size_kb}
                    onChange={(e) => handleFeatureChange('jpeg_payload_size_kb', e.target.value)}
                  />
                  <div className="slider-hints"><span>5 KB</span><span>Nominal: 40 KB</span><span>150 KB</span></div>
                </div>
              </div>
            </div>

            {/* Sensor Controls Deck */}
            <div className="deck-card sensor-deck">
              <div className="deck-header">
                <div className="deck-title">
                  <span className="deck-icon">🌡️</span>
                  <div>
                    <h4>IoT Sensor &amp; Telemetry Bus</h4>
                    <small>Environmental I2C sensors &amp; baseline deviations</small>
                  </div>
                </div>
                <span className="deck-tag sensor-tag">SENSOR SUBSYSTEM</span>
              </div>

              <div className="control-grid">
                <div className="control-item">
                  <div className="control-label-row">
                    <span>Ambient Temperature</span>
                    <b className={Math.abs(features.temperature_c - 24) > 15 ? 'text-danger' : ''}>{features.temperature_c}°C</b>
                  </div>
                  <input
                    type="range"
                    min="-10"
                    max="100"
                    step="0.5"
                    value={features.temperature_c}
                    onChange={(e) => handleFeatureChange('temperature_c', e.target.value)}
                  />
                  <div className="slider-hints"><span>-10°C</span><span>Nominal: 22-26°C</span><span>100°C (Spoof)</span></div>
                </div>

                <div className="control-item">
                  <div className="control-label-row">
                    <span>Relative Humidity</span>
                    <b>{features.humidity_pct}%</b>
                  </div>
                  <input
                    type="range"
                    min="10"
                    max="100"
                    step="1"
                    value={features.humidity_pct}
                    onChange={(e) => handleFeatureChange('humidity_pct', e.target.value)}
                  />
                  <div className="slider-hints"><span>10%</span><span>Nominal: 40-55%</span><span>100%</span></div>
                </div>

                <div className="control-item">
                  <div className="control-label-row">
                    <span>Reporting Interval</span>
                    <b>{features.sampling_interval_sec} sec</b>
                  </div>
                  <input
                    type="range"
                    min="0.2"
                    max="30"
                    step="0.2"
                    value={features.sampling_interval_sec}
                    onChange={(e) => handleFeatureChange('sampling_interval_sec', e.target.value)}
                  />
                  <div className="slider-hints"><span>0.2s (Burst)</span><span>Nominal: 10s</span><span>30s (Delayed)</span></div>
                </div>

                <div className="control-item">
                  <div className="control-label-row">
                    <span>Baseline Deviation (Z-score)</span>
                    <b className={features.baseline_deviation > 2 ? 'text-danger' : ''}>+{features.baseline_deviation} Z</b>
                  </div>
                  <input
                    type="range"
                    min="-2"
                    max="10"
                    step="0.1"
                    value={features.baseline_deviation}
                    onChange={(e) => handleFeatureChange('baseline_deviation', e.target.value)}
                  />
                  <div className="slider-hints"><span>0 Z</span><span>Nominal: &lt;0.5 Z</span><span>+10 Z (False Data)</span></div>
                </div>

                <div className="control-item">
                  <div className="control-label-row">
                    <span>Packet Transmission Rate</span>
                    <b>{features.packet_rate} pkt/s</b>
                  </div>
                  <input
                    type="range"
                    min="1"
                    max="250"
                    step="1"
                    value={features.packet_rate}
                    onChange={(e) => handleFeatureChange('packet_rate', e.target.value)}
                  />
                  <div className="slider-hints"><span>1 pkt/s</span><span>Nominal: 12 pkt/s</span><span>250 pkt/s</span></div>
                </div>

                <div className="control-item">
                  <div className="control-label-row">
                    <span>Hardware Enclosure Tamper</span>
                    <b className={features.tamper_flag ? 'text-danger' : 'text-safe'}>
                      {features.tamper_flag ? 'TRIPPED (ACTIVE)' : 'DISARMED (SAFE)'}
                    </b>
                  </div>
                  <div className="toggle-switch-wrapper">
                    <button
                      type="button"
                      className={`tamper-toggle-btn ${features.tamper_flag ? 'tripped' : 'safe'}`}
                      onClick={() => handleFeatureChange('tamper_flag', features.tamper_flag ? 0 : 1)}
                    >
                      {features.tamper_flag ? '⚠️ Tamper Trip Active' : '🛡️ Tamper Line Normal'}
                    </button>
                  </div>
                  <div className="slider-hints"><span>0: Intact</span><span /><span>1: Chassis Open</span></div>
                </div>
              </div>
            </div>
          </section>

          {/* Action Bar */}
          <div className="pipeline-action-bar">
            <div className="action-info">
              <span>Selected Configuration: <strong>{activePresetKey === 'custom' ? 'Custom Tuned Telemetry' : presets[activePresetKey]?.name}</strong></span>
            </div>
            <button
              type="button"
              className="eval-btn"
              disabled={evaluating}
              onClick={() => evaluateCurrent(features)}
            >
              {evaluating ? 'Evaluating Pipeline...' : '⚡ Re-Evaluate AI Pipeline'}
            </button>
          </div>

          {/* ===================================================================== */}
          {/* THREE-TIER AI PIPELINE RESULTS                                        */}
          {/* ===================================================================== */}
          <section className="pipeline-results-grid">
            {/* 1. AUTOENCODER ANOMALY INSPECTOR */}
            <article className="ai-glass-card autoencoder-card">
              <div className="card-top-bar">
                <span className="card-stage-tag">MODEL 1: AUTOENCODER</span>
                <span className={`status-pill ${autoencoder?.status === 'ANOMALOUS' ? 'danger' : 'safe'}`}>
                  {autoencoder?.status || 'NORMAL'}
                </span>
              </div>

              <h3>Multivariate Anomaly Detection</h3>
              <p className="card-subtext">Deep Bottleneck Reconstruction (12 → 32 → 8 → 32 → 12)</p>

              {/* Gauge Score Circle */}
              <div className="gauge-container">
                <div className={`score-radial ${autoencoder?.status === 'ANOMALOUS' ? 'anomalous' : 'normal'}`}>
                  <span className="score-value">{(autoencoder?.anomaly_score || 0).toFixed(2)}</span>
                  <span className="score-subtext">Anomaly Score</span>
                </div>
                <div className="gauge-metrics">
                  <div className="metric-box">
                    <span>Reconstruction MSE</span>
                    <strong>{autoencoder?.reconstruction_loss?.toFixed(4) || '0.0000'}</strong>
                  </div>
                  <div className="metric-box">
                    <span>Model Confidence</span>
                    <strong>{Math.round((autoencoder?.confidence || 0) * 100)}%</strong>
                  </div>
                  <div className="metric-box">
                    <span>Dominant Source</span>
                    <strong className={autoencoder?.dominant_subsystem === 'Camera' ? 'text-camera' : 'text-sensor'}>
                      {autoencoder?.dominant_subsystem || 'Camera'}
                    </strong>
                  </div>
                </div>
              </div>

              {/* Subsystem Error Ratio Comparison */}
              <div className="subsystem-ratio-box">
                <div className="ratio-labels">
                  <span>Camera Error: {autoencoder?.camera_error_share || 50}%</span>
                  <span>Sensor Error: {autoencoder?.sensor_error_share || 50}%</span>
                </div>
                <div className="ratio-track">
                  <i className="camera-fill" style={{ width: `${autoencoder?.camera_error_share || 50}%` }} />
                  <i className="sensor-fill" style={{ width: `${autoencoder?.sensor_error_share || 50}%` }} />
                </div>
              </div>

              {/* Feature Error Decomposition */}
              <div className="feature-decomposition">
                <h4>Root-Cause Feature Contributors</h4>
                <div className="contribution-bars-list">
                  {(autoencoder?.feature_contributions || []).slice(0, 5).map((item) => (
                    <div className="contrib-row" key={item.feature}>
                      <div className="contrib-header">
                        <span className="feature-name">
                          <i className={`subsystem-indicator ${item.subsystem.toLowerCase()}`} />
                          {item.feature.replaceAll('_', ' ')}
                        </span>
                        <span className="contrib-value">{item.contribution_pct}%</span>
                      </div>
                      <div className="contrib-track">
                        <i
                          className={`contrib-fill ${item.subsystem.toLowerCase()}`}
                          style={{ width: `${Math.min(100, item.contribution_pct)}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </article>

            {/* 2. GNN ATTACKER PATTERN GRAPH VISUALIZER */}
            <article className="ai-glass-card gnn-card">
              <div className="card-top-bar">
                <span className="card-stage-tag">MODEL 2: GRAPH ATTENTION NETWORK (GNN)</span>
                <span className="confidence-pill">{Math.round((gnn?.confidence || 0) * 100)}% Graph Match</span>
              </div>

              <h3>Attacker Relational Pattern &amp; Lateral Propagation</h3>
              <p className="card-subtext">2-Hop Message Passing with Edge Attention across 7 Heterogeneous IoT Subsystems</p>

              {/* Pattern Banner */}
              <div className="pattern-banner">
                <div className="pattern-banner-header">
                  <span>CLASSIFIED ATTACK PATTERN</span>
                  <span className="pattern-stage-badge">Stage {gnn?.lifecycle_stage?.stage || 1} of 6</span>
                </div>
                <h4>{gnn?.pattern || 'Normal Telemetry & Surveillance'}</h4>
              </div>

              {/* Critical Attack Path Corridor */}
              <div className="critical-path-banner">
                <div className="critical-path-label">
                  <i className="pulse-beacon-red" />
                  <span>PRIMARY ATTACK CORRIDOR</span>
                </div>
                <code>{gnn?.critical_attack_path || 'Attacker -> Gateway :8080 -> ESP32-CAM Core'}</code>
              </div>

              {/* SVG Topology Attack Canvas */}
              <div className="svg-topology-container">
                <div className="topology-title-row">
                  <span>HETEROGENEOUS IOT TOPOLOGY GRAPH (Click any node to inspect)</span>
                  <small>7 Nodes • 9 Directed Channels</small>
                </div>

                <svg className="gnn-svg-canvas" viewBox="0 0 740 250">
                  <defs>
                    <filter id="glow-red" x="-20%" y="-20%" width="140%" height="140%">
                      <feGaussianBlur stdDeviation="3" result="blur" />
                      <feComposite in="SourceGraphic" in2="blur" operator="over" />
                    </filter>
                    <filter id="glow-blue" x="-20%" y="-20%" width="140%" height="140%">
                      <feGaussianBlur stdDeviation="3" result="blur" />
                      <feComposite in="SourceGraphic" in2="blur" operator="over" />
                    </filter>
                    <marker id="arrow-alert" markerWidth="8" markerHeight="8" refX="16" refY="4" orient="auto">
                      <polygon points="0 0, 8 4, 0 8" fill="#f43f5e" />
                    </marker>
                    <marker id="arrow-normal" markerWidth="6" markerHeight="6" refX="14" refY="3" orient="auto">
                      <polygon points="0 0, 6 3, 0 6" fill="#64748b" />
                    </marker>
                  </defs>

                  {/* Edges */}
                  {(gnn?.graph_topology?.edges || []).map((edge) => {
                    const nodes = gnn?.graph_topology?.nodes || []
                    const src = nodes.find((n) => n.id === edge.from)?.pos || { x: 50, y: 130 }
                    const dst = nodes.find((n) => n.id === edge.to)?.pos || { x: 200, y: 130 }
                    const isAlert = edge.alert
                    const isCritical = edge.critical
                    const midX = (src.x + dst.x) / 2
                    const midY = (src.y + dst.y) / 2 + (src.y === dst.y ? (src.x > 300 ? -22 : 18) : (src.x === 0 ? 12 : -10))

                    return (
                      <g key={edge.id} className="svg-edge-group">
                        <path
                          d={`M ${src.x} ${src.y} Q ${midX} ${midY} ${dst.x} ${dst.y}`}
                          className={`svg-edge-path ${isCritical ? 'critical-flow' : isAlert ? 'alert-flow' : 'normal-flow'}`}
                          markerEnd={isAlert ? 'url(#arrow-alert)' : 'url(#arrow-normal)'}
                        />
                        {isAlert && (
                          <text x={midX} y={midY - 4} className="svg-edge-label">
                            α: {edge.attention_weight}
                          </text>
                        )}
                      </g>
                    )
                  })}

                  {/* Nodes */}
                  {(gnn?.graph_topology?.nodes || []).map((node) => {
                    const isSelected = selectedGnnNodeId === node.id
                    const isDanger = node.highlighted
                    const isThreat = node.active
                    const icons = ['🦹', '🌐', '🖥️', '📹', '🌡️', '💾', '📡']
                    const icon = icons[node.index] || '⚪'

                    return (
                      <g
                        key={node.id}
                        transform={`translate(${node.pos.x}, ${node.pos.y})`}
                        className={`svg-node-group ${isSelected ? 'selected' : ''} ${isDanger ? 'danger' : isThreat ? 'threat' : 'nominal'}`}
                        onClick={() => setSelectedGnnNodeId(node.id)}
                      >
                        {/* Outer status ring */}
                        <circle
                          r={isSelected ? 22 : 18}
                          className="node-circle-outer"
                          filter={isDanger ? 'url(#glow-red)' : isSelected ? 'url(#glow-blue)' : undefined}
                        />
                        <circle r={isSelected ? 18 : 15} className="node-circle-inner" />
                        <text textAnchor="middle" dy="5" className="node-icon-text">{icon}</text>
                        <text textAnchor="middle" dy="28" className="node-label-text">{node.name.split(' ')[0]}</text>
                        <text textAnchor="middle" dy="38" className="node-sub-text">{node.ip.split(' ')[0]}</text>

                        {/* Threat score chip badge */}
                        <g transform="translate(10, -14)">
                          <rect
                            x="0"
                            y="0"
                            width="28"
                            height="13"
                            rx="4"
                            className={`threat-chip ${node.threat_score >= 0.7 ? 'danger' : node.threat_score >= 0.3 ? 'warn' : 'safe'}`}
                          />
                          <text x="14" y="9" textAnchor="middle" className="threat-chip-text">
                            {node.threat_score.toFixed(2)}
                          </text>
                        </g>
                      </g>
                    )
                  })}
                </svg>

                <div className="topology-legend-bar">
                  <span className="legend-item"><i className="leg-dot critical" /> Primary Attack Corridor (α &gt; 0.7)</span>
                  <span className="legend-item"><i className="leg-dot active" /> Elevated Message Weight</span>
                  <span className="legend-item"><i className="leg-dot normal" /> Steady-State Internal Bus</span>
                </div>
              </div>

              {/* Selected Node Inspector Drawer */}
              {selectedGnnNodeId && (() => {
                const selNode = (gnn?.graph_topology?.nodes || []).find((n) => n.id === selectedGnnNodeId) || gnn?.graph_topology?.nodes?.[0]
                if (!selNode) return null
                return (
                  <div className="node-inspector-box">
                    <div className="inspector-top">
                      <div className="inspector-title">
                        <span className="inspector-icon">
                          {['🦹', '🌐', '🖥️', '📹', '🌡️', '💾', '📡'][selNode.index] || '⚪'}
                        </span>
                        <div>
                          <strong>{selNode.name}</strong>
                          <small>{selNode.subsystem} • {selNode.ip}</small>
                        </div>
                      </div>
                      <div className="inspector-score">
                        <span>Node Threat Intensity</span>
                        <b className={selNode.threat_score >= 0.6 ? 'text-danger' : 'text-safe'}>
                          {Math.round(selNode.threat_score * 100)}% ({selNode.threat_score >= 0.6 ? 'COMPROMISED / TARGET' : 'NOMINAL'})
                        </b>
                      </div>
                    </div>
                  </div>
                )
              })()}

              {/* Structural Graph Diagnostics */}
              <div className="graph-diagnostics-grid">
                <div className="diag-card">
                  <span>Lateral Pivot Risk</span>
                  <strong className={gnn?.lateral_movement_risk >= 0.5 ? 'text-danger' : 'text-safe'}>
                    {Math.round((gnn?.lateral_movement_risk || 0) * 100)}%
                  </strong>
                  <small>Subsystem Pivot Probability</small>
                </div>
                <div className="diag-card">
                  <span>Active Threat Channels</span>
                  <strong>{gnn?.graph_metrics?.active_threat_edges || 0} / {gnn?.graph_metrics?.edge_count || 9}</strong>
                  <small>Alerted Interaction Edges</small>
                </div>
                <div className="diag-card">
                  <span>Attacker Centrality</span>
                  <strong>{(gnn?.graph_metrics?.attacker_centrality || 0).toFixed(2)}</strong>
                  <small>Adversary Influence Radius</small>
                </div>
                <div className="diag-card">
                  <span>Graph Density</span>
                  <strong>{(gnn?.graph_metrics?.graph_density || 0).toFixed(3)}</strong>
                  <small>Directed Subgraph Volume</small>
                </div>
              </div>

              {/* 6-Stage Attack Lifecycle Timeline */}
              <div className="lifecycle-timeline">
                <h4>6-Stage Attack Progression Lifecycle</h4>
                <div className="stages-row six-stages">
                  {[1, 2, 3, 4, 5, 6].map((step) => {
                    const currentStageNum = gnn?.lifecycle_stage?.stage || 1
                    const isPassed = step <= currentStageNum
                    const isCurrent = step === currentStageNum
                    const stageNames = ['Recon', 'Gateway', 'Bypass', 'Pivot', 'Tamper', 'Impact']
                    return (
                      <div
                        key={step}
                        className={`stage-step ${isPassed ? 'passed' : ''} ${isCurrent ? 'current' : ''}`}
                      >
                        <div className="step-circle">{isPassed ? '✓' : step}</div>
                        <span className="step-name">{stageNames[step - 1]}</span>
                      </div>
                    )
                  })}
                </div>
                <div className="current-stage-desc">
                  <strong>Stage {gnn?.lifecycle_stage?.stage || 1}: {gnn?.lifecycle_stage?.name}</strong>
                  <p>{gnn?.lifecycle_stage?.description}</p>
                </div>
              </div>

              {/* Ranked Next-Action Contingencies */}
              <div className="next-move-card multi-contingency">
                <div className="next-move-header">
                  <span>RANKED NEXT ATTACKER CONTINGENCIES (TOP 3)</span>
                  <span className="prob-badge">Predictive GNN Head</span>
                </div>
                <div className="contingencies-list">
                  {(gnn?.ranked_next_actions || [
                    { action: gnn?.next_predicted_action || 'Routine Telemetry Polling', probability: gnn?.next_action_confidence || 0.9 }
                  ]).map((item, idx) => (
                    <div className="contingency-item" key={item.action}>
                      <div className="contingency-header">
                        <span className="rank-tag">#{idx + 1}</span>
                        <span className="action-desc">{item.action}</span>
                        <b className="action-prob">{Math.round(item.probability * 100)}%</b>
                      </div>
                      <div className="action-track">
                        <i
                          className={`action-fill rank-${idx + 1}`}
                          style={{ width: `${Math.round(item.probability * 100)}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </article>

            {/* 3. LLM SECURITY INTELLIGENCE BRIEFING */}
            <article className="ai-glass-card llm-card">
              <div className="card-top-bar">
                <span className="card-stage-tag">MODEL 3: LLM ANALYST</span>
                <span className={`threat-badge ${llm?.threat_level?.toLowerCase() || 'low'}`}>
                  {llm?.threat_level || 'LOW'} SEVERITY
                </span>
              </div>

              <h3>Security Intelligence Threat Report</h3>
              <p className="card-subtext">Automated Incident Response &amp; MITRE / OWASP Diagnostic</p>

              {/* Executive Summary */}
              <div className="analyst-block summary-block">
                <h4>Executive Threat Assessment</h4>
                <p>{llm?.executive_summary}</p>
              </div>

              {/* Telemetry Diagnostics */}
              <div className="analyst-block diagnostic-block">
                <h4>Telemetry Diagnostics</h4>
                <p>{llm?.telemetry_diagnostic}</p>
              </div>

              {/* MITRE & OWASP Dual Cards */}
              <div className="dual-framework-row">
                <div className="framework-mini-card mitre">
                  <div className="framework-header">
                    <span>MITRE ATT&amp;CK</span>
                    <b>{llm?.mitre?.technique_id}</b>
                  </div>
                  <strong>{llm?.mitre?.technique}</strong>
                  <small>Tactic: {llm?.mitre?.tactic}</small>
                </div>

                <div className="framework-mini-card owasp">
                  <div className="framework-header">
                    <span>OWASP IoT TOP 10</span>
                    <b>{llm?.owasp_iot?.id}</b>
                  </div>
                  <strong>{llm?.owasp_iot?.category}</strong>
                  <small>{llm?.owasp_iot?.rationale}</small>
                </div>
              </div>

              {/* Recommended Blue-Team Response Playbook */}
              <div className="playbook-box">
                <h4>Actionable Blue-Team Containment Playbook</h4>
                <ul className="playbook-checklist">
                  {(llm?.response_playbook || []).map((step, idx) => (
                    <li key={step}>
                      <span className="step-num">{idx + 1}</span>
                      <span>{step}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </article>
          </section>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: LIVE HONEYPOT OVERVIEW (Preserved)                                  */}
      {/* ========================================================================= */}
      {activeTab === 'overview' && (
        <div className="overview-container">
          <section className="ai-summary-grid">
            <article className="ai-score-card">
              <span>Honeypot Anomaly Score</span>
              <strong>{(overviewIntel.anomaly.score || 0).toFixed(2)}</strong>
              <small>{Math.round((overviewIntel.anomaly.confidence || 0) * 100)}% confidence</small>
              <b className={overviewIntel.anomaly.status === 'MALICIOUS' ? 'danger' : 'safe'}>
                {overviewIntel.anomaly.status}
              </b>
            </article>
            <article className="ai-score-card">
              <span>Global Risk Level</span>
              <strong>{overviewIntel.risk.level}</strong>
              <small>{Math.round((overviewIntel.risk.score || 0) * 100)}% risk score</small>
              <div className="risk-meter"><i style={{ width: `${Math.round((overviewIntel.risk.score || 0) * 100)}%` }} /></div>
            </article>
            <article className="ai-score-card">
              <span>Events Analyzed</span>
              <strong>{overviewIntel.dataset?.rows_loaded || overviewIntel.features.event_count || 0}</strong>
              <small>{overviewIntel.dataset?.source || 'HITL-IoT_dataset.csv'}</small>
            </article>
          </section>

          <section className="ai-section">
            <div className="ai-section-heading">
              <h2>Detection &amp; Categorization</h2>
              <span>Updated: {overviewUpdated}</span>
            </div>
            <div className="ai-card-grid">
              <article className="ai-card">
                <span>Attack Classification</span>
                <strong>{overviewIntel.classification.label}</strong>
                <small>{Math.round((overviewIntel.classification.confidence || 0) * 100)}% confidence</small>
                <p>{overviewIntel.classification.evidence}</p>
              </article>
              <article className="ai-card">
                <span>Next Likely Action</span>
                <strong>{overviewIntel.prediction.next_likely_action}</strong>
                <small>{Math.round((overviewIntel.prediction.confidence || 0) * 100)}% confidence</small>
              </article>
              <article className="ai-card">
                <span>Targeted Vulnerability</span>
                <strong>{overviewIntel.vulnerability}</strong>
              </article>
            </div>
          </section>

          <section className="ai-lower-grid">
            <article className="ai-section">
              <div className="ai-section-heading"><h2>Blue-Team Recommendations</h2></div>
              <ul className="recommendation-list">
                {overviewIntel.recommendations.map((recommendation) => (
                  <li key={recommendation}>{recommendation}</li>
                ))}
              </ul>
            </article>
            <article className="ai-section">
              <div className="ai-section-heading"><h2>System &amp; Source Info</h2></div>
              <p className="sequence-text">{overviewIntel.features.sequence?.join(' -> ') || 'No events collected yet'}</p>
              <small className="model-label">Model: {overviewIntel.model.name} v{overviewIntel.model.version}</small>
              <small className="model-label">Source: {overviewIntel.dataset?.source || 'HITL-IoT_dataset.csv'}</small>
            </article>
          </section>
        </div>
      )}
    </main>
  )
}

export default App
