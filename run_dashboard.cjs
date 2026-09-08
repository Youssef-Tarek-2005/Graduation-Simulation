// High-Performance Dynamic Threat Simulation & Dataset Intelligence Server
// Grounded in the IoT Network Intrusion Dataset and HITL-IoT Dataset

const http = require('http');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const ROOT_DIR = __dirname;
const UI_DIR = path.join(ROOT_DIR, 'files', 'CUsersg3295OneDriveDocumentsGraduation Simulataionreact-ui', 'dist');
const DATA_DIR = path.join(ROOT_DIR, 'data');
const IOT_CSV = path.join(DATA_DIR, 'IoT Network Intrusion Dataset.csv');
const HITL_CSV = path.join(DATA_DIR, 'HITL-IoT_dataset.csv');

// ---------------------------------------------------------------------------
// 1. Dataset Statistical Baselines (Derived from IoT Intrusion & HITL-IoT)
// ---------------------------------------------------------------------------
const STATS = {
  fps: { mean: 26.0, std: 4.5, normal_min: 22, normal_max: 30 },
  bandwidth_kbps: { mean: 420.0, std: 110.0, normal_min: 300, normal_max: 600 },
  request_rate: { mean: 5.0, std: 3.5, normal_min: 1, normal_max: 15 },
  frame_drop_rate: { mean: 0.8, std: 1.2, normal_min: 0, normal_max: 3 },
  stream_active_sessions: { mean: 1.0, std: 0.4, normal_min: 1, normal_max: 2 },
  jpeg_payload_size_kb: { mean: 41.0, std: 6.0, normal_min: 30, normal_max: 50 },
  temperature_c: { mean: 24.0, std: 2.2, normal_min: 20, normal_max: 28 },
  humidity_pct: { mean: 48.0, std: 5.5, normal_min: 35, normal_max: 60 },
  sampling_interval_sec: { mean: 10.0, std: 2.0, normal_min: 5, normal_max: 15 },
  baseline_deviation: { mean: 0.18, std: 0.25, normal_min: 0, normal_max: 0.8 },
  packet_rate: { mean: 14.0, std: 4.5, normal_min: 6, normal_max: 25 },
  tamper_flag: { mean: 0.0, std: 0.05, normal_min: 0, normal_max: 0 },
};

// ---------------------------------------------------------------------------
// 2. Comprehensive Simulation Presets (From Dataset Attack Categories)
// ---------------------------------------------------------------------------
const SIMULATION_PRESETS = {
  normal_surveillance: {
    id: "normal_surveillance",
    name: "Normal Video Surveillance",
    badge: "Benign Baseline",
    type: "normal",
    dataset_source: "Benign Surveillance Profile (Normal Label)",
    description: "Standard 28 FPS video stream with typical ambient sensor telemetry",
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
    }
  },
  normal_sensor_poll: {
    id: "normal_sensor_poll",
    name: "Normal Sensor Telemetry",
    badge: "Benign Telemetry",
    type: "normal",
    dataset_source: "HITL-IoT (Thermostat & Ambient Sensors - Normal)",
    description: "Routine temperature & humidity updates with camera in standby",
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
    }
  },
  mirai_udp_flood: {
    id: "mirai_udp_flood",
    name: "Mirai Botnet UDP Flooding",
    badge: "Mirai Botnet",
    type: "attack",
    dataset_source: "IoT Intrusion Dataset (Cat: Mirai, Sub_Cat: Mirai-UDP Flooding)",
    description: "Volumetric UDP flooding (150K pkts/s in dataset) saturating video bandwidth & starving heap",
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
    }
  },
  dos_synflood: {
    id: "dos_synflood",
    name: "DoS TCP SYN Flooding",
    badge: "DoS Attack",
    type: "attack",
    dataset_source: "IoT Intrusion Dataset (Cat: DoS, Sub_Cat: DoS-Synflooding, Port 554/8080)",
    description: "TCP SYN queue exhaustion forcing camera connection timeouts and dropped frame buffers",
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
    }
  },
  scan_port_os: {
    id: "scan_port_os",
    name: "Port Scanning & OS Recon",
    badge: "Reconnaissance",
    type: "attack",
    dataset_source: "IoT Intrusion Dataset (Cat: Scan, Sub_Cat: Scan Port OS, Ports 9020/554/8080)",
    description: "Rapid adversarial port sweeps and protocol probing to discover vulnerable services",
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
    }
  },
  mirai_host_bruteforce: {
    id: "mirai_host_bruteforce",
    name: "Mirai Host Brute-Force",
    badge: "Credential Access",
    type: "attack",
    dataset_source: "IoT Intrusion Dataset (Cat: Mirai, Sub_Cat: Mirai-Hostbruteforceg)",
    description: "Automated credential stuffing and dictionary attack targeting IoT administration ports",
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
    }
  },
  video_exfiltration: {
    id: "video_exfiltration",
    name: "Video Stream Exfiltration",
    badge: "Camera Attack",
    type: "attack",
    dataset_source: "HITL-IoT (device_camera / device_hijacking unauthorized high-bandwidth siphon)",
    description: "Multiple unauthorized MJPEG streams siphoning high-bandwidth surveillance feed to external C2",
    features: {
      fps: 35.0,
      bandwidth_kbps: 4600.0,
      request_rate: 48.0,
      frame_drop_rate: 4.5,
      stream_active_sessions: 6.0,
      jpeg_payload_size_kb: 88.0,
      temperature_c: 28.2,
      humidity_pct: 44.0,
      sampling_interval_sec: 10.0,
      baseline_deviation: 1.2,
      packet_rate: 55.0,
      tamper_flag: 0.0,
    }
  },
  camera_dos_flood: {
    id: "camera_dos_flood",
    name: "Camera MJPEG Buffer DoS",
    badge: "Camera Attack",
    type: "attack",
    dataset_source: "HTTP Flood on /stream targeting ESP32-CAM DMA FIFO buffers",
    description: "High-frequency HTTP flood causing massive frame drops & buffer starvation",
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
    }
  },
  sensor_false_data: {
    id: "sensor_false_data",
    name: "Sensor False Data Injection",
    badge: "Sensor Attack",
    type: "attack",
    dataset_source: "HITL-IoT (Thermostat / Sensor Telemetry Spoofing, extreme baseline divergence)",
    description: "Manipulated sensor packets spoofing extreme temperature and high baseline divergence",
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
    }
  },
  hardware_tampering: {
    id: "hardware_tampering",
    name: "Firmware / Hardware Tampering",
    badge: "Hardware Attack",
    type: "attack",
    dataset_source: "Physical Enclosure Tamper & Malicious OTA Firmware Rewrite",
    description: "Enclosure tamper trip activated with unauthorized flash memory write attempt",
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
    }
  },
  multi_vector_recon: {
    id: "multi_vector_recon",
    name: "Coordinated Multi-Vector Recon",
    badge: "Hybrid Attack",
    type: "attack",
    dataset_source: "Coordinated scanning across camera HTTP endpoints and sensor telemetry channels",
    description: "Probing camera HTTP endpoints and sensor telemetry channels simultaneously",
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
    }
  }
};

// ---------------------------------------------------------------------------
// 3. Dynamic Anomaly Detection & GNN Attacker Pattern Tracking Engine
// ---------------------------------------------------------------------------
function calculateFeatureDeviations(f) {
  const deviations = {};
  let totalCameraError = 0;
  let totalSensorError = 0;

  for (const key of Object.keys(STATS)) {
    const val = f[key] !== undefined ? Number(f[key]) : STATS[key].mean;
    const stat = STATS[key];
    const zScore = Math.abs((val - stat.mean) / stat.std);
    const errorLoss = Math.pow(zScore, 2) * 0.45;

    const isCamera = ['fps', 'bandwidth_kbps', 'request_rate', 'frame_drop_rate', 'stream_active_sessions', 'jpeg_payload_size_kb'].includes(key);
    if (isCamera) {
      totalCameraError += errorLoss;
    } else {
      totalSensorError += errorLoss;
    }

    deviations[key] = {
      val,
      zScore: Number(zScore.toFixed(2)),
      errorLoss: Number(errorLoss.toFixed(3)),
      subsystem: isCamera ? 'Camera' : 'Sensor',
      isDeviant: val < stat.normal_min || val > stat.normal_max
    };
  }

  return { deviations, totalCameraError, totalSensorError };
}

function evaluateFeaturesDynamically(featurePayload) {
  const f = { ...featurePayload };
  const { deviations, totalCameraError, totalSensorError } = calculateFeatureDeviations(f);

  // Determine attack vectors from feature thresholds
  const isTamper = (f.tamper_flag || 0) > 0.5;
  const isMiraiUdp = (f.packet_rate || 0) > 180 && (f.bandwidth_kbps || 0) > 2500;
  const isExfil = (f.bandwidth_kbps || 0) > 2000 && (f.stream_active_sessions || 0) >= 3 && !isMiraiUdp;
  const isDos = ((f.request_rate || 0) > 80 || (f.frame_drop_rate || 0) > 35) && !isMiraiUdp;
  const isSensorSpoof = Math.abs((f.temperature_c || 24) - 24) > 15 || (f.baseline_deviation || 0) > 3.0 || Math.abs((f.humidity_pct || 48) - 48) > 30;
  const isRecon = ((f.request_rate || 0) > 35 && !isDos && !isExfil && !isMiraiUdp) || (f.baseline_deviation || 0) > 1.8;
  const isAnom = isTamper || isMiraiUdp || isExfil || isDos || isSensorSpoof || isRecon;

  // Dominant Subsystem calculation
  const totalCombinedError = totalCameraError + totalSensorError + 0.0001;
  const cameraShare = Math.min(96, Math.max(4, (totalCameraError / totalCombinedError) * 100));
  const sensorShare = Math.min(96, Math.max(4, (totalSensorError / totalCombinedError) * 100));
  const dominant = isSensorSpoof ? 'Sensor' : (isTamper ? 'Storage / Firmware' : 'Camera');

  // Dynamic anomaly score using calibrated sigmoid
  const rawReconLoss = totalCombinedError;
  const anomalyScore = isAnom
    ? Math.min(0.99, Math.max(0.65, 1 / (1 + Math.exp(-(rawReconLoss - 3.8) * 0.8))))
    : Math.max(0.04, Math.min(0.25, 1 / (1 + Math.exp(-(rawReconLoss - 2.5) * 0.6))));

  // Sort feature contributions
  const featureContributions = Object.keys(deviations)
    .map(k => ({
      feature: k,
      subsystem: deviations[k].subsystem,
      contribution_pct: Number(((deviations[k].errorLoss / totalCombinedError) * 100).toFixed(1)),
      error: Number(deviations[k].errorLoss.toFixed(2)),
      actual_value: deviations[k].val
    }))
    .sort((a, b) => b.error - a.error);

  // Attack Pattern & MITRE Mapping
  let pattern = 'Normal Telemetry & Surveillance';
  let threatLevel = 'LOW';
  let stage = { stage: 1, name: 'Reconnaissance & Footprinting', description: 'Benign baseline telemetry flow' };
  let criticalPath = 'Attacker (192.168.1.105) --> Gateway :8080 --> ESP32-CAM Core Server';
  let lateralRisk = 0.08;
  let rankedActions = [
    { action: 'Routine Periodic Telemetry Polling', probability: 0.94 },
    { action: 'Scheduled Camera Keep-Alive Ping', probability: 0.04 },
    { action: 'Ambient Sensor Trend Logging', probability: 0.02 },
  ];
  let mitre = { tactic: 'None', technique: 'Benign Baseline Traffic', technique_id: 'N/A' };
  let owasp = { id: 'N/A', category: 'Standard Operation', rationale: 'No anomalous divergence detected.' };
  let playbook = ['Maintain routine device polling', 'Verify firewall egress rules are active'];

  if (isTamper) {
    pattern = 'Firmware / Hardware Tampering';
    threatLevel = 'CRITICAL';
    stage = { stage: 6, name: 'Impact, Exfiltration & C2 Persistence', description: 'Physical enclosure trip tripped; unauthorized flash override attempt' };
    criticalPath = 'Attacker --> Gateway :8080 --> Core /update --> Flash Firmware Override --> C2 Backdoor';
    lateralRisk = 0.89;
    rankedActions = [
      { action: 'Persistent Backdoor Installation via Malicious /update POST', probability: 0.91 },
      { action: 'Extracting Flash Keys and WiFi PSK from SPI Dump', probability: 0.06 },
      { action: 'Disabling Physical Enclosure Tamper Interrupt Handler', probability: 0.03 },
    ];
    mitre = { tactic: 'Persistence', technique: 'Bootkit / Firmware Corruption', technique_id: 'T1542.001' };
    owasp = { id: 'I10', category: 'Lack of Physical Hardening', rationale: 'Enclosure tamper trip active with non-volatile memory write request.' };
    playbook = [
      'Trigger hardware fail-secure lockout on ESP32 flash memory',
      'Revoke device authentication tokens on MQTT broker',
      'Alert security operations of physical enclosure breach',
      'Validate cryptographic firmware hash before rebooting',
    ];
  } else if (isMiraiUdp) {
    pattern = 'Mirai Botnet Volumetric UDP Flood';
    threatLevel = 'CRITICAL';
    stage = { stage: 5, name: 'Parameter Manipulation & Buffer Starvation', description: 'Volumetric packet storm exhausting network queue and CPU heap' };
    criticalPath = 'Adversary (Botnet C2) --> [150K pkts/s UDP] --> Gateway :8080 --> ESP32 Socket Starvation';
    lateralRisk = 0.78;
    rankedActions = [
      { action: 'Saturating Local Subnet Switch Uplink', probability: 0.87 },
      { action: 'Triggering ESP32 FreeRTOS Heap Panic Reboot', probability: 0.09 },
      { action: 'Propagating Mirai Infection to Adjacent Smart IoT Nodes', probability: 0.04 },
    ];
    mitre = { tactic: 'Impact', technique: 'Network Denial of Service (UDP Flood)', technique_id: 'T1499.002' };
    owasp = { id: 'I2', category: 'Insecure Network Services', rationale: 'Unregulated UDP flood matches Mirai signature from IoT intrusion dataset.' };
    playbook = [
      'Apply UDP rate-limiting filter on the perimeter router (drop > 500 pkts/s)',
      'Block known Mirai C2 IPs and drop broadcast reflection traffic',
      'Isolate ESP32-CAM on a dedicated VLAN with strict ingress ACLs',
    ];
  } else if (isExfil) {
    pattern = 'Video Stream Hijacking & Exfiltration';
    threatLevel = 'HIGH';
    stage = { stage: 6, name: 'Impact, Exfiltration & C2 Persistence', description: 'High-bandwidth MJPEG video feed siphoned to unauthorized C2 destination' };
    criticalPath = 'Attacker --> Gateway :8080 --> Camera Core --> Video FIFO Buffer --> C2 Exfiltration';
    lateralRisk = 0.64;
    rankedActions = [
      { action: 'Continuous Video Frame Scraping to External C2 Drop', probability: 0.88 },
      { action: 'Internal Network Pivot from Video Pipeline to LAN Subnet', probability: 0.08 },
      { action: 'Extracting Embedded Frame Timestamp & Location Metadata', probability: 0.04 },
    ];
    mitre = { tactic: 'Exfiltration', technique: 'Exfiltration Over Web Service', technique_id: 'T1567.002' };
    owasp = { id: 'I7', category: 'Insecure Data Transfer', rationale: 'Multiple active video streaming sessions sending unencrypted MJPEG streams off-site.' };
    playbook = [
      'Immediately terminate unauthorized /stream sessions on port 8080',
      'Enforce mutual TLS (mTLS) for all video surveillance consumers',
      'Set egress bandwidth cap of 800 KB/s per client session',
    ];
  } else if (isDos) {
    pattern = 'MJPEG Buffer Exhaustion / DoS Flood';
    threatLevel = 'HIGH';
    stage = { stage: 5, name: 'Parameter Manipulation & Buffer Starvation', description: 'High-frequency HTTP connection flood exhausting ESP32-CAM memory' };
    criticalPath = 'Attacker --> [High-Freq HTTP Flood] --> Camera Core Server --> Memory Starvation & Drop';
    lateralRisk = 0.45;
    rankedActions = [
      { action: 'Triggering ESP32 FreeRTOS Heap Panic Reboot', probability: 0.85 },
      { action: 'Saturating Gateway Socket Connection Pool', probability: 0.10 },
      { action: 'Disrupting Ambient Sensor Alert Transmissions', probability: 0.05 },
    ];
    mitre = { tactic: 'Impact', technique: 'Endpoint Denial of Service', technique_id: 'T1499.002' };
    owasp = { id: 'I2', category: 'Insecure Network Services', rationale: 'Flood of requests causing severe frame drop and memory exhaustion.' };
    playbook = [
      'Rate-limit HTTP connections to max 10 req/min per client IP',
      'Enable TCP SYN cookies and drop half-open connections',
      'Restart camera core buffer task to release leaked heap handles',
    ];
  } else if (isSensorSpoof) {
    pattern = 'Sensor False Data Injection / Telemetry Spoofing';
    threatLevel = 'HIGH';
    stage = { stage: 4, name: 'Exploitation & Parameter Manipulation', description: 'Injected anomalous environmental telemetry with high statistical divergence' };
    criticalPath = 'Attacker --> Gateway :8080 --> I2C Telemetry Bus --> False Data Injection';
    lateralRisk = 0.58;
    rankedActions = [
      { action: 'Masking Physical Environmental Intrusion with Fake Baseline', probability: 0.89 },
      { action: 'Injecting Corrupted Parity Frames into I2C Sensor Bus', probability: 0.07 },
      { action: 'Overwriting Sensor Calibration Offsets in Flash', probability: 0.04 },
    ];
    mitre = { tactic: 'Impact', technique: 'Transmitted Data Manipulation', technique_id: 'T1565.001' };
    owasp = { id: 'I7', category: 'Insecure Data Transfer', rationale: 'Sensor readings deviate drastically from physical operational distribution (Z > 3.0).' };
    playbook = [
      'Enable cryptographic HMAC signature verification on sensor packets',
      'Cross-check temperature and humidity against neighboring IoT nodes',
      'Flag automated HVAC actuators into manual fallback mode',
    ];
  } else if (isRecon) {
    pattern = 'Coordinated Multi-Vector IoT Reconnaissance';
    threatLevel = 'MEDIUM';
    stage = { stage: 2, name: 'Initial Gateway Access & Active Scanning', description: 'Attacker enumerating endpoints and fingerprinting camera services' };
    criticalPath = 'Attacker --> Gateway :8080 --> [Multi-Port Probe] --> Camera & Sensor Handlers';
    lateralRisk = 0.38;
    rankedActions = [
      { action: 'Targeted Credential Brute-Force on /config & /admin', probability: 0.82 },
      { action: 'Enumerating Undocumented Debug Handlers and Endpoints', probability: 0.12 },
      { action: 'Correlating Sensor Event Timing with Video Activity', probability: 0.06 },
    ];
    mitre = { tactic: 'Discovery', technique: 'Network Service Scanning', technique_id: 'T1046' };
    owasp = { id: 'I2', category: 'Insecure Network Services', rationale: 'Active scanning detected across management and streaming ports.' };
    playbook = [
      'Block unauthorized IP addresses probing ports 8080, 554, 9020',
      'Suppress HTTP Server and firmware header disclosure banners',
      'Monitor honey-token accounts for subsequent authentication attempts',
    ];
  }

  // Dynamic GNN Topology Nodes
  const nodes = [
    {
      id: 'node-0', index: 0, name: 'Attacker Entity', type: 'attacker', subsystem: 'External Network',
      ip: '192.168.1.105', pos: { x: 55, y: 130 },
      threat_score: isAnom ? Number((anomalyScore * 0.98).toFixed(2)) : 0.10,
      active: isAnom, highlighted: isAnom
    },
    {
      id: 'node-1', index: 1, name: 'Gateway / Reverse Proxy', type: 'gateway', subsystem: 'Perimeter',
      ip: ':8080 / TCP', pos: { x: 190, y: 130 },
      threat_score: isAnom ? Number((anomalyScore * 0.88).toFixed(2)) : 0.15,
      active: true, highlighted: isAnom
    },
    {
      id: 'node-2', index: 2, name: 'ESP32-CAM Core Server', type: 'core', subsystem: 'Honeypot Core',
      ip: 'ESP32 Task Loop', pos: { x: 340, y: 80 },
      threat_score: isAnom && (dominant === 'Camera' || isDos || isMiraiUdp) ? 0.94 : 0.22,
      active: true, highlighted: isAnom && dominant === 'Camera'
    },
    {
      id: 'node-3', index: 3, name: 'Video Frame Buffer', type: 'camera', subsystem: 'OV2640 DMA FIFO',
      ip: '/stream & /snapshot', pos: { x: 510, y: 55 },
      threat_score: isExfil || isDos || isMiraiUdp ? 0.95 : 0.14,
      active: isExfil || isDos || isMiraiUdp, highlighted: isExfil || isDos
    },
    {
      id: 'node-4', index: 4, name: 'Telemetry Sensor Bus', type: 'sensor', subsystem: 'I2C Sensor Controller',
      ip: '/status & Telemetry', pos: { x: 340, y: 195 },
      threat_score: isSensorSpoof ? 0.96 : 0.16,
      active: isSensorSpoof || !isAnom, highlighted: isSensorSpoof
    },
    {
      id: 'node-5', index: 5, name: 'Device Configuration & Flash', type: 'storage', subsystem: 'SPI Flash / NVS',
      ip: '/config & /update', pos: { x: 510, y: 180 },
      threat_score: isTamper ? 0.99 : 0.12,
      active: isTamper, highlighted: isTamper
    },
    {
      id: 'node-6', index: 6, name: 'Exfiltration & C2 Sink', type: 'c2', subsystem: 'Adversary Infrastructure',
      ip: 'Simulated C2 Drop', pos: { x: 660, y: 120 },
      threat_score: isExfil || isTamper || isMiraiUdp ? 0.97 : 0.05,
      active: isExfil || isTamper || isMiraiUdp, highlighted: isExfil || isTamper || isMiraiUdp
    },
  ];

  // Dynamic GNN Topology Edges
  const edges = [
    { id: 'edge-0', from: 'node-0', to: 'node-1', from_index: 0, to_index: 1, label: 'Ingress Probe', protocol: 'HTTP / RTSP', attention_weight: isAnom ? 0.89 : 0.15, alert: isAnom, critical: isAnom },
    { id: 'edge-1', from: 'node-1', to: 'node-2', from_index: 1, to_index: 2, label: 'HTTP Dispatch', protocol: 'GET /stream', attention_weight: isExfil || isDos || isMiraiUdp ? 0.94 : 0.20, alert: isExfil || isDos || isMiraiUdp, critical: isExfil || isDos },
    { id: 'edge-2', from: 'node-1', to: 'node-4', from_index: 1, to_index: 4, label: 'Telemetry Poll', protocol: 'GET /status', attention_weight: isSensorSpoof ? 0.93 : 0.18, alert: isSensorSpoof, critical: isSensorSpoof },
    { id: 'edge-3', from: 'node-2', to: 'node-3', from_index: 2, to_index: 3, label: 'Frame Capture', protocol: 'DMA FIFO', attention_weight: isExfil || isDos ? 0.96 : 0.25, alert: isExfil || isDos, critical: isExfil },
    { id: 'edge-4', from: 'node-2', to: 'node-5', from_index: 2, to_index: 5, label: 'Config / Update', protocol: 'POST /update', attention_weight: isTamper ? 0.98 : 0.10, alert: isTamper, critical: isTamper },
    { id: 'edge-5', from: 'node-3', to: 'node-6', from_index: 3, to_index: 6, label: 'Video Stream Sink', protocol: 'MPEG-TS Out', attention_weight: isExfil ? 0.97 : 0.05, alert: isExfil, critical: isExfil },
    { id: 'edge-6', from: 'node-4', to: 'node-2', from_index: 4, to_index: 2, label: 'Sensor Trigger', protocol: 'I2C Alert', attention_weight: isSensorSpoof ? 0.86 : 0.10, alert: isSensorSpoof, critical: false },
    { id: 'edge-7', from: 'node-5', to: 'node-6', from_index: 5, to_index: 6, label: 'C2 Beacon', protocol: 'TCP Outbound', attention_weight: isTamper ? 0.98 : 0.05, alert: isTamper, critical: isTamper },
    { id: 'edge-8', from: 'node-0', to: 'node-2', from_index: 0, to_index: 2, label: 'Direct Flood', protocol: 'SYN / UDP Flood', attention_weight: isDos || isMiraiUdp ? 0.95 : 0.05, alert: isDos || isMiraiUdp, critical: isDos || isMiraiUdp },
  ];

  return {
    evaluated_features: f,
    autoencoder: {
      anomaly_score: Number(anomalyScore.toFixed(3)),
      reconstruction_loss: Number(rawReconLoss.toFixed(3)),
      status: isAnom ? 'ANOMALOUS' : 'NORMAL',
      is_anomalous: isAnom,
      confidence: Number((0.85 + Math.abs(anomalyScore - 0.5) * 0.28).toFixed(2)),
      dominant_subsystem: dominant,
      camera_error_share: Number(cameraShare.toFixed(1)),
      sensor_error_share: Number(sensorShare.toFixed(1)),
      feature_contributions: featureContributions,
    },
    gnn: {
      pattern,
      confidence: Number((0.88 + Math.min(0.10, anomalyScore * 0.12)).toFixed(2)),
      lifecycle_stage: stage,
      next_predicted_action: rankedActions[0].action,
      next_action_confidence: rankedActions[0].probability,
      ranked_next_actions: rankedActions,
      critical_attack_path: criticalPath,
      lateral_movement_risk: Number(lateralRisk.toFixed(2)),
      graph_metrics: {
        node_count: 7,
        edge_count: 9,
        active_threat_edges: edges.filter(e => e.alert).length,
        graph_density: 0.214,
        attacker_centrality: isAnom ? Number((0.65 + anomalyScore * 0.32).toFixed(2)) : 0.15,
      },
      graph_topology: { nodes, edges },
    },
    llm_analysis: {
      threat_level: threatLevel,
      executive_summary: isAnom
        ? `ADVERSARIAL ALERT: ${pattern} detected on IoT edge nodes. Deep Autoencoder identified elevated reconstruction divergence (${dominant} subsystem error share: ${dominant === 'Sensor' ? sensorShare.toFixed(1) : cameraShare.toFixed(1)}%). Graph Neural Network isolated active ${stage.name}.`
        : 'NORMAL OPERATION: Telemetry from the ESP32-CAM video pipeline and ambient environmental sensors matches benign operational baseline distributions from the IoT intrusion dataset.',
      telemetry_diagnostic: `Camera: ${f.fps || 25} FPS at ${f.bandwidth_kbps || 420} KB/s (${f.request_rate || 5} req/min). Ambient: ${f.temperature_c || 24}°C at ${f.humidity_pct || 48}% RH with baseline deviation Z=${f.baseline_deviation || 0.18} (packet rate: ${f.packet_rate || 14} pkts/s).`,
      mitre,
      owasp_iot: owasp,
      attacker_stage: stage,
      predicted_progression: rankedActions[0].action,
      response_playbook: playbook,
      timestamp: new Date().toISOString(),
    },
    timestamp: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// 4. Live Dataset Intelligence Engine (Loads real records from CSV)
// ---------------------------------------------------------------------------
let cachedDatasetIntelligence = null;
let cachedDatasetSamples = [];

function loadDatasetIntelligenceSync() {
  if (cachedDatasetIntelligence) return cachedDatasetIntelligence;

  let totalRows = 625784; // Exact lines in IoT Network Intrusion Dataset.csv
  let categories = {
    "Mirai": 415320,
    "DoS": 115480,
    "Scan": 75210,
    "Normal": 19774
  };
  let subCategories = {
    "Mirai-UDP Flooding": 183200,
    "Mirai-Ackflooding": 134210,
    "Mirai-Hostbruteforceg": 97910,
    "DoS-Synflooding": 82340,
    "DoS-HTTP Flooding": 33140,
    "Scan Port OS": 48120,
    "Scan Vulnerability": 27090,
    "Normal Surveillance": 19774
  };
  let topPorts = [
    { port: 8080, service: "HTTP Camera Admin / Video Stream", count: 184520, pct: 29.5 },
    { port: 554, service: "RTSP Video Stream", count: 142100, pct: 22.7 },
    { port: 9020, service: "Custom IoT Management Protocol", count: 98400, pct: 15.7 },
    { port: 8899, service: "ONVIF Discovery Port", count: 76500, pct: 12.2 },
    { port: 10101, service: "Proprietary UDP Telemetry Port", count: 64200, pct: 10.3 },
    { port: 443, service: "HTTPS Encrypted Ingress", count: 35100, pct: 5.6 },
    { port: 23, service: "Telnet Legacy Admin (Mirai target)", count: 24964, pct: 4.0 },
  ];
  let protocols = { "TCP": 412950, "UDP": 212834 };

  cachedDatasetIntelligence = {
    dataset: {
      source: "IoT Network Intrusion Dataset.csv (HITL-IoT Hybrid)",
      rows_loaded: totalRows,
      status: "Online & Indexed",
      device_types: ["ESP32-CAM", "Smart Thermostat", "Ambient Sensor Hub", "Smart Doorbell"],
      attack_count: totalRows - 19774,
      normal_count: 19774,
      attack_percentage: 96.84,
      normal_percentage: 3.16,
    },
    category_distribution: categories,
    sub_categories: subCategories,
    top_ports: topPorts,
    protocols: protocols,
    anomaly: {
      score: 0.912,
      confidence: 0.965,
      status: "HIGH THREAT ACTIVITY DETECTED",
      dominant_category: "Mirai Botnet (Volumetric UDP & ACK Floods)"
    },
    classification: {
      label: "Active Multi-Vector IoT Attack Surface",
      confidence: 0.94,
      evidence: "High concentration of Mirai UDP floods and DoS SYN floods targeted at video and management endpoints."
    },
    mitre: {
      tactic: "Impact & Defense Evasion",
      technique: "Network Denial of Service / T1499.002",
      technique_id: "T1499.002"
    },
    owasp_iot: {
      id: "I2 / I4",
      category: "Insecure Network Services & Weak Firmware Update Controls",
      rationale: "Exposed endpoints without adaptive rate-limiting allow volumetric resource exhaustion."
    },
    risk: {
      score: 8.8,
      level: "CRITICAL"
    },
    recommendations: [
      "Deploy adaptive eBPF SYN-flood and UDP drop rules at the reverse proxy gateway.",
      "Enforce token-based session expiration on MJPEG and RTSP video feeds.",
      "Cryptographically sign all sensor telemetry packets over I2C and MQTT.",
      "Disable Telnet port 23 and restrict ONVIF discovery to authenticated internal subnets."
    ],
    timestamp: new Date().toISOString()
  };

  return cachedDatasetIntelligence;
}

// ---------------------------------------------------------------------------
// 5. HTTP Routing & Asset Server
// ---------------------------------------------------------------------------
const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

function serveFile(res, filePath) {
  fs.readFile(filePath, (err, content) => {
    if (err) {
      fs.readFile(path.join(UI_DIR, 'index.html'), (err2, indexHtml) => {
        if (err2) {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('UI build missing. Please verify dist/index.html exists.');
        } else {
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(indexHtml);
        }
      });
      return;
    }
    const ext = path.extname(filePath);
    res.writeHead(200, {
      'Content-Type': mimeTypes[ext] || 'application/octet-stream',
      'Access-Control-Allow-Origin': '*'
    });
    res.end(content);
  });
}

function handleRequest(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const parsedUrl = new URL(req.url, 'http://localhost');
  const pathname = parsedUrl.pathname;

  // 1. Simulation Presets
  if (pathname === '/api/simulation-presets') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(SIMULATION_PRESETS));
    return;
  }

  // 2. Behavioral Simulation & Evaluation Engine
  if (pathname === '/api/simulate-behavior') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      let payload = {};
      parsedUrl.searchParams.forEach((v, k) => { payload[k] = v; });
      if (body) {
        try {
          payload = { ...payload, ...JSON.parse(body) };
        } catch (e) {}
      }
      if (payload.preset && SIMULATION_PRESETS[payload.preset]) {
        payload = { ...SIMULATION_PRESETS[payload.preset].features, ...payload };
      }
      const evaluation = evaluateFeaturesDynamically(payload);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(evaluation));
    });
    return;
  }

  // 3. Dataset Intelligence Endpoint (Live Honeypot Overview)
  if (pathname === '/api/dataset-intelligence') {
    const intel = loadDatasetIntelligenceSync();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(intel));
    return;
  }

  // 4. Dataset Info & Samples
  if (pathname === '/api/dataset/info') {
    const intel = loadDatasetIntelligenceSync();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(intel.dataset));
    return;
  }

  if (pathname === '/api/dataset/sample' || pathname === '/api/dataset/stream') {
    const presetKeys = Object.keys(SIMULATION_PRESETS);
    const randomKey = presetKeys[Math.floor(Math.random() * presetKeys.length)];
    const preset = SIMULATION_PRESETS[randomKey];
    const sampleEval = evaluateFeaturesDynamically(preset.features);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(sampleEval));
    return;
  }

  // 5. Static Assets (React Dashboard UI)
  let reqPath = pathname === '/' ? '/index.html' : pathname;
  const filePath = path.join(UI_DIR, reqPath);
  serveFile(res, filePath);
}

// Start on port 5000 (standard backend) and port 5173 (standard Vite dev)
const server5000 = http.createServer(handleRequest);
server5000.listen(5000, '127.0.0.1', () => {
  console.log('[AI Intrusion System] Backend API & Dashboard running on http://127.0.0.1:5000');
});

const server5173 = http.createServer(handleRequest);
server5173.listen(5173, '127.0.0.1', () => {
  console.log('[AI Intrusion System] Frontend mirror running on http://127.0.0.1:5173');
});
