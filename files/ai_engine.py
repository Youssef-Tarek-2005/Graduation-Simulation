"""Dataset-ready baseline intelligence for ESP32-CAM interaction events.

This module deliberately uses an explainable baseline until a labeled dataset is
available. A trained LSTM/VAE/GNN implementation can replace the scoring methods
without changing the event contract or API response shape.
"""

from __future__ import annotations

import csv
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


EVENT_SCHEMA = {
    "timestamp": "ISO-8601 timestamp",
    "device_id": "string",
    "device_type": "string",
    "src_ip": "string",
    "method": "HTTP method",
    "path": "request path",
    "event_type": "normalized event name",
    "outcome": "success|fail|info|unauthorized|suspicious",
    "authenticated": "boolean",
    "extra": "object",
}


def _clamp(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    return round(max(minimum, min(maximum, value)), 3)


def _number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _column(row: dict[str, Any], *names: str) -> Any:
    normalized = {str(key).strip().lower().replace(" ", "_"): value for key, value in row.items()}
    for name in names:
        if name in normalized and normalized[name] not in (None, ""):
            return normalized[name]
    return None


def load_csv_events(dataset_path: str | Path, limit: int = 5000) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Adapt common network-flow CSV schemas to the internal event contract."""
    path = Path(dataset_path)
    if not path.exists():
        return [], {"source": str(path), "available": False, "rows_loaded": 0}

    events = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as dataset_file:
        reader = csv.DictReader(dataset_file)
        columns = reader.fieldnames or []
        for row in reader:
            label = str(_column(row, "label", "class", "category", "attack", "attack_type") or "unknown")
            label_lower = label.lower()
            normal = label_lower in {"normal", "benign", "legitimate", "0", "false"}
            event_type = str(_column(row, "event_type", "activity", "category", "attack_type") or label)
            path_value = str(_column(row, "path", "uri", "url", "service", "protocol") or "dataset-record")
            source_ip = str(_column(row, "src_ip", "source_ip", "src", "ip") or "dataset-source")
            events.append({
                "timestamp": _column(row, "timestamp", "time", "date") or "",
                "device_id": "HITL-IoT",
                "device_type": "IoT",
                "src_ip": source_ip,
                "method": str(_column(row, "method", "http_method") or "DATASET"),
                "path": path_value,
                "event_type": event_type,
                "outcome": "info" if normal else "suspicious",
                "authenticated": False,
                "extra": {"dataset_label": label, "raw": row},
            })
            if len(events) >= limit:
                break

    return events, {
        "source": str(path),
        "available": True,
        "rows_loaded": len(events),
        "columns": columns,
        "limit": limit,
    }


def extract_features(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Convert raw JSONL events into stable numeric and categorical features."""
    event_types = Counter(event.get("event_type", "unknown") for event in events)
    outcomes = Counter(event.get("outcome", "info") for event in events)
    paths = Counter(event.get("path", "unknown") for event in events)
    source_ips = {event.get("src_ip") for event in events if event.get("src_ip")}
    failed_logins = event_types.get("login_attempt", 0) and sum(
        1 for event in events
        if event.get("event_type") == "login_attempt" and event.get("outcome") == "fail"
    ) or 0
    request_rates = [
        _number(event.get("extra", {}).get("requests_last_60s"))
        for event in events
        if isinstance(event.get("extra"), dict)
    ]

    return {
        "event_count": len(events),
        "unique_source_ips": len(source_ips),
        "unique_paths": len(paths),
        "event_types": dict(event_types),
        "outcomes": dict(outcomes),
        "failed_login_count": failed_logins,
        "suspicious_event_count": outcomes.get("suspicious", 0) + outcomes.get("scan_suspect", 0),
        "max_requests_last_60s": max(request_rates, default=0),
        "sequence": [event.get("event_type", "unknown") for event in events[-12:]],
    }


def _classify(features: dict[str, Any]) -> tuple[str, float, str]:
    event_types = features["event_types"]
    outcomes = features["outcomes"]
    failed_logins = features["failed_login_count"]
    max_rate = features["max_requests_last_60s"]

    if failed_logins >= 3:
        return "Brute Force", _clamp(0.72 + failed_logins / 50), "Repeated failed authentication attempts"
    if event_types.get("probe_unknown_path", 0) >= 2:
        return "Scanning", _clamp(0.7 + event_types["probe_unknown_path"] / 30), "Multiple unknown paths were requested"
    if max_rate >= 20 or event_types.get("stream_access", 0) >= 20:
        return "DoS", _clamp(0.68 + max_rate / 100), "Abnormally high request frequency"
    if event_types.get("firmware_update_attempt", 0) or outcomes.get("suspicious", 0):
        return "Exploitation", 0.86, "Suspicious firmware or configuration action"
    if event_types.get("status_check", 0) or event_types.get("dashboard_access", 0):
        return "Recon", 0.58, "Device metadata or service information was queried"
    return "Normal Activity", 0.82, "Observed behavior matches ordinary camera use"


def _mitre_mapping(attack_class: str) -> dict[str, str]:
    mappings = {
        "Brute Force": {"tactic": "Credential Access", "technique": "Brute Force: Password Guessing", "technique_id": "T1110"},
        "Scanning": {"tactic": "Discovery", "technique": "Network Service Scanning", "technique_id": "T1046"},
        "DoS": {"tactic": "Impact", "technique": "Endpoint Denial of Service", "technique_id": "T1499"},
        "Exploitation": {"tactic": "Initial Access", "technique": "Exploit Public-Facing Application", "technique_id": "T1190"},
        "Recon": {"tactic": "Discovery", "technique": "System Information Discovery", "technique_id": "T1082"},
        "Normal Activity": {"tactic": "None", "technique": "No malicious technique detected", "technique_id": "N/A"},
    }
    return mappings.get(attack_class, mappings["Recon"])


def _owasp_iot_mapping(attack_class: str) -> dict[str, str]:
    mappings = {
        "Brute Force": {
            "id": "I1",
            "category": "Weak, Guessable, or Hardcoded Passwords",
            "rationale": "Authentication attempts target the device login surface.",
        },
        "Scanning": {
            "id": "I2",
            "category": "Insecure Network Services",
            "rationale": "The device exposes network services that are being enumerated.",
        },
        "DoS": {
            "id": "I2",
            "category": "Insecure Network Services",
            "rationale": "The network-facing service is receiving abnormal request volume.",
        },
        "Exploitation": {
            "id": "I4",
            "category": "Lack of Secure Update Mechanism",
            "rationale": "Firmware or configuration surfaces are being targeted.",
        },
        "Recon": {
            "id": "I8",
            "category": "Lack of Device Management",
            "rationale": "Device metadata and management surfaces are being inspected.",
        },
        "Normal Activity": {
            "id": "N/A",
            "category": "No OWASP IoT risk mapped",
            "rationale": "No suspicious behavior is currently classified.",
        },
    }
    return mappings.get(attack_class, mappings["Recon"])


def _next_action(sequence: list[str], attack_class: str) -> str:
    if attack_class == "Scanning" or "status_check" in sequence:
        return "Authentication exploitation"
    if attack_class == "Brute Force":
        return "Account lockout or credential reuse attempt"
    if attack_class == "Recon":
        return "Service enumeration"
    if attack_class == "DoS":
        return "Continued request flooding"
    if attack_class == "Exploitation":
        return "Configuration or firmware tampering"
    return "Normal camera interaction"


def analyze_events(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Return the dashboard contract for raw event dictionaries."""
    normalized_events = [event for event in events if isinstance(event, dict)]
    features = extract_features(normalized_events)
    attack_class, class_confidence, evidence = _classify(features)
    anomaly_components = {
        "failed_authentication": _clamp(features["failed_login_count"] / 5),
        "request_burst": _clamp(features["max_requests_last_60s"] / 50),
        "unknown_paths": _clamp(features["event_types"].get("probe_unknown_path", 0) / 5),
        "suspicious_actions": _clamp(features["suspicious_event_count"] / 3),
    }
    anomaly_score = _clamp(sum(anomaly_components.values()) / len(anomaly_components))
    malicious = attack_class != "Normal Activity" and anomaly_score >= 0.35
    risk_score = _clamp(anomaly_score * 0.55 + class_confidence * 0.3 + (0.15 if malicious else 0.0))
    mitre = _mitre_mapping(attack_class)
    owasp_iot = _owasp_iot_mapping(attack_class)

    if attack_class == "Normal Activity":
        vulnerability = "No targeted weakness identified"
        recommendations = ["Continue normal monitoring", "Keep camera firmware and credentials current"]
    elif attack_class == "Brute Force":
        vulnerability = "Authentication weakness or exposed login service"
        recommendations = ["Rate-limit login attempts", "Use strong unique credentials", "Restrict camera access to trusted networks"]
    elif attack_class == "Scanning":
        vulnerability = "Exposed HTTP service or unnecessary endpoints"
        recommendations = ["Restrict exposed camera service", "Review reachable endpoints", "Monitor related IoT devices"]
    elif attack_class == "DoS":
        vulnerability = "Resource-constrained HTTP or stream service"
        recommendations = ["Apply request throttling", "Limit concurrent streams", "Block or limit the suspicious source"]
    else:
        vulnerability = "Exposed configuration or firmware update surface"
        recommendations = ["Restrict configuration access", "Require signed firmware updates", "Review authentication configuration"]

    return {
        "model": {"name": "Explainable baseline", "version": "0.1", "ready_for_training": True},
        "anomaly": {
            "score": anomaly_score,
            "confidence": _clamp(0.55 + abs(anomaly_score - 0.5) * 0.8),
            "status": "MALICIOUS" if malicious else "NORMAL",
            "components": anomaly_components,
        },
        "classification": {"label": attack_class, "confidence": class_confidence, "evidence": evidence},
        "prediction": {"next_likely_action": _next_action(features["sequence"], attack_class), "confidence": class_confidence},
        "mitre": mitre,
        "owasp_iot": owasp_iot,
        "vulnerability": vulnerability,
        "risk": {"score": risk_score, "level": "HIGH" if risk_score >= 0.7 else "MEDIUM" if risk_score >= 0.4 else "LOW"},
        "recommendations": recommendations,
        "features": features,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
