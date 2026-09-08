"""AI-powered intrusion-detection dashboard — Flask API + React frontends.

/             -> rich React UI (react-ui build)
/ai-dashboard -> live dataset React dashboard (frontend build)
"""

from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

import ai_engine
import dataset_ai
from camera_sensor_ai import evaluate_behavior, SIMULATION_PRESETS

ROOT = Path(__file__).resolve().parents[1]
RAW_CSV = ROOT / "data" / "IoT Network Intrusion Dataset.csv"

app = Flask(__name__)

UI_RICH = Path(__file__).resolve().parent / "CUsersg3295OneDriveDocumentsGraduation Simulataionreact-ui" / "dist"
UI_LIVE = Path(__file__).resolve().parent / "frontend" / "dist"

_events_cache = None


def _dataset_events():
    global _events_cache
    if _events_cache is None:
        events, meta = ai_engine.load_csv_events(RAW_CSV, limit=5000)
        _events_cache = (events, meta)
    return _events_cache


def _serve_ui(folder: Path):
    if (folder / "index.html").exists():
        return send_from_directory(folder, "index.html")
    return "<h1>UI build missing</h1><p>Run: npm install &amp;&amp; npm run build</p>", 503


@app.route("/")
def index():
    return _serve_ui(UI_RICH)


@app.route("/ai-dashboard")
def ai_dashboard():
    return _serve_ui(UI_LIVE)


@app.route("/api/simulation-presets", methods=["GET"])
def get_simulation_presets():
    return jsonify(SIMULATION_PRESETS)


@app.route("/api/simulate-behavior", methods=["GET", "POST", "OPTIONS"])
def simulate_behavior_endpoint():
    if request.method == "OPTIONS":
        return "", 204
    payload = request.get_json(silent=True) or {} if request.method == "POST" else request.args.to_dict()
    return jsonify(evaluate_behavior(payload))


@app.route("/api/dataset/info", methods=["GET"])
def get_dataset_info():
    return jsonify(dataset_ai.dataset_info())


@app.route("/api/dataset/sample", methods=["GET"])
def get_dataset_sample():
    import random

    index = request.args.get("index")
    return jsonify(dataset_ai.predict_index(int(index) if index is not None else random.randrange(5000)))


@app.route("/api/dataset/stream", methods=["GET"])
def get_dataset_stream():
    import random

    count = min(max(int(request.args.get("count", 6)), 1), 25)
    return jsonify([dataset_ai.predict_index(random.randrange(5000)) for _ in range(count)])


@app.route("/api/dataset/history", methods=["GET"])
def get_dataset_history():
    return jsonify(dataset_ai.history(int(request.args.get("count", 60))))


@app.route("/api/dataset-intelligence", methods=["GET"])
def get_dataset_intelligence():
    events, meta = _dataset_events()
    report = ai_engine.analyze_events(events)
    report["dataset"] = {"rows_loaded": meta.get("rows_loaded", 0), "source": meta.get("source", "IoT Network Intrusion Dataset.csv")}
    return jsonify(report)


if __name__ == "__main__":
    print("AI dashboard starting on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
