# AI Intrusion-Detection Dashboard

This project provides an interactive dashboard for testing the AI intrusion-detection pipeline. It includes anomaly detection, attack-pattern analysis, and an AI-generated incident report.

## Run

```powershell
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. The root URL redirects to the dashboard.

## Available routes

- `GET /` — redirects to the dashboard
- `GET /ai-dashboard` — interactive AI dashboard
- `GET /api/simulation-presets` — available test presets
- `GET` or `POST /api/simulate-behavior` — runs the AI pipeline

Example:

```text
/api/simulate-behavior?preset=normal_surveillance
```