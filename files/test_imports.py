import sys
import traceback

print("=== Testing imports ===")

try:
    import numpy as np
    print("numpy OK:", np.__version__)
except Exception as e:
    print("numpy FAIL:", e)

try:
    import pandas as pd
    print("pandas OK:", pd.__version__)
except Exception as e:
    print("pandas FAIL:", e)

try:
    import flask
    print("flask OK:", flask.__version__)
except Exception as e:
    print("flask FAIL:", e)

try:
    from camera_sensor_ai import evaluate_behavior, SIMULATION_PRESETS
    print("camera_sensor_ai OK")
    print("  Presets found:", list(SIMULATION_PRESETS.keys()))
except Exception as e:
    print("camera_sensor_ai FAIL:")
    traceback.print_exc()

try:
    from ai_engine import analyze_events, load_csv_events
    print("ai_engine OK")
except Exception as e:
    print("ai_engine FAIL:")
    traceback.print_exc()

print("\n=== Testing dataset load ===")
import os
DATASET_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "HITL-IoT_dataset.csv")
print("Dataset path:", os.path.abspath(DATASET_FILE))
print("Exists:", os.path.exists(DATASET_FILE))

if os.path.exists(DATASET_FILE):
    try:
        from ai_engine import load_csv_events
        events, meta = load_csv_events(DATASET_FILE, limit=100)
        print("Loaded events:", len(events))
        print("Meta:", meta)
        if events:
            print("First event keys:", list(events[0].keys()))
    except Exception as e:
        print("Dataset load FAIL:")
        traceback.print_exc()
