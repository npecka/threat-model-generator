# falco_fetcher.py

import os
import json
import subprocess
from datetime import datetime, timedelta

FALCO_USER = os.getenv("FALCO_UI_USER", "admin")
FALCO_PASS = os.getenv("FALCO_UI_PASS", "admin")

def fetch_falco_events_from_ui(limit=500):
    """
    Fetch Falco events directly from Falco pod logs.

    The Falco UI API has issues with event retention/indexing, so we parse
    events directly from the Falco daemonset pod logs which are reliable.
    """
    try:
        print("[Falco] Fetching events from Falco pod logs (bypassing broken UI API)...")

        # Get logs from last 10 minutes to capture runtime detections
        cmd = [
            "kubectl", "logs",
            "-n", "falco",
            "-l", "app.kubernetes.io/name=falco",
            "-c", "falco",
            "--tail", str(limit * 2),  # Get more lines since not all are JSON events
            "--since", "10m"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode != 0:
            print(f"[Falco] Error fetching logs: {result.stderr}")
            return fetch_falco_events_from_ui_fallback(limit)

        # Parse JSON events from logs
        events = []
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line or not line.startswith('{'):
                continue

            try:
                event = json.loads(line)
                # Only include events with required fields
                if event.get('rule') and event.get('output'):
                    events.append(event)
            except json.JSONDecodeError:
                continue

        print(f"[Falco] Parsed {len(events)} events from pod logs")

        # Return most recent events up to limit
        events.sort(key=lambda e: e.get('time', ''), reverse=True)
        return events[:limit]

    except subprocess.TimeoutExpired:
        print("[Falco] Timeout fetching pod logs, falling back to UI API...")
        return fetch_falco_events_from_ui_fallback(limit)
    except Exception as e:
        print(f"[Falco] Error parsing pod logs: {e}")
        return fetch_falco_events_from_ui_fallback(limit)


def fetch_falco_events_from_ui_fallback(limit=500):
    """
    Fallback method using the Falco UI API.

    Note: The UI API has known issues with event retention, showing old events
    from September instead of current events. Use pod logs method instead.
    """
    try:
        import requests
        url = f"https://falco.lab.internal/api/v1/events/search?limit={limit}&sort=desc"
        resp = requests.get(url, auth=(FALCO_USER, FALCO_PASS), verify=False, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        print("Falco API returned keys:", data.keys())
        if isinstance(data, dict):
            if "events" in data:
                return data["events"]
            for key, val in data.items():
                if isinstance(val, list):
                    print(f"Using list from key: {key}")
                    return val
        elif isinstance(data, list):
            return data
        print("Unexpected format:", data)
        return []
    except Exception as e:
        print("Falco fetch error:", e)
        return []
