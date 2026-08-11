import requests

BASE_URL = "https://vuln-hunter-backend.onrender.com"

# Real response shape, from telemetry.py's get_telemetry_summary() -- not guessed.
EXPECTED_KEYS = {
    "window_hours", "total_scans", "completed", "hung", "crashed",
    "success_rate", "p50_duration_sec", "p90_duration_sec", "p90_near_timeout",
    "scanner_volumes", "silent_zero_scanners", "severity_breakdown",
    "fp_rate", "stopper_bugs_count", "mcp_process_count",
}


def test_telemetry_summary() -> None:
    response = requests.get(f"{BASE_URL}/telemetry/summary", timeout=60)
    assert response.status_code == 200, f"expected 200, got {response.status_code}: {response.text}"
    body = response.json()
    missing = EXPECTED_KEYS - body.keys()
    assert not missing, f"response missing expected keys: {missing}"
    assert body["window_hours"] == 24, f"default window_hours should be 24, got {body['window_hours']}"


test_telemetry_summary()
