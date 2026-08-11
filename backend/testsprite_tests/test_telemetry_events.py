import requests

BASE_URL = "https://vuln-hunter-backend.onrender.com"


def test_telemetry_events() -> None:
    response = requests.get(f"{BASE_URL}/telemetry/events?limit=5", timeout=60)
    assert response.status_code == 200, f"expected 200, got {response.status_code}: {response.text}"
    body = response.json()
    assert isinstance(body, list), f"expected a list, got {type(body)}: {body}"
    assert len(body) <= 5, f"limit=5 should cap the result, got {len(body)} events"
    # get_recent_events() row shape, from telemetry.py -- not guessed.
    for event in body:
        assert "event_id" in event and "event_type" in event and "timestamp" in event, (
            f"unexpected event shape: {event}"
        )


test_telemetry_events()
