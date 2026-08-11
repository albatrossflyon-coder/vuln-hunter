import requests

BASE_URL = "https://vuln-hunter-backend.onrender.com"


def test_health() -> None:
    # Render free tier cold-starts after ~15min idle -- generous timeout.
    response = requests.get(f"{BASE_URL}/health", timeout=60)
    assert response.status_code == 200, f"expected 200, got {response.status_code}: {response.text}"
    body = response.json()
    assert body == {"status": "ok"}, f"unexpected body: {body}"


test_health()
