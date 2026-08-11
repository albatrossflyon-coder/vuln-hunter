import requests

BASE_URL = "https://vuln-hunter-backend.onrender.com"


def test_telemetry_repos() -> None:
    response = requests.get(f"{BASE_URL}/telemetry/repos", timeout=60)
    assert response.status_code == 200, f"expected 200, got {response.status_code}: {response.text}"
    body = response.json()
    assert isinstance(body, list), f"expected a list, got {type(body)}: {body}"
    # get_repo_staleness() shape, from telemetry.py -- not guessed.
    for entry in body:
        assert "repo_path" in entry and "last_success_ago_sec" in entry and "last_status" in entry, (
            f"unexpected entry shape: {entry}"
        )


test_telemetry_repos()
