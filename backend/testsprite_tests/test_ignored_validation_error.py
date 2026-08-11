import requests

BASE_URL = "https://vuln-hunter-backend.onrender.com"


def test_ignored_missing_repo_path() -> None:
    # main.py's GET /ignored declares repo_path: str with no default, so
    # FastAPI requires it as a query param -- omitting it should 422, not 200
    # or 500. No SCAN_API_KEY needed: this route has no require_scan_key dependency.
    response = requests.get(f"{BASE_URL}/ignored", timeout=60)
    assert response.status_code == 422, f"expected 422 for missing repo_path, got {response.status_code}: {response.text}"
    body = response.json()
    assert "detail" in body, f"expected a FastAPI validation error body, got: {body}"


test_ignored_missing_repo_path()
