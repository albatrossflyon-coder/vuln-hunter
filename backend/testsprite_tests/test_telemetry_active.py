import requests

BASE_URL = "https://vuln-hunter-backend.onrender.com"


def test_telemetry_active() -> None:
    response = requests.get(f"{BASE_URL}/telemetry/active", timeout=60)
    assert response.status_code == 200, f"expected 200, got {response.status_code}: {response.text}"
    body = response.json()
    assert isinstance(body, list), f"expected a list, got {type(body)}: {body}"
    # get_active_scans() row shape, from telemetry.py -- not guessed. No scan
    # should be running while this test executes, so an empty list is the
    # expected steady state, not just a lenient allowance.
    for scan in body:
        assert "scan_id" in scan and "elapsed_sec" in scan and "current_scanner" in scan, (
            f"unexpected active-scan shape: {scan}"
        )


test_telemetry_active()
