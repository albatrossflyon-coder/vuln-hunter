"""Manual regression test: the scan endpoints must rate-limit per IP and per
API key.

Background (BUILDLOG Pending, "No rate limiting yet"): the password/API-key
gate only blocks callers without the key. If the key ever leaks, scan volume
-- and with it the Anthropic API + compute bill -- is completely uncapped.
This asserts the cap exists: N scans/hour (env: SCAN_RATE_LIMIT_PER_HOUR),
429 + Retry-After past it, a separate bucket per IP, and one shared bucket per
API key across IPs.

Env vars are set BEFORE importing main on purpose: main reads them per-request
via os.getenv, and this run must pin a small limit instead of the default.

Run: python test_rate_limit_manual.py  (fails before the rate limiter lands)
"""

import os
import tempfile

os.environ["SCAN_API_KEY"] = "rate-limit-test-key"
os.environ["SCAN_RATE_LIMIT_PER_HOUR"] = "3"

from unittest.mock import patch

from fastapi.testclient import TestClient

import main

LIMIT = 3
KEY = "rate-limit-test-key"


def _scan(client, repo_path, ip, key=KEY):
    headers = {"X-Forwarded-For": ip}
    if key:
        headers["X-API-Key"] = key
    with patch.object(main.all_scanners, "run_full_scan", return_value=[]):
        return client.post("/scan", json={"repo_path": repo_path}, headers=headers)


def main_test() -> None:
    repo_path = tempfile.mkdtemp(prefix="rate-limit-test-repo-")
    client = TestClient(main.app)

    # A1: an unauthenticated request is rejected before it can burn quota.
    r = _scan(client, repo_path, "198.51.100.99", key=None)
    assert r.status_code == 401, f"expected 401 with no API key, got {r.status_code}"

    # A2/A3: a fresh IP with the valid key gets the full allowance.
    for i in range(LIMIT):
        r = _scan(client, repo_path, "198.51.100.99")
        assert r.status_code == 200, (
            f"scan {i + 1}/{LIMIT} under the cap: expected 200, got "
            f"{r.status_code} {r.text}"
        )
    print(f"PASS A: the 401 above consumed no quota; first {LIMIT} scans allowed")

    # A4: the next scan from that IP is refused, with a Retry-After.
    r = _scan(client, repo_path, "198.51.100.99")
    assert r.status_code == 429, (
        f"expected 429 after {LIMIT} scans from one API key, got "
        f"{r.status_code} {r.text}"
    )
    retry_after = r.headers.get("Retry-After")
    assert retry_after is not None, "429 must carry a Retry-After header"
    assert int(retry_after) > 0, f"Retry-After must be > 0 seconds, got {retry_after!r}"
    print(f"PASS B: scan {LIMIT + 1} -> 429 with Retry-After: {retry_after}s")

    # A5: the same API key from a *different* IP is still capped -- one shared
    # per-key bucket, not a fresh allowance per IP.
    r = _scan(client, repo_path, "203.0.113.10")
    assert r.status_code == 429, (
        "same API key from a new IP must stay limited (per-API-key bucket), "
        f"got {r.status_code} {r.text}"
    )
    print("PASS C: per-API-key bucket is shared across IPs (429 from a new IP)")

    # B: without SCAN_API_KEY set (local/keyless mode) the cap is per-IP only,
    # and a different IP starts with its own bucket.
    os.environ.pop("SCAN_API_KEY")
    try:
        for i in range(LIMIT):
            r = _scan(client, repo_path, "192.0.2.55", key=None)
            assert r.status_code == 200, (
                f"keyless scan {i + 1}/{LIMIT} from a fresh IP: expected 200, "
                f"got {r.status_code} {r.text}"
            )
        r = _scan(client, repo_path, "192.0.2.55", key=None)
        assert r.status_code == 429, (
            f"expected 429 after {LIMIT} scans from one IP, got "
            f"{r.status_code} {r.text}"
        )
        print(f"PASS D: keyless mode caps per IP ({LIMIT} ok, then 429)")

        r = _scan(client, repo_path, "192.0.2.56", key=None)
        assert r.status_code == 200, (
            "a different IP must have its own bucket "
            f"(expected 200, got {r.status_code} {r.text})"
        )
        print("PASS E: a fresh IP gets its own bucket (per-IP, not global)")
    finally:
        os.environ["SCAN_API_KEY"] = KEY

    print("PASS: scan endpoints rate-limit per IP and per API key")


if __name__ == "__main__":
    main_test()
