"""Manual regression test for /scan/url endpoint:
Verifies that the real GitHub URL is recorded in telemetry, not the temp clone path.
"""

import os
import sys
import tempfile
from pathlib import Path

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

# Use a local temp database for testing
TEST_DB_DIR = Path(tempfile.mkdtemp(prefix="vuln_hunter_test_"))
os.environ["TELEMETRY_DB_PATH"] = str(TEST_DB_DIR / "test_telemetry.db")

import telemetry

# Re-init telemetry with test DB
telemetry.DB_PATH = Path(os.environ["TELEMETRY_DB_PATH"])
telemetry.JSONL_PATH = telemetry.DB_PATH.with_suffix(".jsonl")
telemetry.init_db()

TEST_URL = "https://github.com/octocat/Hello-World"
TEMP_PATH = "/tmp/vuln-hunter-scan-abc123"


def test_telemetry_stores_what_is_passed():
    """Test that telemetry.start_scan stores exactly what is passed as repo_path."""
    # Simulate the BUGGY behavior: passing temp path
    scan_id_buggy = telemetry.start_scan(TEMP_PATH, tool="rest:/scan/url")
    
    with telemetry._connect() as conn:
        row = conn.execute("SELECT repo_path FROM scans WHERE scan_id = ?", (scan_id_buggy,)).fetchone()
    
    stored_buggy = row["repo_path"] if row else None
    print(f"Buggy behavior - stored: {stored_buggy}")
    assert stored_buggy == TEMP_PATH, "Buggy behavior should store temp path"
    
    # Simulate the FIXED behavior: passing the real URL
    scan_id_fixed = telemetry.start_scan(TEST_URL, tool="rest:/scan/url")
    
    with telemetry._connect() as conn:
        row = conn.execute("SELECT repo_path FROM scans WHERE scan_id = ?", (scan_id_fixed,)).fetchone()
    
    stored_fixed = row["repo_path"] if row else None
    print(f"Fixed behavior - stored: {stored_fixed}")
    print(f"Expected (URL):          {TEST_URL}")
    
    # This should PASS after the fix (URL stored)
    if stored_fixed == TEST_URL:
        print("PASS: telemetry correctly stores the real GitHub URL when passed")
        return True
    else:
        print(f"FAIL: telemetry stored '{stored_fixed}' instead of URL '{TEST_URL}'")
        return False


def test_main_py_passes_correct_value():
    """Verify what main.py currently passes to telemetry.start_scan.
    
    This reads the source code to check the argument passed.
    """
    main_py_path = Path(__file__).parent / "main.py"
    content = main_py_path.read_text()
    
    # Find the scan_url function and the start_scan call
    import re
    # Look for the pattern: scan_id = telemetry.start_scan(dest, tool="rest:/scan/url")
    # or: scan_id = telemetry.start_scan(request.url.strip(), tool="rest:/scan/url")
    match = re.search(r'scan_id = telemetry\.start_scan\(([^,]+),\s*tool="rest:/scan/url"\)', content)
    
    if not match:
        print("FAIL: Could not find telemetry.start_scan call in scan_url function")
        return False
    
    arg_passed = match.group(1).strip()
    print(f"main.py passes to telemetry.start_scan: {arg_passed}")
    
    if arg_passed == "dest":
        print("FAIL: main.py passes 'dest' (temp path) - this is the BUG")
        return False
    elif arg_passed == 'request.url.strip()':
        print("PASS: main.py passes 'request.url.strip()' (the real URL) - this is the FIX")
        return True
    else:
        print(f"UNKNOWN: main.py passes '{arg_passed}'")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("Test 1: telemetry stores what is passed")
    print("=" * 60)
    test1_pass = test_telemetry_stores_what_is_passed()
    
    print()
    print("=" * 60)
    print("Test 2: main.py passes correct value to telemetry")
    print("=" * 60)
    test2_pass = test_main_py_passes_correct_value()
    
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    if test1_pass and test2_pass:
        print("ALL TESTS PASS")
        sys.exit(0)
    else:
        print("TESTS FAIL (expected before fix)")
        sys.exit(1)