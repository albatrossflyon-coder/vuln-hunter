#!/usr/bin/env python3
"""Manual test for vulnometry import integration.

This test verifies that vulnometry can process SARIF output from vuln-hunter scans.
It expects the scan to include CVE findings (from trivy/pip-audit) for vulnometry
to produce meaningful business-priority scores.

Run: python test_vulnometry_manual.py
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def run_semgrep_sarif(repo_path: str, output_path: str) -> bool:
    """Run semgrep with local rules and output SARIF."""
    # Use venv's semgrep directly
    venv_semgrep = Path(sys.executable).parent / "semgrep"
    cmd = [
        str(venv_semgrep), "scan",
        "--config", "backend/rules/custom-python-security.yml",
        "--sarif", "--output", output_path,
        repo_path
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    return result.returncode in (0, 1)  # 0 = no findings, 1 = findings found


def run_vulnometry_import(sarif_path: str) -> tuple[bool, str]:
    """Run vulnometry import on SARIF file. Returns (success, output)."""
    # vulnometry is installed as a script, not a module
    cmd = ["vulnometry", "import", sarif_path]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return result.returncode == 0, result.stdout + result.stderr


def test_vulnometry_with_cve_sarif():
    """Test that vulnometry works with SARIF containing CVE IDs."""
    # Create a minimal SARIF with CVE findings (simulating trivy output)
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "trivy", "version": "0.75.0"}},
            "results": [{
                "ruleId": "trivy.CVE-2021-44228",
                "level": "error",
                "message": {"text": "log4j-core 2.14.1 has a known vulnerability (CVE-2021-44228)."},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "package-lock.json"},
                        "region": {"startLine": 1, "endLine": 1}
                    }
                }]
            }]
        }],
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
        json.dump(sarif, f)
        sarif_path = f.name
    
    try:
        success, output = run_vulnometry_import(sarif_path)
        print(f"vulnometry import with CVE SARIF: {'PASS' if success else 'FAIL'}")
        print(f"Output: {output[:500]}")
        return success
    finally:
        Path(sarif_path).unlink(missing_ok=True)


def test_vulnometry_with_semgrep_only_sarif():
    """Test vulnometry with semgrep-only SARIF (no CVEs). This demonstrates the gap."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
        # This simulates what semgrep produces - CWE/OWASP but no CVEs
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Semgrep OSS", "version": "1.180.0"}},
                "results": [{
                    "ruleId": "backend.rules.sql-injection-string-concat",
                    "level": "error",
                    "message": {"text": "SQL query built via string concatenation..."},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "test.py"},
                            "region": {"startLine": 10, "endLine": 11}
                        }
                    }]
                }]
            }],
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
        }
        json.dump(sarif, f)
        sarif_path = f.name
    
    try:
        success, output = run_vulnometry_import(sarif_path)
        # vulnometry returns exit code 0 but with "No CVE identifiers found" message
        has_cve_msg = "No CVE identifiers found" in output
        print(f"vulnometry import with semgrep-only SARIF: {'PASS (no CVEs found)' if has_cve_msg else 'UNEXPECTED'}")
        print(f"Output: {output[:500]}")
        # This is expected behavior - vulnometry works but finds no CVEs to score
        return has_cve_msg
    finally:
        Path(sarif_path).unlink(missing_ok=True)


def test_full_scan_pipeline():
    """Test the full vuln-hunter scan pipeline producing SARIF for vulnometry."""
    # This would run the actual scan but requires trivy to be installed
    # For now, we just verify the SARIF generation works
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
        sarif_path = f.name
    
    try:
        # Use local rules only to avoid network dependency
        success = run_semgrep_sarif(".", sarif_path)
        if not success:
            print("semgrep SARIF generation: FAIL")
            return False
        
        # Check SARIF has expected structure
        with open(sarif_path) as f:
            sarif = json.load(f)
        
        has_results = len(sarif.get("runs", [{}])[0].get("results", [])) > 0
        print(f"semgrep SARIF generation: {'PASS' if has_results else 'FAIL (no findings)'}")
        print(f"  Findings: {len(sarif.get('runs', [{}])[0].get('results', []))}")
        
        # Try vulnometry import
        vuln_success, vuln_output = run_vulnometry_import(sarif_path)
        has_cve_msg = "No CVE identifiers found" in vuln_output
        print(f"vulnometry import on semgrep SARIF: {'No CVEs (expected)' if has_cve_msg else 'Has CVEs'}")
        
        return has_results
    finally:
        Path(sarif_path).unlink(missing_ok=True)


if __name__ == "__main__":
    print("=" * 60)
    print("Testing vulnometry import integration")
    print("=" * 60)
    
    print("\n1. Testing vulnometry with CVE-containing SARIF (simulated trivy)...")
    test1 = test_vulnometry_with_cve_sarif()
    
    print("\n2. Testing vulnometry with semgrep-only SARIF (no CVEs)...")
    test2 = test_vulnometry_with_semgrep_only_sarif()
    
    print("\n3. Testing full scan pipeline (semgrep local rules)...")
    test3 = test_full_scan_pipeline()
    
    print("\n" + "=" * 60)
    print("Summary:")
    print(f"  CVE SARIF test: {'PASS' if test1 else 'FAIL'}")
    print(f"  Semgrep-only SARIF test: {'PASS (expected no CVEs)' if test2 else 'FAIL'}")
    print(f"  Full pipeline test: {'PASS' if test3 else 'FAIL'}")
    print("=" * 60)
    
    # Overall: vulnometry works, but needs CVE-producing scanners (trivy)
    if test1 and test2 and test3:
        print("RESULT: vulnometry integration WORKS - needs trivy for CVEs")
        sys.exit(0)
    else:
        print("RESULT: Issues detected")
        sys.exit(1)