"""Standalone regression check for dep_scan.py. Run directly:
python test_dep_scan.py
No pytest dependency -- same pattern as test_gitleaks.py / test_resolve_repo_dir.py.

Uses a real known-CVE package pinned to a vulnerable version, so this is a
live check against the actual pip-audit binary and the real OSV/PyPI
advisory data, not a mock.
"""

import tempfile
from pathlib import Path

from dep_scan import run_pip_audit_scan

with tempfile.TemporaryDirectory() as tmpdir:
    repo = Path(tmpdir)

    # urllib3 1.26.4 has several well-documented, long-since-patched CVEs
    # (e.g. PYSEC-2021-108) -- stable, real, unambiguous test fixture.
    (repo / "requirements.txt").write_text("urllib3==1.26.4\n", encoding="utf-8")

    findings = run_pip_audit_scan(str(repo))
    assert len(findings) > 0, "expected at least one known CVE for urllib3==1.26.4"

    # pip-audit genuinely emits the same advisory twice for some packages
    # (confirmed live against this exact fixture: PYSEC-2021-108 showed up
    # twice, once with a short description and once with the full GHSA
    # text) -- dep_scan.py must dedupe per vuln id.
    rule_ids = [f["rule_id"] for f in findings]
    assert len(rule_ids) == len(set(rule_ids)), f"duplicate findings: {rule_ids}"

    f = findings[0]
    assert f["finding_type"] == "dependency_cve"
    assert f["rule_id"].startswith("pip-audit.")
    assert f["path"] == str((repo / "requirements.txt").resolve())
    assert f["snippet"] == "urllib3==1.26.4"
    assert f["start_line"] == 1  # only line in the file
    assert f["explanation"] and f["exploitability"] and f["suggested_fix"]

    # A clean, fully up-to-date-shaped requirements.txt with no matching
    # package still returns [] gracefully (no requirements.txt = no crash).
    with tempfile.TemporaryDirectory() as empty_dir:
        assert run_pip_audit_scan(empty_dir) == []

print(f"test_dep_scan: all checks passed ({len(findings)} findings for urllib3==1.26.4)")
