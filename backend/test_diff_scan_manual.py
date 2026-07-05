"""Manual regression test for diff-only scanning: creates a real temp git repo,
commits a clean baseline, then makes an uncommitted change introducing a real
vulnerability, and confirms the diff-scan finds only that -- not anything in
the unchanged committed files.
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

from scanner import get_changed_files, run_scan


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


def main():
    tmpdir = Path(tempfile.mkdtemp(prefix="vuln_hunter_diff_test_"))
    try:
        _git(tmpdir, "init", "-q")
        _git(tmpdir, "config", "user.email", "test@example.com")
        _git(tmpdir, "config", "user.name", "Test")

        # Committed baseline: one file with a real vulnerability, unchanged going forward.
        baseline = tmpdir / "baseline_vulnerable.py"
        baseline.write_text('import os\ndef f(u):\n    os.system("echo " + u)\n', encoding="utf-8")
        _git(tmpdir, "add", "-A")
        _git(tmpdir, "commit", "-q", "-m", "baseline")

        # Sanity: full scan should find the baseline vulnerability.
        full_scan_findings = run_scan(str(tmpdir))
        assert len(full_scan_findings) == 1, "expected the baseline vuln to be found on a full scan"

        # Diff-scan with zero changes should find nothing.
        no_changes = get_changed_files(str(tmpdir), "HEAD")
        assert no_changes == [], f"expected no changed files, got {no_changes}"
        assert run_scan(str(tmpdir), files=no_changes) == []

        # Now make an uncommitted change introducing a NEW vulnerability elsewhere.
        new_file = tmpdir / "new_change.py"
        new_file.write_text('import os\ndef g(u):\n    os.system("echo " + u)\n', encoding="utf-8")

        changed = get_changed_files(str(tmpdir), "HEAD")
        assert any("new_change.py" in c for c in changed), f"expected new_change.py in changed files, got {changed}"
        assert not any("baseline_vulnerable.py" in c for c in changed), "unchanged baseline file should not appear as changed"

        diff_findings = run_scan(str(tmpdir), files=changed)
        touched_paths = {f["path"] for f in diff_findings}
        assert any("new_change.py" in p for p in touched_paths), "diff-scan should catch the new vulnerability"
        assert not any("baseline_vulnerable.py" in p for p in touched_paths), (
            "diff-scan should NOT re-scan the unchanged committed file"
        )

        print("PASS: diff-only scan correctly scopes to changed files only, catches new vulns, skips unchanged ones")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
