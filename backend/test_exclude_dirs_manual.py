"""Manual regression test: EXCLUDE_DIRS (node_modules, .venv, etc.) must be passed
to semgrep itself, not just used to filter results after the fact -- the earlier
bug let semgrep fully crawl these directories on every scan, the real cause of a
"near-zero CPU, no progress" hang on repos with large vendor/generated dirs.
"""

import shutil
import sys
import tempfile
from pathlib import Path

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

from scanner import run_scan


def main():
    tmpdir = Path(tempfile.mkdtemp(prefix="vuln_hunter_exclude_test_"))
    try:
        vulnerable_code = 'import subprocess\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n'
        (tmpdir / "app.py").write_text(vulnerable_code, encoding="utf-8")

        vendor_dir = tmpdir / "node_modules" / "vendor"
        vendor_dir.mkdir(parents=True)
        (vendor_dir / "app.py").write_text(vulnerable_code, encoding="utf-8")

        findings = run_scan(str(tmpdir))
        paths = [f["path"] for f in findings]

        assert any("node_modules" not in p for p in paths), "expected the real app.py finding to survive"
        assert not any("node_modules" in p for p in paths), (
            f"node_modules copy should never be scanned, but semgrep found: {paths}"
        )
        print("PASS: node_modules genuinely excluded from the semgrep scan itself, not just post-filtered")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
