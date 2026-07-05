"""Manual regression test: sensitive files (.env, credentials.json, keys, etc.)
must never be read or appear in any finding, even when present in the scan
target. Creates fixtures in a temp dir so nothing sensitive-looking gets
committed to the repo.
"""

import shutil
import sys
import tempfile
from pathlib import Path

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

from scanner import run_scan


def main():
    tmpdir = Path(tempfile.mkdtemp(prefix="vuln_hunter_never_read_"))
    try:
        (tmpdir / "vulnerable.py").write_text(
            'import os\ndef run(u):\n    os.system("echo " + u)\n', encoding="utf-8"
        )
        (tmpdir / ".env").write_text("ANTHROPIC_API_KEY=sk-ant-shouldneverbescanned\n", encoding="utf-8")
        (tmpdir / "credentials.json").write_text('{"key": "shouldneverberead"}', encoding="utf-8")
        (tmpdir / "id_rsa").write_text("-----BEGIN FAKE PRIVATE KEY-----\n", encoding="utf-8")

        findings = run_scan(str(tmpdir))
        touched_paths = {f["path"] for f in findings}

        assert any("vulnerable.py" in p for p in touched_paths), "Expected the real vulnerability to still be caught"
        for sensitive in (".env", "credentials.json", "id_rsa"):
            assert not any(sensitive in p for p in touched_paths), f"LEAK: {sensitive} was read/scanned!"

        print(f"PASS: {len(findings)} finding(s) on vulnerable.py, zero sensitive files touched")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
