"""Manual regression test for the suppression/ignore mechanism:
1. Ignoring a finding removes it from subsequent scans of the same repo.
2. Un-ignoring restores it.
3. Fingerprints are stable across unrelated line-number drift (the whole
   point of content-based fingerprinting instead of line-number-based).
"""

import shutil
import sys
import tempfile
from pathlib import Path

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

import ignore_store
from scanner import run_scan

VULNERABLE_SOURCE = (
    'import os\n'
    'def run_command(user_input):\n'
    '    os.system("echo " + user_input)\n'
)

PADDING = "# unrelated comment\n" * 6


def main():
    tmpdir = Path(tempfile.mkdtemp(prefix="vuln_hunter_ignore_test_"))
    try:
        target = tmpdir / "vulnerable.py"
        target.write_text(VULNERABLE_SOURCE, encoding="utf-8")

        findings = run_scan(str(target))
        assert len(findings) == 1, f"expected 1 finding, got {len(findings)}"
        fp_before = ignore_store.fingerprint(findings[0])

        # 1. Ignore it, rescan, confirm it's gone.
        ignore_store.add_ignore(str(target), fp_before, findings[0]["rule_id"], findings[0]["path"], "test")
        remaining = ignore_store.filter_ignored(str(target), run_scan(str(target)))
        assert len(remaining) == 0, "finding should have been filtered out after ignoring"

        # 2. Un-ignore, rescan, confirm it's back.
        ignore_store.remove_ignore(str(target), fp_before)
        remaining = ignore_store.filter_ignored(str(target), run_scan(str(target)))
        assert len(remaining) == 1, "finding should be back after un-ignoring"

        # 3. Add unrelated padding lines above the vulnerability -> fingerprint must be stable.
        target.write_text(PADDING + VULNERABLE_SOURCE, encoding="utf-8")
        findings_after_drift = run_scan(str(target))
        assert len(findings_after_drift) == 1
        fp_after = ignore_store.fingerprint(findings_after_drift[0])
        assert fp_after == fp_before, (
            f"fingerprint changed after unrelated line drift: {fp_before} -> {fp_after}"
        )

        print("PASS: ignore/un-ignore lifecycle works, fingerprint stable across line drift")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
