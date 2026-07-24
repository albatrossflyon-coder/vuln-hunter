"""Standalone regression check for gitleaks.py. Run directly:
python test_gitleaks.py
No pytest dependency -- kept as a plain assert script, same as test_resolve_repo_dir.py.

Uses a real temp git repo with a planted fake secret so this is a live check
against the actual gitleaks binary, not a mock.
"""

import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path

from gitleaks import run_gitleaks_scan

# Generated fresh each run, never a fixed literal -- a hardcoded token-shaped
# string here would get blocked by GitHub push protection as a suspected real
# secret (this repro'd for real: the first version of this fixture reused a
# known-leaked token from another repo's history and got rejected on push).
FAKE_TOKEN = f"figd_{secrets.token_hex(20)}"

# Skip gracefully if gitleaks isn't installed -- matches run_gitleaks_scan's
# own degrade-gracefully behavior rather than failing the whole check.
if shutil.which("gitleaks") is None:
    print("test_gitleaks: SKIPPED (gitleaks not on PATH)")
    raise SystemExit(0)

with tempfile.TemporaryDirectory() as tmpdir:
    repo = Path(tmpdir)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=repo, check=True)

    secret_file = repo / "secret.py"
    secret_file.write_text(f'FIGMA_TOKEN = "{FAKE_TOKEN}"\n', encoding="utf-8")
    subprocess.run(["git", "add", "secret.py"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "test commit with fake secret"], cwd=repo, check=True)

    findings = run_gitleaks_scan(str(repo))
    assert len(findings) == 1, f"expected 1 finding, got {len(findings)}"

    f = findings[0]
    assert f["finding_type"] == "secret_leak"
    assert f["rule_id"].startswith("gitleaks.")
    assert f["path"] == str((repo / "secret.py").resolve())
    assert f["severity"] == "HIGH"
    assert f["cwe"] == "CWE-798"
    # --redact must have actually redacted -- the raw token string must never
    # appear anywhere in the finding.
    assert FAKE_TOKEN not in str(f), "raw secret leaked into the finding!"
    assert "REDACTED" in f["matched_code"]
    assert f["explanation"] and f["exploitability"] and f["suggested_fix"]

    # ignore_store fingerprinting depends on rule_id/path/matched_code being
    # present and stable -- confirm the shape is compatible without importing
    # ignore_store here (keeps this test focused on gitleaks.py itself).
    for required in ("rule_id", "path", "matched_code"):
        assert required in f

    # A plain (non-git) directory degrades gracefully instead of erroring.
    with tempfile.TemporaryDirectory() as plain_dir:
        assert run_gitleaks_scan(plain_dir) == []

print("test_gitleaks: all checks passed")
