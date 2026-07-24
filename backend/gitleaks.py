"""Wraps gitleaks to catch secrets in git *history* -- NEVER_READ_PATTERNS in
scanner.py only protects the present working tree; git remembers forever, so
a token committed once and later removed from the tree is still readable by
anyone who clones the repo until the history itself is purged.

Deterministic findings only, same reasoning as scanner.py: a hardcoded
credential doesn't need an LLM to explain why it's risky, so this skips
triage.py entirely and fills explanation/exploitability/suggested_fix
directly, same as business_logic.py does for its own findings.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List

FINDING_TYPE = "secret_leak"


def _gitleaks_executable() -> str | None:
    """Resolve the gitleaks binary on PATH. None if not installed -- callers
    should degrade gracefully (skip this layer) rather than crash the whole
    scan over an optional detector."""
    return shutil.which("gitleaks")


def run_gitleaks_scan(repo_path: str) -> List[Dict[str, Any]]:
    """Scan repo_path's git history for secrets. Returns [] if gitleaks isn't
    installed or repo_path isn't a git repo -- this is a supplementary layer
    alongside the Semgrep-based scan, not the primary one, so its absence
    should never break a scan.
    """
    exe = _gitleaks_executable()
    if exe is None:
        return []
    if not (Path(repo_path) / ".git").exists():
        return []  # not a git repo -- history scanning doesn't apply

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = tmp.name

    try:
        cmd = [
            exe, "git",
            "--report-format", "json",
            "--report-path", report_path,
            "--redact",
            # Read findings from the report file instead of the exit code --
            # gitleaks' default --exit-code=1-on-leaks would otherwise need
            # the same "is this an error or just findings" disambiguation
            # semgrep required. Forcing 0 here means non-zero really means
            # "something broke", nothing more to interpret.
            "--exit-code", "0",
            repo_path,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            raise RuntimeError("gitleaks scan exceeded the 120s timeout")
        if result.returncode != 0:
            raise RuntimeError(f"gitleaks failed: {result.stderr[:2000]}")

        report_file = Path(report_path)
        if not report_file.exists() or report_file.stat().st_size == 0:
            return []  # empty report file = no leaks found
        payload = json.loads(report_file.read_text(encoding="utf-8"))
    finally:
        Path(report_path).unlink(missing_ok=True)

    return [_to_finding(item, repo_path) for item in payload]


def _to_finding(item: Dict[str, Any], repo_path: str) -> Dict[str, Any]:
    path = str((Path(repo_path) / item["File"]).resolve())
    commit = item.get("Commit", "unknown")
    author = item.get("Author", "unknown")
    date = item.get("Date", "an unknown date")

    return {
        "rule_id": f"gitleaks.{item['RuleID']}",
        "path": path,
        "start_line": item["StartLine"],
        "end_line": item["EndLine"],
        "message": item["Description"],
        "severity": "HIGH",
        "cwe": "CWE-798",  # Use of Hard-coded Credentials
        "owasp": None,
        "snippet": item["Match"],
        "matched_code": item["Secret"],
        "explanation": (
            f"A secret matching gitleaks rule '{item['RuleID']}' was committed to git "
            f"history in commit {commit[:12]} by {author} on {date}. Removing it from "
            f"the current working tree does not remove it from git's object history -- "
            f"it stays retrievable by anyone who clones or has already cloned this repo, "
            f"until the history itself is rewritten and force-pushed."
        ),
        "exploitability": "high",
        "suggested_fix": (
            "Rotate or revoke this credential immediately if it may still be valid -- "
            "assume it's compromised. Then purge it from git history (e.g. `git filter-repo` "
            "or BFG Repo-Cleaner) and force-push, since deleting the file alone leaves it in "
            "every prior commit."
        ),
        "finding_type": FINDING_TYPE,
    }
