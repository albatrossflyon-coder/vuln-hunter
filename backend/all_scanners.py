"""Single source of truth for 'which scanners does vuln-hunter run.'

Both main.py (REST API) and mcp_server.py (Claude Code's MCP tools) call the
two functions here instead of each independently listing out scanner calls.

This exists because gitleaks and pip-audit were added to main.py on
2026-07-24 -- one day after mcp_server.py was first created -- and never
mirrored into it. Two files each holding their own scanner list drifted
apart with nothing forcing them back in sync, so every scan_repo/scan_diff
call through Claude Code silently skipped secret-scanning and dependency-CVE
checks that the REST API already had. A new scanner (trivy, or whatever's
next) now only ever needs adding here, once -- both callers automatically
pick it up.
"""

from pathlib import Path
from typing import Any, Dict, List

import business_logic
from dep_scan import run_pip_audit_scan
from gitleaks import run_gitleaks_scan
from scanner import run_scan
from trivy_scan import TRIVY_LOCKFILE_NAMES, run_trivy_scan
from triage import triage_all


FULL_SCAN_SCANNERS = ["semgrep", "gitleaks", "pip-audit", "trivy"]


def diff_scanners_invoked(changed_files: List[str]) -> List[str]:
    """Which scanners run_diff_scan will actually invoke for this changed_files
    set -- semgrep always, pip-audit/trivy conditionally, gitleaks never (see
    run_diff_scan's docstring). Exposed separately so telemetry instrumentation
    doesn't have to duplicate this condition."""
    changed_names = {Path(f).name for f in changed_files}
    scanners = ["semgrep"]
    if "requirements.txt" in changed_names:
        scanners.append("pip-audit")
    if changed_names & TRIVY_LOCKFILE_NAMES:
        scanners.append("trivy")
    return scanners


def run_full_scan(repo_path: str) -> List[Dict[str, Any]]:
    """Everything, for a first pass on a whole repo: semgrep+Claude-triage
    (rule_confirmed/ai_reasoning) plus the deterministic scanners (gitleaks
    secrets, pip-audit + trivy dependency CVEs) that skip triage entirely."""
    findings = triage_all(run_scan(repo_path))
    findings += run_gitleaks_scan(repo_path)
    findings += run_pip_audit_scan(repo_path)
    findings += run_trivy_scan(repo_path)
    return findings


def run_diff_scan(repo_path: str, changed_files: List[str], deep_review: bool = False) -> List[Dict[str, Any]]:
    """Just-changed-files scan. Takes an already-resolved changed_files list
    rather than (repo_path, base_ref) -- each caller resolves that itself via
    scanner.get_changed_files() first, since main.py and mcp_server.py want
    different things to happen on a bad ref (HTTP 400 vs. an early-return
    string, before mcp_server.py's stall-watchdog even starts). That's a
    caller-specific concern, not part of "which scanners run."

    Deliberately does NOT run gitleaks: a whole-git-history secret scan
    doesn't map onto "just this diff" (an old secret from 5 commits back has
    nothing to do with what changed here) -- see gitleaks.py. The dependency
    CVE scanners (pip-audit, trivy) DO run, but only when a lockfile they
    actually read is among the changed files -- no point re-checking CVEs for
    packages that didn't change.
    """
    findings = triage_all(run_scan(repo_path, files=changed_files))
    if deep_review:
        findings += business_logic.review_files(changed_files)

    invoked = diff_scanners_invoked(changed_files)
    if "pip-audit" in invoked:
        findings += run_pip_audit_scan(repo_path)
    if "trivy" in invoked:
        findings += run_trivy_scan(repo_path)

    return findings
