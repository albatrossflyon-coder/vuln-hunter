"""Wraps trivy (Aqua Security's own scanner) to catch known CVEs across every
dependency ecosystem pip-audit can't see -- Rust/Cargo, npm/yarn, Go modules,
Ruby, Java, and more. dep_scan.py already covers Python via pip-audit; this is
the same job for everything else vuln-hunter's real target repos actually use
(job-hunter's frontend, various Rust MCP tools, etc.).

Deterministic findings only, same reasoning as gitleaks.py/dep_scan.py: a
known CVE with a known fix version doesn't need an LLM to explain why it
matters, so this skips triage.py entirely and fills
explanation/exploitability/suggested_fix directly.

# ponytail: only runs the `vuln` scanner (dependency CVEs), not `secret` or
# `misconfig` -- gitleaks.py already owns secret scanning (better git-history
# coverage), and container/IaC misconfig scanning isn't a fit for vuln-hunter's
# current target repos (plain source trees, not Dockerfiles/Terraform). Add
# `--scanners misconfig` when a repo that actually needs it shows up.
"""

import json
import shutil
import sys
from pathlib import Path
from subprocess import run, TimeoutExpired
from typing import Any, Dict, List

FINDING_TYPE = "dependency_cve"

# Lockfile names trivy actually reads. Used by callers (see mcp_server.py /
# main.py's diff-scan path) to decide whether a trivy re-scan is worth it --
# same "only worth re-running when a relevant lockfile changed" logic as
# dep_scan.py's requirements.txt check, just covering more ecosystems.
TRIVY_LOCKFILE_NAMES = frozenset({
    "requirements.txt", "Cargo.lock", "package-lock.json", "yarn.lock",
    "pnpm-lock.yaml", "go.sum", "go.mod", "Pipfile.lock", "poetry.lock",
    "Gemfile.lock", "composer.lock",
})


def _trivy_executable() -> str:
    """Resolve trivy on PATH, falling back to the Go install location (trivy
    ships as a Go binary, not a pip package, so it isn't in the venv's Scripts/
    dir like semgrep/pip-audit are)."""
    found = shutil.which("trivy")
    if found:
        return found
    go_bin = Path.home() / "go" / "bin" / ("trivy.exe" if sys.platform == "win32" else "trivy")
    return str(go_bin) if go_bin.exists() else "trivy"


def run_trivy_scan(repo_path: str) -> List[Dict[str, Any]]:
    """Scan repo_path for known-CVE dependencies across every ecosystem trivy
    recognizes. Returns [] if trivy finds no supported lockfiles -- this is a
    supplementary layer like dep_scan.py, its absence should never break a scan.
    """
    cmd = [_trivy_executable(), "fs", "--scanners", "vuln", "--format", "json", "--quiet", repo_path]
    try:
        result = run(cmd, capture_output=True, text=True, timeout=180)
    except TimeoutExpired:
        raise RuntimeError("trivy scan exceeded the 180s timeout")
    except FileNotFoundError:
        # trivy not installed -- same "supplementary, don't break the scan"
        # contract as a missing requirements.txt in dep_scan.py.
        return []

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"trivy failed: {result.stderr[:2000]}")

    findings = []
    for res in payload.get("Results", []) or []:
        target = res.get("Target", "")
        for vuln in res.get("Vulnerabilities", []) or []:
            findings.append(_to_finding(vuln, target, repo_path))
    return findings


def _to_finding(vuln: Dict[str, Any], target: str, repo_path: str) -> Dict[str, Any]:
    name = vuln["PkgName"]
    version = vuln.get("InstalledVersion", "unknown")
    vuln_id = vuln["VulnerabilityID"]
    fixed = vuln.get("FixedVersion")
    # trivy's Target is relative to the scan root; resolve to an absolute path
    # matching dep_scan.py's convention so ignore_store fingerprints line up
    # the same way across scanner types.
    path = str((Path(repo_path) / target).resolve()) if not Path(target).is_absolute() else target

    fix_text = f"Upgrade to {fixed}." if fixed else "No fixed version is published yet -- track the advisory for an update."

    return {
        "rule_id": f"trivy.{vuln_id}",
        "path": path,
        "start_line": 1,
        "end_line": 1,
        "message": f"{name} {version} has a known vulnerability ({vuln_id}).",
        "severity": vuln.get("Severity", "UNKNOWN"),
        "cwe": None,
        "owasp": None,
        "snippet": f"{name} {version}",
        "matched_code": f"{name} {version}",
        "explanation": vuln.get("Description") or vuln.get("Title") or f"{name} {version} is affected by {vuln_id}.",
        "exploitability": "high" if vuln.get("Severity") in ("HIGH", "CRITICAL") else "low",
        "suggested_fix": fix_text,
        "finding_type": FINDING_TYPE,
    }
