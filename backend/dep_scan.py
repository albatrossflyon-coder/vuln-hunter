"""Wraps pip-audit (PyPA's own dependency scanner) to catch known CVEs in
Python packages pinned in requirements.txt. Semgrep sees the code you wrote;
this sees the code you imported -- a library-level vulnerability exists even
if your own code is flawless.

Deterministic findings only, same reasoning as gitleaks.py: a known CVE with
a known fix version doesn't need an LLM to explain why it matters, so this
skips triage.py entirely and fills explanation/exploitability/suggested_fix
directly.

# ponytail: only checks requirements.txt at the repo root -- pyproject.toml
# / Pipfile / poetry.lock support would need a separate resolution path per
# format. Add when a real repo needing them shows up (job-hunter, rag-system,
# etc. all use requirements.txt today).
"""

import json
import shutil
import sys
from pathlib import Path
from subprocess import run, TimeoutExpired
from typing import Any, Dict, List

FINDING_TYPE = "dependency_cve"
REQUIREMENTS_FILENAME = "requirements.txt"


def _pip_audit_executable() -> str:
    """Resolve pip-audit next to the current interpreter (works inside a venv,
    same pattern as scanner.py's _semgrep_executable), falling back to PATH."""
    candidate = Path(sys.executable).parent / ("pip-audit.exe" if sys.platform == "win32" else "pip-audit")
    if candidate.exists():
        return str(candidate)
    return shutil.which("pip-audit") or "pip-audit"


def run_pip_audit_scan(repo_path: str) -> List[Dict[str, Any]]:
    """Scan repo_path/requirements.txt for known-CVE dependencies. Returns []
    if there's no requirements.txt -- this is a supplementary layer, not the
    primary scan, so its absence should never break a scan.
    """
    req_file = Path(repo_path) / REQUIREMENTS_FILENAME
    if not req_file.exists():
        return []

    cmd = [_pip_audit_executable(), "-r", str(req_file), "-f", "json"]
    try:
        result = run(cmd, capture_output=True, text=True, timeout=180)
    except TimeoutExpired:
        raise RuntimeError("pip-audit scan exceeded the 180s timeout")

    # pip-audit exits 1 both when vulnerabilities are found AND on a real
    # failure (e.g. an unresolvable package) -- unlike gitleaks, it has no
    # --exit-code override to force success. Disambiguate by whether stdout
    # actually parses as the expected JSON shape: a real failure produces no
    # usable JSON on stdout, only an error on stderr.
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"pip-audit failed: {result.stderr[:2000]}")

    findings = []
    for dep in payload.get("dependencies", []):
        # pip-audit genuinely emits the same advisory twice for some
        # packages (confirmed live: urllib3==1.26.4 reports PYSEC-2021-108
        # twice, once with a short description and once with the full GHSA
        # text) -- almost certainly from combining OSV + PyPI advisory
        # sources that both flag the identical ID. Dedupe per vuln id,
        # keeping whichever copy has the longer/more complete description.
        by_id: Dict[str, Dict[str, Any]] = {}
        for vuln in dep.get("vulns", []):
            existing = by_id.get(vuln["id"])
            if existing is None or len(vuln.get("description", "")) > len(existing.get("description", "")):
                by_id[vuln["id"]] = vuln
        for vuln in by_id.values():
            findings.append(_to_finding(dep, vuln, req_file))
    return findings


def _line_for_package(req_file: Path, package_name: str) -> int:
    """Best-effort line number of package_name in requirements.txt. Falls back
    to line 1 for transitive dependencies that aren't directly listed there."""
    try:
        lines = req_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return 1
    needle = package_name.lower()
    for i, line in enumerate(lines):
        stripped = line.strip().lower()
        if stripped.startswith(needle) and (
            len(stripped) == len(needle) or not stripped[len(needle)].isalnum()
        ):
            return i + 1
    return 1


def _to_finding(dep: Dict[str, Any], vuln: Dict[str, Any], req_file: Path) -> Dict[str, Any]:
    name = dep["name"]
    version = dep["version"]
    vuln_id = vuln["id"]
    fix_versions = vuln.get("fix_versions", [])
    line = _line_for_package(req_file, name)

    fix_text = (
        f"Upgrade to {' or '.join(fix_versions)}." if fix_versions
        else "No fixed version is published yet -- track the advisory for an update."
    )

    return {
        "rule_id": f"pip-audit.{vuln_id}",
        "path": str(req_file.resolve()),
        "start_line": line,
        "end_line": line,
        "message": f"{name} {version} has a known vulnerability ({vuln_id}).",
        "severity": "HIGH",
        "cwe": None,  # pip-audit's JSON doesn't include a CWE mapping
        "owasp": None,
        "snippet": f"{name}=={version}",
        "matched_code": f"{name}=={version}",
        "explanation": vuln.get("description") or f"{name} {version} is affected by {vuln_id}.",
        "exploitability": "high",
        "suggested_fix": fix_text,
        "finding_type": FINDING_TYPE,
    }
