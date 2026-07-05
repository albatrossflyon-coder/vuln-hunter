"""Wraps semgrep as the ground-truth detection layer.

Deliberately not an LLM freeform vulnerability hunt — semgrep finds real,
rule-matched issues; the LLM layer (triage.py) only explains/prioritizes/
suggests fixes for findings that actually exist, grounded in the real code.
"""

import fnmatch
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

RULES_DIR = Path(__file__).parent / "rules"
DEFAULT_CONFIGS = [str(RULES_DIR / "custom-python-security.yml"), "p/security-audit", "p/secrets"]

# Never read the *contents* of these, regardless of .gitignore state — the whole
# point of this tool is to avoid credentials ever reaching a snippet or the LLM.
NEVER_READ_PATTERNS = [
    ".env", ".env.*", "*.pem", "*.key", "*.pfx", "*.p12",
    "id_rsa", "id_rsa.pub", "id_ed25519", "id_ed25519.pub",
    "credentials.json", "secrets.json", "secrets.yml", "secrets.yaml",
    ".npmrc", ".git-credentials", "known_hosts",
]


def _is_never_read(path: Path) -> bool:
    name = path.name
    return any(fnmatch.fnmatch(name, pattern) for pattern in NEVER_READ_PATTERNS)


def _semgrep_executable() -> str:
    """Resolve semgrep.exe next to the current interpreter (works inside a venv)."""
    candidate = Path(sys.executable).parent / ("semgrep.exe" if sys.platform == "win32" else "semgrep")
    return str(candidate) if candidate.exists() else "semgrep"


def run_scan(target_path: str, configs: List[str] | None = None) -> List[Dict[str, Any]]:
    """Run semgrep against target_path, return parsed findings with real code context.

    Sensitive files (NEVER_READ_PATTERNS) are excluded from the semgrep target
    selection itself, so their content is never read or matched in the first
    place — not just filtered out of the results afterward.
    """
    configs = configs or DEFAULT_CONFIGS
    cmd = [_semgrep_executable(), "scan"]
    for config in configs:
        cmd += ["--config", config]
    for pattern in NEVER_READ_PATTERNS:
        cmd += ["--exclude", pattern]
    cmd += [target_path, "--json", "--quiet"]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode not in (0, 1):  # semgrep exits 1 when findings exist
        raise RuntimeError(f"semgrep failed: {result.stderr[:2000]}")

    payload = json.loads(result.stdout)
    findings = []
    for item in payload.get("results", []):
        # Defense in depth: skip even if something slipped past --exclude above.
        if _is_never_read(Path(item["path"])):
            continue
        findings.append(_enrich_with_source(item))
    return findings


def _enrich_with_source(item: Dict[str, Any]) -> Dict[str, Any]:
    """Attach the real source snippet around the finding so triage is grounded in it."""
    path = Path(item["path"])
    start_line = item["start"]["line"]
    end_line = item["end"]["line"]

    snippet = ""
    if path.exists() and not _is_never_read(path):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        context_start = max(0, start_line - 4)
        context_end = min(len(lines), end_line + 3)
        snippet = "\n".join(
            f"{i + 1}: {lines[i]}" for i in range(context_start, context_end)
        )

    return {
        "rule_id": item["check_id"],
        "path": str(path),
        "start_line": start_line,
        "end_line": end_line,
        "message": item["extra"]["message"],
        "severity": item["extra"].get("severity", "UNKNOWN"),
        "cwe": _as_string(item["extra"].get("metadata", {}).get("cwe")),
        "owasp": _as_string(item["extra"].get("metadata", {}).get("owasp")),
        "snippet": snippet,
    }


def _as_string(value: Any) -> str | None:
    """Semgrep community rules return cwe/owasp as lists; custom rules return strings. Normalize."""
    if value is None:
        return None
    if isinstance(value, list):
        return "; ".join(str(v) for v in value)
    return str(value)
