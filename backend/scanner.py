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

# Vendor/build directories to skip entirely — checked against path *components*,
# not just the filename, since NEVER_READ_PATTERNS alone never matches a file
# merely because it lives inside one of these (path.name is the leaf, not the dir).
EXCLUDE_DIRS = {"node_modules", ".venv", "venv", "dist", "build", "__pycache__", ".git"}


def _is_never_read(path: Path) -> bool:
    if any(fnmatch.fnmatch(path.name, pattern) for pattern in NEVER_READ_PATTERNS):
        return True
    return any(part in EXCLUDE_DIRS for part in path.parts)


def _semgrep_executable() -> str:
    """Resolve semgrep.exe next to the current interpreter (works inside a venv)."""
    candidate = Path(sys.executable).parent / ("semgrep.exe" if sys.platform == "win32" else "semgrep")
    return str(candidate) if candidate.exists() else "semgrep"


def get_changed_files(repo_path: str, base_ref: str = "HEAD") -> List[str]:
    """Files changed vs base_ref (a branch, tag, or commit SHA), as absolute paths.

    base_ref="HEAD" diffs against the last commit (i.e. uncommitted changes).
    Use a branch name (e.g. "main") to diff a feature branch for PR-style scans.

    `git diff` alone only reports changes to already-tracked files -- brand new,
    never-`git add`ed files are invisible to it by design. Since "scan what I'm
    about to commit" is the main use case, untracked files are unioned in too.
    """
    diff_cmd = ["git", "-C", repo_path, "diff", "--name-only", "--diff-filter=ACMR", base_ref]
    diff_result = subprocess.run(diff_cmd, capture_output=True, text=True, timeout=30)
    if diff_result.returncode != 0:
        raise RuntimeError(f"git diff failed (is this a git repo? is '{base_ref}' a valid ref?): {diff_result.stderr[:500]}")

    untracked_cmd = ["git", "-C", repo_path, "ls-files", "--others", "--exclude-standard"]
    untracked_result = subprocess.run(untracked_cmd, capture_output=True, text=True, timeout=30)

    relative_paths = set(diff_result.stdout.splitlines()) | set(untracked_result.stdout.splitlines())

    # A contributor who already committed their fix (normal edit -> commit -> test
    # flow) has nothing left in `git diff HEAD` -- it only shows uncommitted work.
    # Without this, that case silently looks identical to "nothing to scan".
    if base_ref == "HEAD" and not relative_paths:
        prev_commit_cmd = ["git", "-C", repo_path, "diff", "--name-only", "--diff-filter=ACMR", "HEAD~1"]
        prev_commit_result = subprocess.run(prev_commit_cmd, capture_output=True, text=True, timeout=30)
        if prev_commit_result.returncode == 0:
            relative_paths = set(prev_commit_result.stdout.splitlines())

    root = Path(repo_path)
    changed = []
    for line in relative_paths:
        line = line.strip()
        if not line:
            continue
        full_path = root / line
        if full_path.exists():  # skip deleted files, nothing to scan
            changed.append(str(full_path))
    return changed


def run_scan(target_path: str, configs: List[str] | None = None, files: List[str] | None = None) -> List[Dict[str, Any]]:
    """Run semgrep against target_path (or, if `files` is given, only those specific
    files — used for diff-only scans), return parsed findings with real code context.

    Sensitive files (NEVER_READ_PATTERNS) are excluded from the semgrep target
    selection itself, so their content is never read or matched in the first
    place — not just filtered out of the results afterward.
    """
    if files is not None and len(files) == 0:
        return []  # diff-only scan with zero changed files -> nothing to scan, not "scan everything"

    configs = configs or DEFAULT_CONFIGS
    cmd = [_semgrep_executable(), "scan"]
    for config in configs:
        cmd += ["--config", config]
    for pattern in NEVER_READ_PATTERNS:
        cmd += ["--exclude", pattern]
    cmd += files if files is not None else [target_path]
    cmd += ["--json", "--quiet"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        raise RuntimeError("semgrep scan exceeded the 300s timeout — repo is likely too large for a single-pass scan")
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
    matched_code = ""
    if path.exists() and not _is_never_read(path):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        context_start = max(0, start_line - 4)
        context_end = min(len(lines), end_line + 3)
        snippet = "\n".join(
            f"{i + 1}: {lines[i]}" for i in range(context_start, context_end)
        )
        # Just the matched lines, no padding — used for fingerprinting so that
        # unrelated edits near (not in) the vulnerable code don't change identity.
        matched_code = "\n".join(lines[start_line - 1 : end_line])

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
        "matched_code": matched_code,
    }


def _as_string(value: Any) -> str | None:
    """Semgrep community rules return cwe/owasp as lists; custom rules return strings. Normalize."""
    if value is None:
        return None
    if isinstance(value, list):
        return "; ".join(str(v) for v in value)
    return str(value)
