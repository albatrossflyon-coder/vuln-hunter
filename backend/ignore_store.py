"""Persistent per-repo suppression list, so a finding marked "safe, don't flag
again" doesn't resurface on every re-scan. Stored as a small JSON file at the
root of the scanned target, analogous to a lockfile — not a database, since
this needs zero setup and travels with the repo if committed.

Fingerprint is content-based (rule + path + normalized matched code), not
line-number-based, so it survives unrelated edits shifting line numbers.
"""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

IGNORE_FILENAME = ".vulnhunter-ignore.json"


def fingerprint(finding: Dict[str, Any]) -> str:
    """Identity based on the exact matched vulnerable code only — not the
    padded display snippet — so edits *near* (not in) the finding don't
    change its identity. Falls back to `snippet` for older callers/tests
    that don't have `matched_code`."""
    code = finding.get("matched_code") or finding.get("snippet", "")
    basis = f"{finding['rule_id']}|{finding['path']}|{_normalize(code)}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _normalize(code: str) -> str:
    """Strip 'N: ' line-number prefixes (if present) and surrounding whitespace
    per line, so cosmetic reformatting doesn't change the fingerprint."""
    lines = []
    for line in code.splitlines():
        _, sep, content = line.partition(": ")
        lines.append((content if sep else line).strip())
    return "\n".join(lines)


def _store_path(repo_path: str) -> Path:
    p = Path(repo_path)
    root = p if p.is_dir() else p.parent
    return root / IGNORE_FILENAME


def load_ignored(repo_path: str) -> Dict[str, Dict[str, Any]]:
    store = _store_path(repo_path)
    if not store.exists():
        return {}
    try:
        return json.loads(store.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def add_ignore(repo_path: str, fingerprint_id: str, rule_id: str = "", path: str = "", reason: str = "") -> str:
    ignored = load_ignored(repo_path)
    ignored[fingerprint_id] = {"rule_id": rule_id, "path": path, "reason": reason}
    _store_path(repo_path).write_text(json.dumps(ignored, indent=2), encoding="utf-8")
    return fingerprint_id


def remove_ignore(repo_path: str, fingerprint_id: str) -> bool:
    ignored = load_ignored(repo_path)
    if fingerprint_id not in ignored:
        return False
    del ignored[fingerprint_id]
    _store_path(repo_path).write_text(json.dumps(ignored, indent=2), encoding="utf-8")
    return True


def filter_ignored(repo_path: str, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach a stable `fingerprint` to every finding, and drop the ones already ignored."""
    ignored = load_ignored(repo_path)
    kept = []
    for f in findings:
        fp = fingerprint(f)
        f["fingerprint"] = fp
        if fp not in ignored:
            kept.append(f)
    return kept
