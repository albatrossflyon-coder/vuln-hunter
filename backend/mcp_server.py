"""MCP server exposing vuln-hunter's Semgrep+Claude scanner directly to Claude Code.

Wire into Claude Code's MCP config (e.g. ~/.claude.json) with:
{
  "vuln-hunter": {
    "command": "C:\\Repos\\vuln-hunter\\backend\\venv\\Scripts\\python.exe",
    "args": ["C:\\Repos\\vuln-hunter\\backend\\mcp_server.py"]
  }
}
"""

from pathlib import Path
from typing import Any, Dict, List, Tuple

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

from mcp.server.fastmcp import FastMCP

import business_logic
import ignore_store
from scanner import get_changed_files, run_scan
from triage import triage_all

mcp = FastMCP("vuln-hunter")


def _finalize(repo_path: str, findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    raw_total = len(findings)
    kept = ignore_store.filter_ignored(repo_path, findings)
    return kept, raw_total - len(kept)


def _format_findings(findings: List[Dict[str, Any]], ignored_count: int) -> str:
    if not findings:
        suffix = f" ({ignored_count} ignored)" if ignored_count else ""
        return f"No findings.{suffix}"

    header = f"{len(findings)} finding(s)" + (f", {ignored_count} ignored" if ignored_count else "")
    lines = [header + ":\n"]
    for f in findings:
        tag = "[AI review]" if f.get("finding_type") == "ai_reasoning" else "[rule]"
        lines.append(
            f"{tag} {f['rule_id']} — {f['path']}:{f['start_line']}-{f['end_line']} "
            f"({f.get('exploitability', 'n/a')} exploitability)\n"
            f"  {f['message']}\n"
            f"  Fix: {f.get('suggested_fix') or '(none suggested)'}\n"
            f"  fingerprint: {f['fingerprint']}\n"
        )
    return "\n".join(lines)


@mcp.tool()
def scan_repo(repo_path: str) -> str:
    """Run a full security scan of a repo (Semgrep detection + Claude triage for
    explanation/exploitability/fix). Use for a first pass on a whole repo. For
    just-changed files, use scan_diff instead -- it's much faster."""
    target = Path(repo_path)
    if not target.exists():
        return f"Error: path does not exist: {repo_path}"
    findings = triage_all(run_scan(str(target)))
    kept, ignored_count = _finalize(repo_path, findings)
    return _format_findings(kept, ignored_count)


@mcp.tool()
def scan_diff(repo_path: str, base_ref: str = "HEAD", deep_review: bool = False) -> str:
    """Scan only files changed vs base_ref (default HEAD = uncommitted changes) --
    much cheaper than scan_repo for iterative work. Set deep_review=True to also
    run a second AI pass for business-logic/access-control issues (missing
    ownership checks, etc.) that rule-matching can't express -- costs one extra
    Claude call per changed file."""
    try:
        changed_files = get_changed_files(repo_path, base_ref)
    except RuntimeError as e:
        return f"Error: {e}"

    findings = triage_all(run_scan(repo_path, files=changed_files))
    if deep_review:
        findings += business_logic.review_files(changed_files)

    kept, ignored_count = _finalize(repo_path, findings)
    return _format_findings(kept, ignored_count)


@mcp.tool()
def ignore_finding(repo_path: str, fingerprint: str, rule_id: str = "", path: str = "", reason: str = "") -> str:
    """Mark a finding as safe (by its fingerprint, from a prior scan result) so it
    doesn't resurface on future scans of this repo."""
    ignore_store.add_ignore(repo_path, fingerprint, rule_id, path, reason)
    return f"Ignored {fingerprint}."


@mcp.tool()
def list_ignored(repo_path: str) -> str:
    """List findings currently marked safe/ignored for this repo."""
    ignored = ignore_store.load_ignored(repo_path)
    if not ignored:
        return "No ignored findings for this repo."
    return "\n".join(
        f"{fp}: {info['rule_id']} @ {info['path']} -- {info.get('reason') or '(no reason given)'}"
        for fp, info in ignored.items()
    )


if __name__ == "__main__":
    mcp.run()
