"""MCP server exposing vuln-hunter's Semgrep+Claude scanner directly to Claude Code.

Wire into Claude Code's MCP config (e.g. ~/.claude.json) with:
{
  "vuln-hunter": {
    "command": "C:\\Repos\\vuln-hunter\\backend\\venv\\Scripts\\python.exe",
    "args": ["C:\\Repos\\vuln-hunter\\backend\\mcp_server.py"]
  }
}
"""

import contextlib
import faulthandler
import functools
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import anyio
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

from mcp.server.fastmcp import Context, FastMCP

import all_scanners
import ignore_store
import telemetry
from scanner import get_changed_files

mcp = FastMCP("vuln-hunter")


@contextlib.contextmanager
def _stall_watchdog(seconds: int = 90):
    """Dumps every thread's real Python stack to stderr if a scan is still
    running past `seconds`, repeating -- scoped to just the scan call (not
    left running server-wide) so it only ever fires on an actual stall, not
    every N seconds during idle time between tool calls. anyio.to_thread offloads
    the blocking work to a real worker thread, and dump_traceback_later dumps
    ALL threads by default, so this shows exactly which call the worker thread
    is stuck in -- the forensic gap that made prior hangs (scan_repo AND
    scan_diff, both previously reported) undiagnosable."""
    faulthandler.dump_traceback_later(seconds, repeat=True, file=sys.stderr)
    try:
        yield
    finally:
        faulthandler.cancel_dump_traceback_later()


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
async def scan_repo(repo_path: str, ctx: Context) -> str:
    """Run a full security scan of a repo: Semgrep + Claude triage, a git-history
    secret scan (gitleaks), and dependency-CVE checks across Python, Rust, npm,
    Go, and other ecosystems (pip-audit + trivy). Use for a first pass on a whole
    repo. For just-changed files, use scan_diff instead -- it's much faster.

    Scanner selection lives in all_scanners.run_full_scan -- both this tool and
    the REST API's /scan route call that one function, so a scanner only ever
    needs adding in one place."""
    target = Path(repo_path)
    if not target.exists():
        return f"Error: path does not exist: {repo_path}"

    # ponytail: FastMCP calls sync tool functions directly on the server's single
    # asyncio event loop (see mcp/server/fastmcp/utilities/func_metadata.py) --
    # it does NOT thread-offload them. A sync tool that blocks for minutes freezes
    # the whole server, so it can't relay any response/progress, and Claude Code's
    # own idle-timeout kills the call ("sent no response or progress for 1800s")
    # regardless of vuln-hunter's own internal timeouts. anyio.to_thread.run_sync
    # keeps the event loop free so the server stays alive and report_progress can
    # actually get out.
    scan_id = telemetry.start_scan(repo_path, tool="mcp:scan_repo")
    total_scanners = len(all_scanners.FULL_SCAN_SCANNERS)

    def _on_progress(scanner_name: str, step: int, total: int) -> None:
        # Runs on the anyio worker thread (see run_full_scan's call below), not
        # the event loop -- telemetry.report_progress is a plain sync DB write,
        # safe to call directly; ctx.report_progress is async and belongs to
        # the event loop, so it has to hop back via anyio.from_thread.run.
        telemetry.report_progress(scan_id, step, total, scanner_name)
        anyio.from_thread.run(ctx.report_progress, step, total, f"{scanner_name} done ({step}/{total})")

    try:
        with _stall_watchdog():
            await ctx.report_progress(0, total_scanners, "running semgrep + gitleaks + pip-audit + trivy...")
            findings = await anyio.to_thread.run_sync(
                functools.partial(all_scanners.run_full_scan, str(target), on_progress=_on_progress)
            )
    except Exception as e:
        # A hard process crash/kill never reaches this except -- that's what
        # telemetry.reconcile_stale() catches reactively on the next dashboard
        # poll. This only catches exceptions the process survives long enough
        # to raise.
        telemetry.log_stopper_bug(scan_id, "mcp_server.scan_repo", str(e), exc=e)
        raise

    telemetry.record_scan_results(scan_id, all_scanners.FULL_SCAN_SCANNERS, findings)
    await ctx.report_progress(total_scanners, total_scanners, "done")
    kept, ignored_count = _finalize(repo_path, findings)
    telemetry.complete_scan(scan_id, status="COMPLETED")
    return _format_findings(kept, ignored_count)


@mcp.tool()
async def scan_diff(repo_path: str, ctx: Context, base_ref: str = "HEAD", deep_review: bool = False) -> str:
    """Scan only files changed vs base_ref (default HEAD = uncommitted changes) --
    much cheaper than scan_repo for iterative work. Set deep_review=True to also
    run a second AI pass for business-logic/access-control issues (missing
    ownership checks, etc.) that rule-matching can't express -- costs one extra
    Claude call per changed file.

    Also runs pip-audit/trivy dependency-CVE checks when a lockfile they read is
    among the changed files -- see all_scanners.run_diff_scan for the reasoning
    on why gitleaks (whole-history secret scan) doesn't run here."""
    try:
        changed_files = await anyio.to_thread.run_sync(functools.partial(get_changed_files, repo_path, base_ref))
    except RuntimeError as e:
        return f"Error: {e}"

    scan_id = telemetry.start_scan(repo_path, tool="mcp:scan_diff")
    try:
        with _stall_watchdog():
            await ctx.report_progress(0, 1, "running semgrep...")
            findings = await anyio.to_thread.run_sync(
                functools.partial(all_scanners.run_diff_scan, repo_path, changed_files, deep_review)
            )
    except Exception as e:
        telemetry.log_stopper_bug(scan_id, "mcp_server.scan_diff", str(e), exc=e)
        raise

    telemetry.record_scan_results(scan_id, all_scanners.diff_scanners_invoked(changed_files), findings)
    await ctx.report_progress(1, 1, "done")
    kept, ignored_count = _finalize(repo_path, findings)
    telemetry.complete_scan(scan_id, status="COMPLETED")
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
