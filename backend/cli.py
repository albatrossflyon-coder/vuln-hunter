"""Plain CLI entrypoint over the same core all_scanners.py functions main.py
(REST) and mcp_server.py (MCP tools) already call -- a third thin adapter,
not a fourth scanning implementation.

Exists specifically to sidestep a class of bug the MCP path has: a
subprocess spawned from mcp_server.py inherits the MCP server's stdin (the
JSON-RPC pipe to Claude Code, which never sees EOF for the life of the
session) unless explicitly redirected. A CLI invocation has no such pipe to
inherit in the first place -- every run is a fresh, isolated process.

# ponytail: two subcommands, stdlib argparse, JSON or plain text out. No
# SARIF/HTML/PDF export, no plugin system, no `doctor`/`update` commands --
# none of that is needed to unblock a scan; add if a real need shows up.
"""

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

from all_scanners import run_diff_scan, run_full_scan
from scanner import get_changed_files


def _print_findings(findings, as_json: bool) -> None:
    if as_json:
        print(json.dumps(findings, indent=2))
        return
    if not findings:
        print("No findings.")
        return
    print(f"{len(findings)} finding(s):\n")
    for f in findings:
        print(f"[{f.get('severity', '?')}] {f['rule_id']} -- {f['path']}:{f['start_line']}")
        print(f"  {f['message']}\n")


def main() -> None:
    parser = argparse.ArgumentParser(prog="vuln-hunter")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Full scan: semgrep + gitleaks + pip-audit + trivy")
    scan.add_argument("repo_path")
    scan.add_argument("--json", action="store_true")

    diff = sub.add_parser("diff", help="Scan only files changed vs. base_ref")
    diff.add_argument("repo_path")
    diff.add_argument("--base-ref", default="HEAD")
    diff.add_argument("--deep-review", action="store_true")
    diff.add_argument("--json", action="store_true")

    args = parser.parse_args()
    repo_path = str(Path(args.repo_path).resolve())

    try:
        if args.command == "scan":
            findings = run_full_scan(repo_path)
        else:
            changed_files = get_changed_files(repo_path, args.base_ref)
            findings = run_diff_scan(repo_path, changed_files, deep_review=args.deep_review)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    _print_findings(findings, args.json)


if __name__ == "__main__":
    main()
