"""Manual smoke test: scan -> triage, end to end, against the planted test_sample/."""

import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

from scanner import run_scan
from triage import triage_all


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "test_sample/vulnerable.py"
    findings = run_scan(target)
    print(f"Semgrep found {len(findings)} real findings\n")

    triaged = triage_all(findings)
    for f in triaged:
        print(f"--- {f['rule_id']} (line {f['start_line']}) ---")
        print(f"Severity (scanner): {f['severity']} | Exploitability (Claude): {f['exploitability']}")
        print(f"Explanation: {f['explanation']}")
        print(f"Suggested fix: {f['suggested_fix']}")
        print()


if __name__ == "__main__":
    main()
