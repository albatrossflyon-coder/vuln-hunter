"""Manual regression test for the AI business-logic reasoning pass -- the
riskiest feature in this repo for reintroducing false positives, so this
tests all three cases that matter:
1. A real access-control bug (missing ownership check) is caught.
2. A fixed version of the SAME code shape is NOT flagged (proves it's
   reasoning about the actual check, not pattern-matching function names).
3. Completely unrelated code produces zero findings (no manufactured noise).
"""

import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

from business_logic import review_file


def main():
    vulnerable = review_file("test_sample/business_logic/vulnerable_idor.py")
    assert len(vulnerable) >= 1, "expected the missing-ownership-check bug to be caught"
    assert all(f["finding_type"] == "ai_reasoning" for f in vulnerable)
    print(f"PASS: vulnerable_idor.py -> {len(vulnerable)} finding(s) caught")

    safe = review_file("test_sample/business_logic/safe_with_ownership_check.py")
    assert safe == [], f"expected 0 findings on the safe version, got {len(safe)}: {safe}"
    print("PASS: safe_with_ownership_check.py -> 0 findings (no false positive on similarly-shaped safe code)")

    clean = review_file("test_sample/clean.py")
    assert clean == [], f"expected 0 findings on unrelated clean code, got {len(clean)}"
    print("PASS: clean.py -> 0 findings (no manufactured noise on unrelated code)")


if __name__ == "__main__":
    main()
