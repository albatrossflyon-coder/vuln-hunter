"""Second, separate AI reasoning pass for business-logic/access-control issues
that pattern-based static analysis structurally cannot express -- e.g. a
delete/update action that never checks the caller actually owns the resource.
Semgrep's rules match syntax patterns; this reasons about intent, which is
exactly the class of bug rule-matching can't catch (and exactly the class of
bug that's easiest for an LLM to hallucinate about if not constrained hard).

Kept strictly separate from scanner.py's rule-confirmed findings and tagged
"ai_reasoning" everywhere, specifically so nothing here is ever presented with
the same confidence as a real rule match. This is the price of catching a
class of bug rules can't see: it can be wrong, and must say so honestly.
"""

import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List

import anthropic

# Bounded concurrency, same reasoning as triage.py's MAX_CONCURRENT_TRIAGE:
# review_files used to call review_file() one file at a time -- on a diff
# with many changed files that was pure serial API latency with no progress
# feedback, easily adding up to hours and looking exactly like a hang.
MAX_CONCURRENT_REVIEWS = 5

SYSTEM_PROMPT = """You are doing a business-logic / access-control security \
review of ONE file, as a second pass that complements automated pattern-based \
scanning already done separately. That automated scanning already checked for \
known vulnerability patterns (injection, hardcoded secrets, unsafe eval, etc.) \
-- your job is different and narrower: look ONLY for missing authorization/
ownership checks, broken access control, or logic that trusts input it \
shouldn't, where understanding intent (not pattern-matching) is required.

Examples of what you're looking for: a delete/update/read handler that acts \
on a resource ID from the caller without verifying the caller owns or may \
access that specific resource; an admin-only action reachable without an \
admin/role check; validation performed on one code path but not another that \
reaches the same sensitive operation.

CRITICAL RULES -- breaking any of these makes your output useless:
1. Only flag something you can ground in code ACTUALLY PRESENT in the file below.
   Quote the exact lines. Do not describe a concern without a quote.
2. If the authorization check might happen elsewhere (middleware, a decorator, \
   a base class you can't see the body of), say that explicitly as uncertainty \
   -- do NOT assume it's missing just because you can't see it.
3. If you find nothing you're prepared to ground in a quote, return exactly: []
   Do not invent a finding to seem useful. An empty result is a valid, common,
   and correct result.
4. Every finding needs an honest confidence level -- this is reasoning about
   intent, not a rule match, so never claim certainty a pattern-matcher would.

Respond with ONLY a raw JSON array (no markdown fences), each item exactly:
{"start_line": int, "end_line": int, "quoted_code": "...", "concern": "...", "confidence": "low"|"medium"|"high"}"""


def review_file(file_path: str, model: str = "claude-sonnet-4-6") -> List[Dict[str, Any]]:
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return []

    content = path.read_text(encoding="utf-8", errors="replace")
    numbered = "\n".join(f"{i + 1}: {line}" for i, line in enumerate(content.splitlines()))

    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    response = client.messages.create(
        model=model,
        max_tokens=1200,
        temperature=0,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": f"File: {path.name}\n\n{numbered}"}],
    )
    text = "".join(b.text for b in response.content if b.type == "text").strip()
    items = _parse_json_array(text)

    findings = []
    for item in items:
        if not all(k in item for k in ("start_line", "end_line", "quoted_code", "concern", "confidence")):
            continue  # drop malformed items rather than guess at missing fields
        findings.append({
            "finding_type": "ai_reasoning",
            "rule_id": "ai-reasoning.business-logic",
            "path": str(path),
            "start_line": item["start_line"],
            "end_line": item["end_line"],
            "matched_code": item["quoted_code"],
            "snippet": item["quoted_code"],
            "message": item["concern"],
            "severity": "REVIEW",
            "cwe": None,
            "owasp": None,
            "explanation": item["concern"],
            "exploitability": item["confidence"],
            "suggested_fix": "",
        })
    return findings


def _parse_json_array(text: str) -> List[Dict[str, Any]]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("\n", 1)[1] if "\n" in stripped else stripped
        if stripped.endswith("```"):
            stripped = stripped.rsplit("```", 1)[0]
        stripped = stripped.strip()
    try:
        parsed = json.loads(stripped)
        return parsed if isinstance(parsed, list) else []
    except json.JSONDecodeError:
        return []


def review_files(file_paths: List[str]) -> List[Dict[str, Any]]:
    if not file_paths:
        return []
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_REVIEWS) as pool:
        results = pool.map(review_file, file_paths)
        return [finding for file_findings in results for finding in file_findings]
