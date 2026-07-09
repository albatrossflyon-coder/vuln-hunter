"""Claude triage layer: explains, prioritizes, and suggests fixes for real semgrep
findings. Does NOT hunt for new vulnerabilities — that would reintroduce the
false-positive problem this tool exists to avoid. Every finding passed in here
already came from a rule match against real source code.
"""

import json
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List

import anthropic

# Bounded concurrency for triage calls: each is a separate Claude API request,
# so this stays low enough to avoid a rate-limit thundering herd while still
# fixing the real bug (triage_all used to run these one at a time -- on a scan
# with dozens of findings, that meant tens of minutes of serial API latency
# with zero progress feedback, which just looked like a hang).
MAX_CONCURRENT_TRIAGE = 5

SYSTEM_PROMPT = """You are a security triage assistant. You will be given a single
static-analysis finding (rule ID, severity, message, and the exact source code
snippet it matched). Your job is ONLY to:

1. Explain in plain language why this specific matched code is a real risk
2. Rate exploitability in this exact context (not in the abstract) as one of:
   low, medium, high, critical
3. Suggest a concrete, minimal code fix for the exact snippet shown

Do NOT invent additional vulnerabilities not present in the given snippet. Do NOT
guess about code you cannot see. If the snippet doesn't give you enough context to
judge exploitability, say so explicitly rather than assuming the worst or the best.

Respond with ONLY the raw JSON object below — no markdown code fences, no ```json
wrapper, no text before or after it:
{"explanation": "...", "exploitability": "low|medium|high|critical", "suggested_fix": "..."}"""


def _parse_json_response(text: str) -> Dict[str, Any]:
    """Claude sometimes wraps JSON in ```json fences despite instructions not to. Strip them."""
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("\n", 1)[1] if "\n" in stripped else stripped
        if stripped.endswith("```"):
            stripped = stripped.rsplit("```", 1)[0]
        stripped = stripped.strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return {"explanation": text, "exploitability": "unknown", "suggested_fix": ""}


def triage_finding(finding: Dict[str, Any], model: str = "claude-sonnet-4-6") -> Dict[str, Any]:
    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    user_message = (
        f"Rule: {finding['rule_id']}\n"
        f"Severity (from scanner): {finding['severity']}\n"
        f"CWE: {finding.get('cwe', 'n/a')}\n"
        f"Scanner message: {finding['message']}\n\n"
        f"Source snippet (line numbers as in file):\n{finding['snippet']}"
    )

    response = client.messages.create(
        model=model,
        max_tokens=600,
        temperature=0,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    text = "".join(block.text for block in response.content if block.type == "text").strip()
    parsed = _parse_json_response(text)

    return {**finding, **parsed, "finding_type": "rule_confirmed"}


def triage_all(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not findings:
        return []
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_TRIAGE) as pool:
        return list(pool.map(triage_finding, findings))
