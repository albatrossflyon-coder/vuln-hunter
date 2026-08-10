"""Claude triage layer: explains, prioritizes, and suggests fixes for real semgrep
findings. Does NOT hunt for new vulnerabilities — that would reintroduce the
false-positive problem this tool exists to avoid. Every finding passed in here
already came from a rule match against real source code.
"""

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List

import openai
from openai import OpenAI

# ponytail: routed off Anthropic's paid API (2026-08-10, ANTHROPIC_API_KEY
# ran out of credits -- same key job-hunter hit 2026-08-09) onto Groq's free
# tier -- own quota, separate from job-hunter's NVIDIA NIM key, so the two
# don't compete. 30 RPM / 1,000 RPD / 12K TPM free (console.groq.com).
# Swap back to anthropic.Anthropic(...) + "claude-sonnet-4-6" if that ever
# proves insufficient.
TRIAGE_MODEL = "llama-3.3-70b-versatile"


def _llm_client() -> OpenAI:
    return OpenAI(
        base_url="https://api.groq.com/openai/v1",
        api_key=os.getenv("GROQ_API_KEY"),
    )


def _call_with_retry(client: OpenAI, max_attempts: int = 5, **kwargs):
    """Groq's free tier is 12K TPM -- a real ceiling this codebase hits under
    concurrent load (confirmed 2026-08-10 on a full-repo scan), not a theoretical
    one. The SDK's built-in retries aren't enough on their own once several
    concurrent workers are all backed up on the same per-minute budget, so
    retry explicitly with backoff long enough for the window to clear."""
    last_error = None
    for attempt in range(max_attempts):
        try:
            return client.chat.completions.create(**kwargs)
        except openai.RateLimitError as e:
            last_error = e
            if attempt == max_attempts - 1:
                raise
            time.sleep(2 ** attempt * 3)  # 3, 6, 12, 24s
    raise last_error


# Bounded concurrency for triage calls: each is a separate LLM API request.
# Dropped from 5 -> 3 (2026-08-10) after the Groq swap -- 5 concurrent workers
# blew through Groq's 12K TPM free-tier ceiling on a real repo scan; 3 leaves
# more per-minute budget for _call_with_retry's backoff to actually recover.
MAX_CONCURRENT_TRIAGE = 3

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


def triage_finding(finding: Dict[str, Any], model: str = TRIAGE_MODEL) -> Dict[str, Any]:
    # ponytail: SDK default read timeout is much longer -- since triage_all
    # blocks on every concurrent call finishing, one stuck request can stall
    # the whole scan_repo/scan_diff response for a long time, indistinguishable
    # from a hang. Bound it so a stuck call fails fast and visibly instead.
    client = _llm_client()

    user_message = (
        f"Rule: {finding['rule_id']}\n"
        f"Severity (from scanner): {finding['severity']}\n"
        f"CWE: {finding.get('cwe', 'n/a')}\n"
        f"Scanner message: {finding['message']}\n\n"
        f"Source snippet (line numbers as in file):\n{finding['snippet']}"
    )

    response = _call_with_retry(
        client,
        model=model,
        max_tokens=600,
        temperature=0,
        timeout=60.0,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
    )

    text = (response.choices[0].message.content or "").strip()
    parsed = _parse_json_response(text)

    return {**finding, **parsed, "finding_type": "rule_confirmed"}


def triage_all(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not findings:
        return []
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_TRIAGE) as pool:
        return list(pool.map(triage_finding, findings))
