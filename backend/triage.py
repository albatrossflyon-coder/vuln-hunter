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
from langfuse import get_client
from openai import OpenAI

# ponytail: routed off Anthropic's paid API (2026-08-10, ANTHROPIC_API_KEY
# ran out of credits -- same key job-hunter hit 2026-08-09) onto Groq's free
# tier, then off Groq (2026-08-19, after Groq deprecated the prior model with
# zero warning AND its replacement's free tier turned out to cap at 8K TPM --
# too tight for real scans) onto Z.AI's free tier instead. Own quota, separate
# key from Pi's WSL2 setup so the two don't compete. Swap back to
# anthropic.Anthropic(...) + "claude-sonnet-4-6" if this ever proves
# insufficient too.
TRIAGE_MODEL = "glm-4.7-flash"

# ponytail: fallback chain, tried in order when the primary hits a rate limit
# or any other API error (model deprecated/renamed, daily cap, etc.) -- see
# _call_with_retry. Groq demoted from primary to fallback 2026-08-19 rather
# than dropped outright, so its capacity isn't lost, just no longer a single
# point of failure. Each provider is its own account/quota, no shared ceiling.
# "extra" holds kwargs that only apply to that one provider's call -- e.g.
# gpt-oss-120b is a reasoning model that needs reasoning_effort capped or it
# burns the token budget on internal reasoning before writing the JSON
# answer (confirmed 2026-08-19); other providers don't recognize that
# parameter, so it must NOT be sent to them.
FALLBACK_PROVIDERS = [
    {
        "base_url": "https://api.groq.com/openai/v1",
        "api_key_env": "GROQ_API_KEY",
        "model": "openai/gpt-oss-120b",
        "extra": {"reasoning_effort": "low"},
    },
    {
        "base_url": "https://openrouter.ai/api/v1",
        "api_key_env": "OPENROUTER_API_KEY",
        "model": "nvidia/nemotron-3-super-120b-a12b:free",
        "extra": {},
    },
    {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "api_key_env": "GEMINI_API_KEY",
        "model": "gemini-3.7-flash",
        "extra": {},
    },
    {
        "base_url": "https://api.mistral.ai/v1",
        "api_key_env": "MISTRAL_API_KEY",
        "model": "devstral-2512",  # code-focused, 1M TPM on this account -- most headroom of any tier here
        "extra": {},
    },
]


def _llm_client() -> OpenAI:
    return OpenAI(
        base_url="https://api.z.ai/api/paas/v4/",
        api_key=os.getenv("ZAI_API_KEY"),
    )


def _update_generation_from_completion(generation, response, *, model: str) -> None:
    """Map an OpenAI-style ChatCompletion response onto the active Langfuse
    generation. Shared by the primary call and every fallback-provider retry
    so usage/output reporting is consistent regardless of which provider
    actually served the request."""
    content = None
    if response.choices:
        content = response.choices[0].message.content
    usage_details = None
    if response.usage:
        usage_details = {
            "input": response.usage.prompt_tokens or 0,
            "output": response.usage.completion_tokens or 0,
            "total": response.usage.total_tokens or 0,
        }
    generation.update(model=model, output=content, usage_details=usage_details)


def _call_with_retry(client: OpenAI, max_attempts: int = 5, **kwargs):
    """Groq's free tier is 12K TPM -- a real ceiling this codebase hits under
    concurrent load (confirmed 2026-08-10 on a full-repo scan), not a theoretical
    one. The SDK's built-in retries aren't enough on their own once several
    concurrent workers are all backed up on the same per-minute budget, so
    retry explicitly with backoff long enough for the window to clear."""
    langfuse = get_client()
    with langfuse.start_as_current_observation(
        as_type="generation",
        name="vuln-hunter-triage",
        model=kwargs.get("model"),
        input=kwargs.get("messages"),
    ) as generation:
        last_error = None
        for attempt in range(max_attempts):
            try:
                response = client.chat.completions.create(**kwargs)
                _update_generation_from_completion(generation, response, model=kwargs.get("model"))
                return response
            except openai.RateLimitError as e:
                last_error = e
                if attempt == max_attempts - 1:
                    break
                time.sleep(2 ** attempt * 3)  # 3, 6, 12, 24s
            except openai.APIStatusError as e:
                # Non-rate-limit API error (model deprecated/renamed, bad
                # request, etc.) -- confirmed 2026-08-19 when Groq retired
                # llama-3.3-70b-versatile and this fell straight through the
                # RateLimitError-only catch above into an unhandled crash,
                # skipping the fallback chain entirely. Retrying the identical
                # request won't fix a model that doesn't exist, so go straight
                # to the fallback providers instead of burning the backoff window.
                last_error = e
                break

        # Groq's per-minute retries are exhausted, or the primary hit a
        # non-transient error above. Walk the fallback chain rather than
        # failing the scan.
        for provider in FALLBACK_PROVIDERS:
            fallback_client = OpenAI(
                base_url=provider["base_url"],
                api_key=os.getenv(provider["api_key_env"]),
            )
            try:
                response = fallback_client.chat.completions.create(
                    **{**kwargs, **provider.get("extra", {}), "model": provider["model"]}
                )
                _update_generation_from_completion(generation, response, model=provider["model"])
                return response
            except Exception:
                continue
        generation.update(level="ERROR", status_message=str(last_error) if last_error else "all providers exhausted")
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
        max_tokens=1200,
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
