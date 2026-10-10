"""Regression test for card 150: scan_repo crashes when the triage model
returns an empty reply ('NoneType' has no attribute 'choices').

Tests that triage_finding and review_file handle None responses and
responses with empty choices gracefully -- retry once, then fall back
to unknown exploitability (triage) or empty list (business_logic)
instead of crashing. One finding's failure must never discard others.
"""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure backend is importable
sys.path.insert(0, str(Path(__file__).parent))

import triage
import business_logic


SAMPLE_FINDING = {
    "rule_id": "test.rule",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "test message",
    "snippet": "x = input()",
}


def _make_response(choices_list):
    """Build a fake response object mimicking OpenAI ChatCompletion."""
    resp = MagicMock()
    resp.choices = choices_list
    return resp


def _make_choice(content):
    choice = MagicMock()
    choice.message.content = content
    return choice


def test_triage_none_response():
    """_call_with_retry returns None -> triage_finding should not crash."""
    with patch.object(triage, "_llm_client"):
        with patch.object(triage, "_call_with_retry", return_value=None):
            result = triage.triage_finding(SAMPLE_FINDING)
    assert result["exploitability"] == "unknown"
    assert result["finding_type"] == "rule_confirmed"
    assert result["rule_id"] == SAMPLE_FINDING["rule_id"]
    print("PASS: triage_finding handles None response")


def test_triage_empty_choices():
    """_call_with_retry returns response with choices=[] -> no crash."""
    empty_resp = _make_response([])
    with patch.object(triage, "_llm_client"):
        with patch.object(triage, "_call_with_retry", return_value=empty_resp):
            result = triage.triage_finding(SAMPLE_FINDING)
    assert result["exploitability"] == "unknown"
    assert result["finding_type"] == "rule_confirmed"
    print("PASS: triage_finding handles empty choices")


def test_triage_retries_then_succeeds():
    """First call returns None, second succeeds -> uses second result."""
    good_resp = _make_response([_make_choice('{"explanation":"ok","exploitability":"low","suggested_fix":"none"}')])
    call_count = 0

    def side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return None
        return good_resp

    with patch.object(triage, "_llm_client"):
        with patch.object(triage, "_call_with_retry", side_effect=side_effect):
            result = triage.triage_finding(SAMPLE_FINDING)
    assert call_count == 2
    assert result["exploitability"] == "low"
    print("PASS: triage_finding retries once on None then succeeds")


def test_triage_all_one_failure_keeps_others():
    """triage_all: one finding fails, the other succeeds -> both returned."""
    good_resp = _make_response([_make_choice('{"explanation":"ok","exploitability":"high","suggested_fix":"fix"}')])
    finding_a = {**SAMPLE_FINDING, "rule_id": "a"}
    finding_b = {**SAMPLE_FINDING, "rule_id": "b"}

    def side_effect(client, **kwargs):
        msgs = kwargs.get("messages", [])
        user = msgs[1]["content"] if len(msgs) > 1 else ""
        if "Rule: a" in user:
            return None
        return good_resp

    with patch.object(triage, "_llm_client"):
        with patch.object(triage, "_call_with_retry", side_effect=side_effect):
            results = triage.triage_all([finding_a, finding_b])
    assert len(results) == 2
    by_rule = {r["rule_id"]: r for r in results}
    assert by_rule["a"]["exploitability"] == "unknown"
    assert by_rule["b"]["exploitability"] == "high"
    print("PASS: triage_all keeps all findings even when one fails")


def test_review_file_none_response(tmp_path):
    """review_file: _call_with_retry returns None -> empty list, no crash."""
    f = tmp_path / "sample.py"
    f.write_text("x = 1\n")
    with patch.object(business_logic, "_llm_client"):
        with patch.object(business_logic, "_call_with_retry", return_value=None):
            result = business_logic.review_file(str(f))
    assert result == []
    print("PASS: review_file handles None response")


def test_review_file_empty_choices(tmp_path):
    """review_file: response with choices=[] -> empty list, no crash."""
    f = tmp_path / "sample.py"
    f.write_text("x = 1\n")
    empty_resp = _make_response([])
    with patch.object(business_logic, "_llm_client"):
        with patch.object(business_logic, "_call_with_retry", return_value=empty_resp):
            result = business_logic.review_file(str(f))
    assert result == []
    print("PASS: review_file handles empty choices")


if __name__ == "__main__":
    import tempfile
    test_triage_none_response()
    test_triage_empty_choices()
    test_triage_retries_then_succeeds()
    test_triage_all_one_failure_keeps_others()
    with tempfile.TemporaryDirectory() as td:
        test_review_file_none_response(Path(td))
        test_review_file_empty_choices(Path(td))
    print("\nAll tests passed.")
