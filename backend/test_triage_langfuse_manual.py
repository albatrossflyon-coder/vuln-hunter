"""Telemetry must never break a scan.

If langfuse's configured endpoint is unreachable -- e.g. a stale
LANGFUSE_BASE_URL inherited from another app on the same machine -- the triage
layer must run untraced rather than crash the whole scan (regression: a full
scan died on `requests.exceptions.ConnectionError` to localhost:3000, 2026-09-07).
"""
import triage


def _boom_client():
    class C:
        def start_as_current_observation(self, **_kw):
            raise ConnectionError("simulated: langfuse endpoint refused")
    return C()


def main() -> None:
    orig = triage.get_client
    triage.get_client = _boom_client
    try:
        with triage._triage_observation(name="test", model="x", input=[]) as gen:
            assert gen is None, f"expected None when langfuse is down, got {gen!r}"
        # a None generation must not blow up the completion-mapping helper either
        triage._update_generation_from_completion(None, object(), model="x")
        print("PASS: triage fails open when langfuse is unreachable")
    finally:
        triage.get_client = orig


if __name__ == "__main__":
    main()
