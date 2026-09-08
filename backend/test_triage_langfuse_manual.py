"""Telemetry must never break a scan.

If langfuse's configured endpoint is unreachable -- e.g. a stale
LANGFUSE_BASE_URL inherited from another app on the same machine -- the triage
layer must run untraced rather than crash the whole scan (regression: a full
scan died on `requests.exceptions.ConnectionError` to localhost:3000, 2026-09-07).
"""
import contextlib

import triage


def _boom_client():
    class C:
        def start_as_current_observation(self, **_kw):
            raise ConnectionError("simulated: langfuse endpoint refused")
    return C()


def _flush_boom_client():
    """Span creation succeeds; the flush on span close raises -- this happens
    well after the LLM call already returned, so the scan result must stand."""
    class C:
        def start_as_current_observation(self, **_kw):
            @contextlib.contextmanager
            def cm():
                try:
                    yield "generation-obj"
                finally:
                    raise ConnectionError("simulated: langfuse flush refused")
            return cm()
    return C()


def main() -> None:
    orig = triage.get_client
    try:
        triage.get_client = _boom_client
        with triage._triage_observation(name="test", model="x", input=[]) as gen:
            assert gen is None, f"expected None when langfuse is down, got {gen!r}"
        # a None generation must not blow up the completion-mapping helper either
        triage._update_generation_from_completion(None, object(), model="x")
        print("PASS: triage fails open when langfuse span creation is unreachable")

        triage.get_client = _flush_boom_client
        with triage._triage_observation(name="test", model="x", input=[]) as gen:
            assert gen == "generation-obj", f"expected a live span, got {gen!r}"
        print("PASS: triage swallows a failed span flush after the call succeeds")
    finally:
        triage.get_client = orig


if __name__ == "__main__":
    main()
