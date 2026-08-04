"""Manual regression test: scan_repo's blocking work (semgrep subprocess, Claude
triage) must run off the asyncio event loop, not on it -- the earlier bug had
FastMCP calling the (sync) tool function directly on its single event loop, which
froze the whole server for the scan's entire duration. With the server frozen, it
can't relay any response or progress, so Claude Code's own idle-timeout kills the
call ("sent no response or progress for 1800s") no matter how long the real work
actually takes. This proves the event loop stays free to run other coroutines
while scan_repo's simulated blocking work is in flight.
"""

import asyncio
import sys
import time
from unittest.mock import patch

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

import all_scanners
import mcp_server


class _FakeContext:
    async def report_progress(self, progress, total=None, message=None):
        pass


def _fake_run_full_scan(repo_path):
    # simulates the real blocking work run_full_scan does: semgrep subprocess,
    # Claude triage, gitleaks/pip-audit/trivy subprocesses -- all now behind
    # this one function since the 2026-08-03 all_scanners refactor.
    time.sleep(1.0)
    return []


async def main():
    heartbeats = 0

    async def heartbeat():
        nonlocal heartbeats
        while True:
            heartbeats += 1
            await asyncio.sleep(0.05)

    with patch.object(all_scanners, "run_full_scan", _fake_run_full_scan):
        heartbeat_task = asyncio.create_task(heartbeat())
        start = time.monotonic()
        await mcp_server.scan_repo(repo_path=".", ctx=_FakeContext())
        elapsed = time.monotonic() - start
        heartbeat_task.cancel()

    # ~1s of blocking work at a 0.05s heartbeat interval should yield ~20 ticks.
    # A blocked event loop would yield 0 or 1 (only the tick that snuck in before
    # the blocking call started).
    assert heartbeats > 10, (
        f"event loop only ticked {heartbeats} times during a {elapsed:.2f}s scan -- "
        "the blocking work is freezing the event loop again"
    )
    print(f"PASS: event loop ticked {heartbeats} times during a {elapsed:.2f}s scan_repo call (not blocked)")


if __name__ == "__main__":
    asyncio.run(main())
