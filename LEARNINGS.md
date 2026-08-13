# Learnings

How `start-to-finish` (and anyone debugging this repo) gets better with real use instead of starting cold every time. Not a chat log — only non-obvious things worth remembering: a scanner quirk, a false-positive pattern, a failure mode nobody expected.

**Format:** one entry per topic. Keep each entry to a few lines — a fact plus why it matters, not a transcript. Prune entries that stop being true (a since-fixed bug, a changed default) rather than let them accumulate as noise.

```
## <topic>

- <date> — <what was learned, and why it matters next time>
```

---

## scanning

- 2026-08-08 — **The dashboard's severity counter only recognizes `critical`/`high`/`medium`/`low`.** A trivy finding with severity `"UNKNOWN"` (happens when trivy's own CVE database lacks a rating for that CVE) is invisible to the counter even though the finding is still included in the total count — a real, confusing discrepancy between "total findings" and "sum of the severity buckets shown." Not fixed as of this entry; a real, scoped fix (main.py's dashboard aggregation), not started.
- 2026-07-23 — **`scan_repo`'s underlying semgrep subprocess call has a hardcoded 300-second timeout and silently fails (not partially reports) on larger repos.** If a scan on a real-sized repo comes back suspiciously fast or empty, check for this before trusting the result. Fixed once already (2026-07-23) but re-verify the fix is still in place before assuming — this is exactly the kind of thing a later refactor could silently reintroduce. Workaround if it recurs: call `semgrep.exe` directly via `run_in_background` with no imposed timeout, same configs vuln-hunter uses.
- 2026-08-08 — **A real hang in `scan_diff` traced to `get_changed_files` in `scanner.py`** — it was the one subprocess call that never got the Windows MCP-stdin-inheritance `stdin=DEVNULL` fix already applied everywhere else in the codebase. If `scan_diff` hangs, check this function first via `diagnose_hang.ps1`'s actual thread trace before assuming a new, unrelated bug — don't just kill the process and retry blind.
- 2026-08-08 — **The "Repo staleness" dashboard display shows the temp clone path, not the real scanned URL** (`main.py`'s `/scan/url` handler never passes the real URL through to telemetry, only the tempdir it cloned into). Cosmetic, not a scanning-correctness bug, but confusing when reviewing scan history. Known, scoped, not fixed as of this entry.

## false positives

- 2026-08-03 — **A single semgrep hit is a lead, not a confirmed finding.** A private security advisory was filed off one flagged line before reading the surrounding code, and had to be corrected — the file already had a pre-existing guard the flagged line didn't account for. Always read the whole file (or run `fp-check`) before reporting a static-analysis hit externally, especially upstream.

## operations

- 2026-08-08 — **`fff-mcp` reliably disconnects during/after heavy scanning activity** (and apparently GitHub's own security scanning too) — happened 4-5+ times in one session. Not root-caused. Always recovered via `/mcp` reconnect; not a scan-correctness issue, just an annoyance to expect, not panic about.
- 2026-08-10 — **Provider is Groq** (free-tier), not Anthropic/OpenAI directly, for cost reasons. If scoring/triage output looks off, check which model actually ran before assuming a prompt bug.
- 2026-08-13 — **When the MCP tool errors "Connection closed," check for an orphaned `mcp_server.py` process before assuming it's just flaky.** Root-caused once: `jmunch_mcp/proxy.py`'s `Proxy.run()` spawns the upstream child (`asyncio.create_subprocess_exec`, line 66) but never explicitly terminates it — on any exit path it only cancels its own local asyncio tasks (`c2s`/`s2c`/`child_wait`), not the child process itself. If the proxy (`jmunch-mcp.exe`) dies or gets disconnected mid-session, its `mcp_server.py` child survives as an orphan and can itself have spawned further orphaned children. Confirmed via `Get-CimInstance Win32_Process` showing a live `mcp_server.py` whose `ParentProcessId` no longer existed. Diagnostic: `Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" | Where-Object { $_.CommandLine -match 'vuln-hunter|mcp_server' }`, then check each PID's parent is actually alive. This is a bug in `jmunch-mcp` (not our repo), so it isn't something to fix here — just something to check for and clean up (`taskkill /F /PID <n>`) when the connection drops, since it'll recur every time the proxy exits uncleanly.

## general

*(no entries yet — this fills in as start-to-finish runs into real, non-obvious things worth remembering)*

---

## Usage Log

The actual evidence trail. One line every time Step 1 checks this file:

```
- <date> — checked | hit: <which entry, what it saved> | miss: nothing relevant | empty: no entries yet
```

- 2026-08-12 — file created, seeded with 6 real entries pulled from actual session history (not hypothetical) — first real check happens next time `start-to-finish` runs against this repo.
