# Build Log — vuln-hunter

**Repo**: C:\Repos\vuln-hunter | github.com/albatrossflyon-coder/vuln-hunter (public)

AI-assisted security code reviewer. Hybrid architecture: real static analysis
(Semgrep) for ground-truth vulnerability detection, an LLM (currently Groq /
Llama 3.3 70B, see 2026-08-10 entry) for triage, exploitability assessment,
and fix suggestions.

**Rule: Update this file every time a file is added, changed, or a feature ships.**

## Tech Stack

- **Languages**: Python, TypeScript
- **Frameworks/Libraries**: FastAPI, Next.js, React, Tailwind CSS
- **AI/ML**: Z.AI (triage/exploitability, current), Groq/Llama 3.3 70B (earlier fallback), MCP Protocol, GraphQL (strawberry-graphql, query_repo/query_scan live)
- **Cloud/Hosting**: Vercel (frontend), Render (backend)
- **Dev Tools**: Semgrep, Gitleaks, pip-audit, Trivy, pytest, Rich, Textual

---

## 2026-08-21 12:20 AM CDT — GraphQL: auth gate + frontend demo panel, feature now end-to-end

**Auth gate:** `/graphql` now behind `require_scan_key`, stricter than this codebase's existing pattern (read-only `/telemetry`/`/health` stay open) since all 3 resolvers are live and GraphQL invites future mutations. Verified with a real `TestClient`: no key → 401, wrong key → 401, right key → 200 and reaches the resolver, `/health` unaffected.

**Frontend:** new "Lookup Scan by ID" panel on the dashboard (`frontend/app/dashboard/page.tsx`), querying `queryScan` + `findingsForScan` in one round trip through a new `frontend/app/api/graphql/route.ts` server-side proxy (same `SCAN_API_KEY`-off-the-browser pattern as the existing `scan-url/route.ts`). Caught one real bug before implementation: Hermes' plan used snake_case (`repo_id`, `scan_id`) but Strawberry's live schema is camelCase (`repoId`, `findingsForScan(scanId:...)`) — confirmed directly via `schema.schema.as_str()`, corrected before Claude Code implemented it.

**Verified for real:** ran both dev servers locally, hit the proxy route with `curl` against a real `scan_id`, then did an actual browser click-through (chrome-devtools-mcp) confirming the panel renders and shows real data. `scan_diff` clean on both diffs.

**GraphQL feature is now functionally complete end-to-end** (backend + gate + frontend). Not done: merge to `master` (holding pending review).

---

## 2026-08-20 11:14 PM CDT — GraphQL scaffold → all 3 resolvers live, via a real 3-agent herdr handoff (2 phases)

**Phase 1 — query_repo/query_scan:** wired to real data — `query_repo` scans `telemetry.get_repo_staleness()` for a matching `repo_path`; `query_scan` runs a direct SQL lookup against the `scans` table via `telemetry._connect()` (no existing `get_scan_by_id` helper to reuse — confirmed by listing every function in `telemetry.py` before writing new SQL).

**Phase 2 — findings_for_scan:** the real gap phase 1 found (no persistent per-finding storage keyed by `scan_id`, only aggregated `scanner_metrics` counts) is now closed. Added a `findings` table to `init_db()` (PK `finding_id` = the same `fingerprint()` `ignore_store.py` already uses, FK `scan_id → scans.scan_id ON DELETE CASCADE`, indexes on `scan_id`/`rule_id`). `record_scan_results()` now `INSERT OR REPLACE`s each finding into it alongside its existing `scanner_metrics` aggregation. New `telemetry.get_findings_by_scan_id(scan_id)` joins to `scans` for `repo_path` and runs results through `ignore_store.filter_ignored()` before returning, so already-ignored findings don't leak into the GraphQL view. `findings_for_scan` calls it and maps `message` (falling back to `rule_id`) to `Finding.title`, `severity` (falling back to `exploitability`) to `Finding.severity` — precedence documented inline since the plan flagged both as genuinely ambiguous. `require_scan_key` gating still deliberately untouched — same reasoning as phase 1, no new attack surface opened by these reads.

**Process note:** both phases built via a real 3-agent herdr session (Claude Code + Pi/omp + Hermes, all in WSL2, workspace pointed at this repo on `feature/graphql-scaffold`) — Hermes wrote both `PLAN_GRAPHQL.md` (phase 1) and `PLAN_GRAPHQL_PHASE2.md` (the findings-table design), Claude Code implemented against each plan rather than re-deriving it; Pi produced `BACKLOG_SCAN.md` (16 other real, sourced gaps — see below) once its CLIProxyAPI routing was actually working. Real infra issues hit and fixed along the way (unrelated to the GraphQL work itself, logged in `herdr.md`): a WSL2 `.bashrc` PATH-clobbering bug had silently broken `hermes`/`omp` on PATH; Pi's original Z.AI key turned out to have no active coding plan (429→529 errors); several CLIProxyAPI model IDs were deprecated/quota-capped/incompatible with Hermes' auto-sent `reasoning_effort` param before landing on working combos (`gemini-2.5-flash` for Hermes; Pi's `omp` never actually got a working custom-provider route despite several attempts — real open item, see `herdr.md`).

**Verified before calling it done:**
- `vuln-hunter scan_diff` on both diffs: 0 findings on `backend/schema.py` or the new `backend/telemetry.py` code. One pre-existing finding surfaced in `telemetry.py` (`_push_remote`'s `urllib.request.urlopen` call, line ~77, no scheme validation) — well outside anything either diff touched, a genuine design tradeoff (validating a scheme on an internal self-configured mirror URL) rather than a mechanical fix, so flagged here rather than silently changed. The other 5 findings both scans surfaced are pre-existing content in the untracked stray `vuln-hunter/` nested folder (already flagged as a known cleanup item in the 2026-08-06 entry below) — unrelated to this change.
- Direct reuse/simplification review against `telemetry.py`'s real function list both times: clean, no existing helper missed, no unnecessary complexity added.
- Real functional smoke tests against the live SQLite DB (not synthetic), including phase 2's full round trip: inserted a real finding via `record_scan_results()`, confirmed it comes back correctly through `get_findings_by_scan_id()` (with `ignore_store.filter_ignored()` applied) and through the `findings_for_scan` GraphQL resolver with correct title/severity mapping; confirmed a nonexistent `scan_id` returns `[]` cleanly; test rows cleaned up afterward, no pollution of the real DB. `strawberry-graphql` was in `requirements.txt` from the original scaffold commit but was never actually installed in `venv` until this session — fixed as part of running phase 1's smoke test.

**Not done / explicitly deferred:** `require_scan_key` gating for `/graphql` once real data access exists there (still not needed today — everything exposed is already-public telemetry). Pi's `omp` custom-provider routing through CLIProxyAPI — real open item, needs `omp`'s actual docs, not more guessing.

**Also produced this session (separate from GraphQL):** `BACKLOG_SCAN.md` (repo root) — 16 other real, sourced (not speculative) gaps pulled from this file and `LEARNINGS.md`, written by the same herdr session's Claude Code agent.

---

## 2026-08-18 11:18 PM CDT — Groq→Z.AI triage swap + GraphQL scaffold: committed, self-scan verified before push

**What shipped:** `backend/triage.py` primary LLM moved off Groq (deprecated the prior model with no warning, replacement's free tier capped too tight for real scans) onto Z.AI (`glm-4.7-flash`); Groq demoted to first fallback (`gpt-oss-120b`) rather than dropped. `_call_with_retry` now catches non-rate-limit `APIStatusError`s (e.g. a deprecated/renamed model) and falls through to the fallback chain instead of crashing outright — this exact gap is what caused the Groq deprecation to break the live scan pipeline in the first place. Also added `backend/schema.py`, a Strawberry GraphQL scaffold (types/resolvers stubbed, TODOs point at real data sources), wired into `main.py` at `/graphql` — output of a real Pi↔Claude Code multi-agent handoff test (Pi wrote the plan, Claude Code implemented it) on branch `feature/graphql-scaffold`.

**Verified before trusting the triage.py change:** rather than assume the swap didn't break the scanner, ran a real `scan_repo` against a freshly-cloned external target (`duolahypercho/codex-router`, cloned to `reference-repos/` per the New Repo Security Scan Rule) through the live MCP tool — i.e. the actual code path that now hits Z.AI instead of Groq. Came back clean (no error, no timeout) with 15 real findings (13 `detect-child-process` command-injection-pattern warnings in the target's installer scripts, 1 dependency CVE, one flagged high-exploitability with a concrete suggested fix) — confirms the scanner itself is still functioning correctly post-change, not just that the code imports cleanly. Committed `48809f4` on `feature/graphql-scaffold`, not yet pushed as of this entry.

---

## 2026-08-14 8:25 PM CDT — Feature idea captured from deepsec (Vercel Labs): diff-mode + revalidate pass

**Status: idea captured, not built.**

Evaluated `vercel-labs/deepsec` (read-first-then-scanned per the standing security rule — 66 findings, none real: `fixtures/vulnerable-app/` is deepsec's own deliberately-vulnerable test app for validating its detection matchers, the "leaked" API key is inside its own `dev-auth-bypass.ts` matcher pattern, and the rest is standard `pnpm-lock.yaml` dependency-CVE hygiene). It's a same-category tool to this one — agent-powered SAST — but built for expensive, one-shot deep audits of large mature codebases using top-tier reasoning models (its own README states scans can cost thousands to tens-of-thousands of dollars), not the cheap/frequent scanning this repo does. Not adopted — cost model and paid-API-key requirement don't fit how Chris actually uses security scanning (evaluating many candidate repos cheaply via free-tier models).

**Two things worth stealing for `vuln-hunter`, though:**
1. **`process --diff` mode** — deepsec can run its AI investigation on just the files changed in a diff, meant for PR review/CI gating. `vuln-hunter` currently has `scan_repo` (full repo) and `scan_diff` (already exists, per the fast-path note in CLAUDE.md's Quality Gate section) — worth checking `scan_diff`'s actual feature parity against this pattern rather than assuming it already covers the same ground.
2. **`revalidate` pass** — a dedicated step that re-checks existing findings against git history to cut the false-positive rate before a finding gets reported. This directly targets a real recurring problem: Chris has been burned before filing a security advisory off a single semgrep line that turned out to be a false positive (see `feedback-run-fp-check-before-external-reports` in CC memory) — the `fp-check` skill is the current manual mitigation, but a built-in automated revalidation pass would close this gap at the tool level instead of relying on remembering to run a separate skill every time.

Reference clone kept for study (not installed, not run — running it costs real money against its own stated pricing): `C:\Repos\reference-repos\deepsec`.

---

## 2026-08-13 — Langfuse tracing wired into triage.py's LLM call path

Instrumented `_call_with_retry` (the single funnel every triage call already routes through — primary Groq call plus all three fallback providers) with a Langfuse `generation` observation: model name, full input messages, output content, and real token usage (mapped from the OpenAI-style `usage.prompt_tokens`/`completion_tokens`/`total_tokens` into Langfuse's `usage_details` convention) via a shared `_update_generation_from_completion` helper, so the mapping is identical whether Groq or a fallback provider actually served the call. `langfuse` package installed into `backend/venv` (the actual venv the MCP server runs from, not the global Python). Second tool wired into Langfuse tonight, after nanobot — one at a time per explicit instruction, see `albatross-automations/BUILDLOG.md` for the cross-project rollout status.

**Verified for real:** called `triage_finding()` directly against a synthetic-but-real finding (`eval(user_input)`), loading `backend/.env` the same way `mcp_server.py`/`cli.py`/`main.py` already do (`load_dotenv(Path(__file__).parent / ".env")`) rather than guessing at env var propagation. Got a genuine correct triage result back (`exploitability: critical`, real explanation and fix suggestion) — then fetched the actual observation from Langfuse via its REST API and confirmed real data: `model: llama-3.3-70b-versatile` (primary Groq succeeded, no fallback needed), real `usageDetails` (input 306 / output 131 / total 437), full input/output captured correctly.

**Not done this pass:** the live MCP server process (wrapped by `jmunch-mcp`, PID confirmed running from `backend/venv`) was not restarted to pick up this code change — that requires a `/mcp` reconnect only the user can trigger, per the known jmunch-mcp orphan-process behavior. The code path itself is proven correct via direct invocation; the next real scan run through the actual MCP tool will be the first live confirmation, not yet observed.

## 2026-08-12 — Added LEARNINGS.md (Kaizen self-evolving pattern)

Added `LEARNINGS.md` at repo root, seeded with 6 real entries from actual session history (the trivy `UNKNOWN`-severity dashboard-counter gap, the `scan_repo` 300s hardcoded semgrep timeout, the `scan_diff` hang root-caused to `get_changed_files` missing `stdin=DEVNULL`, the dashboard's temp-path-instead-of-real-URL display bug, the fp-check-before-external-reports lesson, the recurring `fff-mcp` disconnect-during-scans pattern) — not an empty scaffold. This wires the repo into the `start-to-finish` skill's Kaizen layer: Step 1 checks this file before diagnosing a new issue here, Step 8 adds new entries after finishing if something non-obvious came up. Committed `8b934e1`, pushed, remote SHA independently verified.

---

## Why hybrid, not pure-LLM

Asking an LLM to freely hunt for vulnerabilities produces too many false
positives/negatives to be credible — that's the classic failure mode of "AI
security tools." Instead: Semgrep (a real, widely-used static analysis engine)
does detection against known rule patterns — that's the ground truth. The
LLM's job is strictly downstream of that: explain *why* a specific matched
finding is risky in context, rate exploitability, and suggest a concrete fix.
It never invents a finding that Semgrep didn't already flag.

## Changelog

### 2026-08-13 6:00 PM CDT — triage.py: 3-provider fallback chain (Groq → OpenRouter → Gemini → Mistral)

**Status: committed, pushed, remote SHA independently verified below.**

Groq's daily token cap (100K TPD) and OpenRouter's free-tier daily cap (50 free-model requests/day) both got exhausted the same evening — a real, confirmed collision, not theoretical. `_call_with_retry`'s existing backoff (3/6/12/24s) can't wait out a *daily* cap that says "try again in 14m47s." Added `FALLBACK_PROVIDERS`, a list `_call_with_retry` walks after Groq's retries exhaust: OpenRouter (`nvidia/nemotron-3-super-120b-a12b:free`, already proven working in nanobot) → Gemini (`gemini-3.7-flash`, genuinely free via AI Studio, verified 2026-08-13 — the paid-looking "$0.75/1M" price from a promo email is a separate billed tier, not this one) → Mistral (`devstral-2512`, code-focused, 1,000,000 TPM on this account — the most headroom of any tier here, verified against the account's real per-model rate-limit page rather than guessed). Each is an independent daily quota on a separate account, so one or two colliding doesn't take the whole triage layer down. `MISTRAL_API_KEY` and `GEMINI_API_KEY` added to `backend/.env`. Verified end-to-end with a real smoke test against a live finding (Groq still exhausted at test time, so it genuinely exercised the fallback path, not just imports) — got a correct, sensible triage response back.

### 2026-08-13 6:05 PM CDT — Root-caused the recurring "MCP error -32000: Connection closed" to an orphaned upstream process, not flakiness

Hit "Connection closed" twice in one session (once mid `scan_diff`, once mid `scan_repo`) and, instead of just falling back to direct semgrep again like every prior time, actually checked for a cause. Found two `mcp_server.py` processes running via `Get-CimInstance Win32_Process`: PID 2776 (parent `jmunch-mcp.exe`, PID 14508) and PID 26548 (parent 2776, i.e. vuln-hunter's own server had itself spawned a further child). **`jmunch-mcp.exe` (the proxy Claude Code actually talks to) was already dead** — `Get-Process -Id 14508` returned nothing — but its child tree survived as orphans. Root cause is in `jmunch_mcp/proxy.py`: `Proxy.run()` spawns the upstream child but never explicitly terminates it on any exit path (only cancels its own asyncio tasks). Killed both orphans (`taskkill /F`). Documented in `LEARNINGS.md` under `operations` so the next "Connection closed" gets diagnosed, not just worked around — this is a `jmunch-mcp` bug (not ours to fix in this repo), but checking for and killing the orphan is a real, repeatable recovery step.

### 2026-08-10 10:00 PM CDT — TestSprite backend onboarding finished: 6 tests written, registered, and passing live (6/6)

Earlier attempts this evening left 0 actual tests registered with TestSprite despite claims of "4 written" — turned out those were never persisted anywhere retrievable (not on disk, not in TestSprite via `testsprite test list`). Rewrote all 6 planned smoke tests fresh in `backend/testsprite_tests/`, each with assertions read directly from the real handler code in `main.py`/`telemetry.py` (response shapes, required/optional query params, which routes actually require `SCAN_API_KEY` and which don't — `/ignored` GET has no auth dependency, unlike `/ignore` POST/DELETE):

- `test_health.py` — `GET /health` → `{"status": "ok"}`
- `test_telemetry_summary.py` — `GET /telemetry/summary` → asserts the full real key set from `get_telemetry_summary()`
- `test_telemetry_repos.py` — `GET /telemetry/repos` → list shape from `get_repo_staleness()`
- `test_telemetry_events.py` — `GET /telemetry/events?limit=5` → list shape + limit respected
- `test_telemetry_active.py` — `GET /telemetry/active` → list shape from `get_active_scans()`
- `test_ignored_validation_error.py` — `GET /ignored` with no `repo_path` → asserts a real `422`, not guessed

**Verified twice, not once:** ran all 6 locally with plain `python` against the live Render backend first (6/6 passed) before spending any TestSprite credits, then registered all 6 via `testsprite test create --code-file` and ran the real batch via `testsprite test run --all --wait` — **6/6 passed for real** through TestSprite's own execution, not just local. Committed to the repo (`backend/testsprite_tests/`).

### 2026-08-10 9:45 PM CDT — SCAN_API_KEY generated and wired end-to-end (local, Render, TestSprite), for the TestSprite onboarding blocked on it since earlier tonight

The 4 TestSprite smoke tests written earlier tonight (`/health`, `/telemetry/summary`, `/telemetry/repos`, `/telemetry/events`) don't need auth, but the remaining write-endpoint tests (`/telemetry/active`, `/ignored`, and any real scan-trigger test) do — they were blocked on `SCAN_API_KEY` not existing anywhere yet. Generated a random 64-char hex value (`secrets.token_hex(32)`) and wired it into all three places that need to agree on it:

1. **`backend/.env`** — added directly. Note: `main.py` loads this via `load_dotenv`, and `require_scan_key`'s own docstring says the key is meant to be *unset* locally so CLI/local-dev scans stay frictionless — adding it here means local scans now also require the `X-API-Key` header. Deliberate tradeoff for this session (consistent value across environments), flagged in case future local dev friction traces back to this.
2. **Render (`vuln-hunter-backend`, `srv-d9q4o1ss728c739191pg`)** — set via direct Render REST API call (`PUT /v1/services/{id}/env-vars/SCAN_API_KEY`), not the `render` CLI (no env-var subcommand exists in CLI v2.22.0, checked directly) and not the `render` MCP server (still fails with the known DCR OAuth incompatibility, see `project-render-mcp-dcr-auth-failure` memory). **Important finding:** the env-var API call does NOT auto-trigger a redeploy — the docs don't say so either way, and empirically the running instance kept 401-ing on the correct key until an explicit `render deploys create` was run. Anyone editing Render env vars via the API (not the dashboard UI) needs to trigger a deploy separately or the change is inert.
3. **TestSprite** (`vuln-hunter backend` project, `a7c88561-77d7-4d63-a734-f100893cf3a9`) — set as the project's backend test credential via `testsprite project credential --type "API key"`. TestSprite's own docs don't document which header name their "API key" credential type actually injects, so this was verified empirically rather than trusted from docs.

**Verified live, not just deployed:** direct `curl` against the hosted backend post-deploy — no key → real `401 Missing or invalid X-API-Key`; correct key → auth passes, request instead fails on body validation (`missing: scan_id`), confirming the key check itself is the thing that changed, not a coincidental pass.

### 2026-08-10 5:12 PM CDT — Triage/business-logic layer moved off Anthropic (out of credits) onto Groq; two real regressions caught and fixed by testing before ship; commit `b7a9d4a`, pushed and confirmed on origin/master

`ANTHROPIC_API_KEY` ran out of credits (same key exhaustion that hit job-hunter 2026-08-09), breaking both `triage.py` and `business_logic.py`. Swapped both from the `anthropic` SDK to Groq's free OpenAI-compatible endpoint (`llama-3.3-70b-versatile`) — a separate quota from job-hunter's NVIDIA NIM fix, chosen after independently verifying Groq's real free-tier limits (30 RPM / 1,000 RPD / 12K TPM, confirmed directly against Groq's docs after cross-checking multiple AI-brainstormer estimates, one of which overstated the daily limit by 14x) and finding a working `GROQ_API_KEY` already provisioned locally for the `/watch` skill's Whisper fallback — zero new signup needed.

**Real bug #1, caught by testing on a full cloned repo, not a synthetic example:** 5 concurrent triage workers blew through Groq's 12K TPM ceiling mid-scan (`openai.RateLimitError`), a limit Anthropic's plan never got close to at the same concurrency. Fixed with a shared `_call_with_retry` backoff helper (`triage.py`) and dropped `MAX_CONCURRENT_TRIAGE`/`MAX_CONCURRENT_REVIEWS` from 5 to 3. Reverified: two full re-scans of the same repo, clean both times.

**Real bug #2, caught by the project's own regression suite (`test_business_logic_manual.py`), not the ad hoc tests run first:** Llama 3.3 70B produced 2 false-positive findings on code that should return zero — traced to a genuine ambiguity in `business_logic.py`'s `SYSTEM_PROMPT`: rule 2 said to "say [uncertainty] explicitly," which Claude apparently read as "note internally, don't emit a finding" but Llama read literally as "output a finding that says you're uncertain." Rewrote rules 2-4 to make "uncertainty is never itself a finding" unambiguous regardless of which model is reading it. Reverified: regression suite passed 4/4 runs after the fix (including the true-positive IDOR case, so this didn't just suppress everything), plus two more full-repo re-scans stayed clean.

**Verification, not just one pass:** semgrep on the diff (0 findings), the project's real `test_business_logic_manual.py` and `test_pipeline_manual.py` suites, 4 full scans total of a real external repo (`ShenSeanChen/waku-agent`) across both bugs and both fixes.

### 2026-08-08 7:56 PM CDT — Local scans now phone home to the hosted dashboard, with live per-scanner progress; commit `308f0a2`, pushed and confirmed on origin/master

Closed the gap where local `scan_repo`/`scan_diff` calls (Claude Code MCP) wrote telemetry to a local-only SQLite file the hosted Operations Center dashboard could never see. `telemetry.py`'s `start_scan`/`report_progress`/`complete_scan` now mirror events to the deployed backend's new `POST /telemetry/ingest` (HTTPS-only, gated behind `SCAN_API_KEY`), and `all_scanners.run_full_scan` gained an `on_progress` callback so the dashboard can show real per-scanner progress (semgrep → gitleaks → pip-audit → trivy) via a new `GET /telemetry/active` endpoint and a live progress bar on the frontend, instead of only a 0/1 start/done state.

**Real bug caught by testing, not shipped:** the ingest handler reused the same telemetry write functions a normal scan calls — which themselves push remotely — so receiving a mirrored event re-triggered another push, forever. A 6-event local test produced 1200+ requests before this was caught. Fixed with a `_push: bool` flag threaded through all three write functions; the ingest handler is the one caller that sets it `False`. Reverified: the same 6-event test now produces exactly 6 requests, and a scan deliberately left mid-run showed real live progress (`2/4, gitleaks`) via `/telemetry/active`.

**Unrelated real bug found and fixed in the same pass**, while a `scan_diff` security-scan-on-this-diff was hanging: `get_changed_files` (scan_diff's only caller) was the one subprocess site in `scanner.py` that never got the `stdin=DEVNULL` fix already applied everywhere else for the Windows MCP-stdin-inheritance hang (see 2026-08-05 entry below). Confirmed via `diagnose_hang.ps1`'s thread trace showing the hang inside that exact function, fixed, reverified by re-running `scan_diff` successfully afterward.

**2 real findings from vuln-hunter's own scan of this diff, both fixed and reverified:** `TELEMETRY_REMOTE_URL` is now restricted to `https://` before use (closes a `file://` SSRF-style path through `urllib.request`; verified directly — an `https://` URL reaches `urlopen`, `http://` and `file://` both get rejected before it). The `ALTER TABLE` column-migration loop now uses a pre-built statement list instead of an f-string, removing the dynamic-SQL pattern semgrep flagged (values were always fixed literals, not user input, but the pattern itself is gone now).

**Not touched, deliberately:** 5 other findings from the same scan live in `vuln-hunter\vuln-hunter\backend\test_sample\vulnerable.py` — the stray nested duplicate-repo folder flagged in the 2026-08-06 entry below as "untracked, not touched." Those are intentional planted-vulnerability test fixtures, not real code, and not part of this change.

### 2026-08-06 — Dashboard gauges, live URL-scan box, and real deploy to Vercel + Render

Shipped the deploy from the previous session's staged plan, with real changes to the shape of it along the way.

**Dashboard (frontend):** Replaced flat success-rate/false-positive stat tiles with animated radial gauges (270° sweep, ascending color bands matching the existing tone logic). Added a "scan a repo" box — drop in a URL, it clones and runs a real scan live, with a real elapsed-time counter (not fake progress theater). Bolder header pass: brought the H1 up to the same uppercase/letter-spaced HUD convention the rest of the page already used (was the one place quietly opting out of it), added a live pulse indicator. Fixed a real mobile bug: header and gauge row weren't centering under 640px width (styled-jsx media query fix).

**Backend:** New `POST /scan/url` endpoint (clone → scan → cleanup, 120s clone timeout). All scan-triggering endpoints (`/scan`, `/scan/url`, `/scan/diff`, `/scan/sarif`, `/ignore`) now sit behind an optional `SCAN_API_KEY` check — unset locally so CLI/local use stays frictionless, enforced only when the hosted deploy sets it.

**Public/private split:** the public hosted site shows the scan box (visible, matches the portfolio "wow" goal) but it's genuinely gated — a Next.js server-side proxy route (`/api/scan-url`) holds the real `SCAN_API_KEY` and checks a separate `SCAN_BOX_PASSWORD`, so the real backend key never reaches the browser. Confirmed live: wrong/blank password → real 401 from the deployed site, not just a UI trick.

**Deploy — changed from the staged plan:** frontend on Vercel as planned (`https://frontend-beta-eight-46.vercel.app`, free tier). Backend moved from the originally-planned Fly.io to **Render** instead (`https://vuln-hunter-backend.onrender.com`, free tier) — Chris already had a Render account and wanted the free option over Fly.io's paid always-on pricing. Trade-off accepted knowingly: Render's free tier sleeps after ~15 min idle, cold-starts ~30-60s on the next request.

**Real bug found and fixed along the way:** `requirements.txt`'s `click>=8.3.3`/`rich>=13.7.0` pins (a verified-working CVE-fix override past what `semgrep`'s own metadata declares) make a single `pip install -r requirements.txt` unresolvable from a genuinely clean environment — confirmed live on the first Render build attempt (`ResolutionImpossible` across every semgrep version 1.90.0–1.124.0). Previously only ever worked because the local Windows venv was built incrementally, never resolved atomically from scratch. Fixed in `Dockerfile`: install semgrep alone first (its real dependency tree resolves fully and correctly with nothing else present to conflict), then the rest of `requirements.txt` on top. Confirmed live: second Render deploy succeeded, `/health` and `/telemetry/*` both verified working through the real public URL.

**Not done / found but not investigated:** a stray `vuln-hunter/vuln-hunter/` nested folder inside the repo root (its own `.git`, an old BUILDLOG dated 2026-07-09) — untracked, not touched, needs a look. `C:\Repos\vuln-hunter.zip` (301MB, dated 2026-07-22) confirmed stale/unused, safe to delete whenever. GitHub profile "watch it scan live" theatrical demo effect — explicitly deferred to a future session, not started.

### 2026-08-05 — Fixed the pip-audit self-scan crash and hang, added a plain CLI entrypoint

Closes the pip-audit item that's been sitting in Pending since the dashboard shipped: `pip-audit -r requirements.txt` crashed every time vuln-hunter scanned its own repo, and turned out to be **two separate real bugs**, both confirmed live, not just reasoned about.

**Bug 1 — the resolver crash.** `requirements.txt` deliberately pins `click>=8.3.3` and `mcp>=1.28.1` past what the pinned `semgrep==1.168.0` itself declares (`click~=8.1.8`, `mcp==1.23.3`) — a verified-working CVE-fix override from an earlier session, but one that makes a *fresh* `pip install -r` permanently unresolvable (`pip check` confirms the venv is already knowingly inconsistent this way). On Windows it's worse than a clean resolver error: pip backtracks through old semgrep versions hunting for a compatible combination, and any version below ~1.11x has no Windows wheel on PyPI, so its own legacy `setup.py` raises `Exception: Semgrep does not support Windows yet` instead of failing to build — which crashed `pip-audit` outright. Fix: `dep_scan.py` gained `_is_self_scan(repo_path)` — when the repo being scanned is the one this process is already running from, audit the *installed* environment directly (`pip-audit -f json`, no `-r`) instead of asking pip to re-resolve `requirements.txt` from scratch. Scanning any other repo is unchanged.

**Bug 2 — a 180s hang, found only after fixing bug 1.** With the resolver crash gone, the exact same fast command (`pip-audit -f json`, ~5s standalone) still hung the full 180s timeout every time it ran through the live MCP server, and only there — reproducible with instrumented logging showing the correct code path and correct command, just never returning. Root cause: the same class of bug already fixed for `semgrep` in `scanner.py` (see the `stdin=DEVNULL` comment there) — a subprocess spawned from `mcp_server.py` inherits the MCP server's own stdin (the JSON-RPC pipe to Claude Code) by default on Windows, and that pipe never sees EOF for the life of the session. `gitleaks.py` and `trivy_scan.py` had the identical gap (never got the fix that shipped for semgrep), fixed the same way in all three.

Verified live end-to-end after both fixes: reconnected the MCP server (confirmed via fresh PID/timestamp, not just "shows connected"), called the real `scan_repo` MCP tool against vuln-hunter's own repo — 8 findings, no crash, no timeout, matching the CLI's output exactly (see below). Also ran a full external-repo scan (`HKUDS/CLI-Anything`, ~1800 files) through the same fixed MCP path with no issues, confirming the non-self-scan branch is unaffected.

**New `backend/cli.py`:** a plain `argparse` entrypoint (`scan`/`diff` subcommands, JSON or plain-text out) calling the exact same `all_scanners.run_full_scan`/`run_diff_scan` functions `main.py` and `mcp_server.py` already call — a third thin adapter, not a fourth scanning implementation. Exists specifically so there's a way to run a scan with zero possibility of the stdin-inheritance bug class above: no persistent server, no pipe to inherit, every invocation is a fresh isolated process. Verified: `cli.py scan .` on vuln-hunter's own repo produces byte-identical findings to the MCP path.

Also added a `.gitignore` entry for `backend/vuln_hunter_telemetry.db` / `backend/vuln_hunter_events.jsonl` — runtime-generated by `telemetry.py`, were never meant to be committed, just hadn't been excluded yet.

### 2026-08-04 — Operations Center dashboard: scan telemetry, live crash capture, split-terminal TUI + web UI

Built after two straight nights of scan_repo/scan_diff failures with zero forensic trail (2026-08-04: a hang on `MonkeyCode`, then a full process crash on `openwork` with no stderr captured anywhere, since jmunch-mcp doesn't persist logs to disk). This closes that gap going forward.

New `backend/telemetry.py`: SQLite + append-only JSONL dual-write for every scan (JSONL survives a corrupted/locked DB or a mid-write process kill). Key design point: a **hung** or **crashed** scan can never self-report — the code that would call `complete_scan()` is exactly what stopped running — so `reconcile_stale()` infers HUNG vs. CRASHED reactively from scans still `RUNNING` past the 1800s MCP idle timeout, using whether `mcp_server.py` is still alive to tell the two apart.

Instrumented both scan paths that actually failed: `main.py`'s `/scan`+`/scan/diff` and `mcp_server.py`'s `scan_repo`+`scan_diff`, wrapping each in `start_scan`/`complete_scan`/`log_stopper_bug` with full tracebacks. `all_scanners.py` gained `FULL_SCAN_SCANNERS` and `diff_scanners_invoked()` so telemetry always knows which scanners a given scan actually ran (needed to distinguish "ran clean" from "never invoked" for the silent-zero-findings alert) without duplicating `run_diff_scan`'s own gitleaks/pip-audit/trivy conditions.

Two front ends, both reading the same telemetry: `backend/dashboard_tui.py` (Textual, for a split terminal pane) and `frontend/app/dashboard/page.tsx` (Next.js, dark ops-center theme per the `dataviz` skill's validated palette, framer-motion animation). Both show success/hung/crashed rate, duration p50/p90 (not just an average — that hides exactly the tail latency that creeps toward the 30-min timeout), per-scanner finding volumes with a silent-zero guard, severity breakdown, false-positive rate (derived from `ignore_store`'s per-repo ignore lists, not a separately-tracked field), MCP process count, and per-repo staleness.

Real bugs caught before shipping, not after: an earlier Gemini-generated draft of this same dashboard leaked a SQLite connection on every write (never closed, just committed), had a stored-XSS path (raw `innerHTML` built from scan-derived strings — repo names/paths are attacker-influenceable data, this tool scans third-party repos), bound the web server to `0.0.0.0` with no auth, and its "kill zombie MCP processes" hotkey killed every instance indiscriminately instead of just the extras (would have taken down an actively-scanning process along with real orphans). None of that shipped — this rebuild fixes all four by construction (React's default escaping instead of innerHTML, kept the newest PID, killed the rest; endpoints added to the existing `main.py`, which already documents why it's 127.0.0.1-only).

Verified live, not just unit-tested: ran a real scan against `vuln-hunter/backend` itself that hit a genuine pre-existing environment bug (pip-audit failing to build a wheel during dependency resolution on this Windows box) — telemetry correctly captured it as CRASHED with the full traceback, in `/telemetry/summary` and `/telemetry/events` both. A second real scan against `vuln-hunter/frontend` completed clean and populated real per-scanner counts (trivy: 14, including a live CVE-2026-64641 hit on the frontend's own `next` 16.2.6 — same version `npm audit` already flagged, now double-confirmed). Dashboard loaded in a real browser against this live data.

New deps: `psutil`, `textual`, `rich` (backend); `framer-motion` (frontend) — installed, `npm audit fix` run (fixed a `brace-expansion` DoS; the remaining 3 findings all require bumping Next.js 16.2.6→16.3.0, outside the pinned range, deliberately not force-applied as a side effect of this change).

### 2026-08-03/04 — trivy wired in, shared `all_scanners.py` fixes the root cause of the gitleaks/pip-audit gap, 2 more real CVEs found live

Root cause of the previous entry's gap, found by tracing history: `mcp_server.py` was created 2026-07-23; gitleaks + pip-audit landed in `main.py` the very next day, 2026-07-24, and were never mirrored into the just-created MCP file. Two files each independently listing "which scanners run" drifted apart with nothing forcing them back in sync — a structural problem, not a one-time oversight, and it would happen again the next time a scanner got added to only one side.

**Fix:** added `all_scanners.py` — one shared `run_full_scan(repo_path)` and `run_diff_scan(repo_path, changed_files, deep_review)`, both `main.py`'s REST routes and `mcp_server.py`'s MCP tools now call these instead of each keeping their own scanner list. `run_diff_scan` takes an already-resolved `changed_files` list rather than resolving it itself, since main.py (HTTP 400) and mcp_server.py (early-return before the stall-watchdog starts) want different things to happen on a bad `base_ref` — that's caller-specific, not part of "which scanners run."

**Added `trivy_scan.py`** (mirrors `dep_scan.py`'s pattern exactly — deterministic, skips `triage.py`) wrapping Aqua Security's `trivy` for every dependency ecosystem `pip-audit` can't see: Rust/Cargo, npm/yarn, Go, Ruby, Java, and more. Verified live against `delta`'s real `Cargo.lock` (5 real advisories found, including a `git2` undefined-behavior bug) before wiring it in — confirms it's not Python-only despite the video that originally suggested it only being framed around a Python use case.

**Live end-to-end proof, not just "the code looks right":** called the real (patched) `mcp_server.scan_repo` against vuln-hunter's own backend. Result: 7 findings, including **2 `pip-audit` findings that had never appeared through the MCP path before** — `click` 8.1.8 (PYSEC-2026-2132) and `protobuf` 4.25.9 (PYSEC-2026-1805), both HIGH, both real, both missed by every prior `scan_repo`/`scan_diff` call ever run through Claude Code, because the scanner that would have caught them wasn't wired in until this session. Fixed both (`click>=8.3.3`, `protobuf>=5.29.6,<7`) alongside the 4 from the previous entry.

**Real conflict found fixing protobuf, not just click/mcp again:** `protobuf>=5.29.6` alone resolved to 7.35.1, which breaks `opentelemetry-proto`'s own `<7.0` requirement — a genuine upper-bound violation, not just a soft mismatch like the `semgrep==mcp==1.23.3`/`click~=8.1.8` pins. Tightened to `protobuf>=5.29.6,<7`, resolved to 6.33.6 (still within the CVE's fixed-version range, compatible with opentelemetry-proto). semgrep's own `click`/`mcp` pins were checked and confirmed non-blocking again (`semgrep --version` + a real 47-rule scan both still succeed) — semgrep evidently doesn't exercise whatever feature those pins are actually for.

**Verified:** trivy re-scan shows 0 vulnerabilities. All 9 manual regression tests pass, including `test_event_loop_not_blocked_manual.py`, which needed a real fix (not just a re-run) — it mocked `mcp_server.run_scan`/`triage_all` directly, which no longer exist there post-refactor; repointed it to mock `all_scanners.run_full_scan` instead, confirmed it still proves the event loop doesn't block (17 ticks during a simulated 1s scan).

**README updated** to document gitleaks/dep_scan/trivy/all_scanners, which had never been mentioned there at all — confirmed via grep before writing anything, not assumed. Install instructions for gitleaks/trivy corrected mid-edit after checking how gitleaks is *actually* installed on this machine (WinGet, not `go install` as first assumed) rather than guessing.

### 2026-08-03 — 4 real CVEs in own dependencies, found via trivy evaluation

While evaluating trivy as a potential new scan mode (see next entry), ran it against vuln-hunter's own actual installed dependencies (pip freeze, not the loose `>=` ranges in `requirements.txt`) and found **4 real, published, HIGH-severity CVEs**: `cryptography` 49.0.0 (CVE-2026-69247, Bleichenbacher-oracle decryption flaw) and `mcp` 1.23.3 — three CVEs (CVE-2026-52869: HTTP transports serving session requests without auth verification; CVE-2026-52870: experimental task handlers over-exposing access; CVE-2026-59950: WebSocket transport missing Host/Origin validation).

**Fix:** bumped `requirements.txt` to `mcp>=1.28.1,<2` and `cryptography>=50.0.0`, installed in the venv. The `<2` upper bound on `mcp` is deliberate — the same session found the `mcp` PyPI package jumped to a breaking `2.0.0` release that removes `mcp.server.fastmcp` entirely (hit this exact break wiring up a different project's MCP server the same night), and `mcp_server.py` here imports exactly that module.

**Real conflict found and resolved during the fix:** `semgrep` 1.168.0 pins `mcp==1.23.3` as its own dependency — the exact vulnerable version. pip installed 1.29.0 anyway (a warning, not a hard block). Verified this doesn't actually break anything: `semgrep --version` and a real scan both still work, and `mcp.server.fastmcp` imports fine at 1.29.0. semgrep's pin is almost certainly for an optional/unused-by-us MCP feature of its own, not something our subprocess-based `semgrep scan` usage touches.

**Verified:** trivy re-scan shows 0 vulnerabilities post-upgrade. All 8 manual regression tests pass (`test_diff_scan_manual.py`, `test_event_loop_not_blocked_manual.py`, `test_exclude_dirs_manual.py`, `test_ignore_manual.py`, `test_never_read_manual.py`, `test_sarif_manual.py`, `test_business_logic_manual.py`, `test_pipeline_manual.py` — the last one exercises the full pipeline including a real live Claude API triage call, exit code 0).

### 2026-08-03 — External hang diagnostics: `diagnose_hang.ps1` (py-spy, run from outside the process)

`scan_diff` failed a third distinct way tonight — not a visible hang, not "Connection closed," but total silence for the full 1800s idle timeout with zero response or progress. The existing `_stall_watchdog` (faulthandler-based, added 2026-07-27/28) only covers code running inside the `with`-block it wraps in `mcp_server.py` — it can't produce a dump for a hang in a phase it never reaches, or if its stderr output isn't being captured/surfaced back to the caller.

Added `backend/diagnose_hang.ps1`: finds the running `mcp_server.py` python.exe process(es) via `Get-CimInstance Win32_Process` (same pattern already used in this changelog to verify process freshness against fix commits) and attaches `py-spy dump --pid <PID>` to each from *outside* the process, printing every thread's live stack.

**Deliberately not an MCP tool on vuln-hunter's own server.** If vuln-hunter's process is the thing that's frozen, it can't answer any tool call at all, including a self-diagnostic one hosted on the same server — this has to run externally. Considered and rejected wiring py-spy in as a `diagnose_hang` MCP tool for this reason.

**Verified live, not just constructed:** ran it against the actually-running server tonight. Found **two** `mcp_server.py` python.exe processes running simultaneously, same start second. py-spy successfully dumped one (idle, event loop waiting on `asyncio.windows_events`, worker threads idle on a queue — process at rest, as expected for a non-hung state). **py-spy failed to read the other** ("Failed to find python version from target process"). Given this exact investigation thread has hit the "the live process was stale/predates the fix" trap at least three times before (2026-07-27, 2026-07-28, 2026-07-29 entries below), a second, unreadable process sitting alongside the working one is a real lead worth checking next time `scan_diff` hangs — not yet root-caused, just flagged.

**Next time `scan_diff` hangs:** run `powershell -File C:\Repos\vuln-hunter\backend\diagnose_hang.ps1` from an admin-capable shell immediately, before killing/restarting anything. py-spy needs to read the process while it's still stuck to be useful.

### 2026-07-30 — MCP `scan_repo` hang: live-verified fixed, real process-freshness proof this time

Ran `scan_repo` against `affaan-m/ECC` (the same repo that hung the full 1800s two sessions ago) with a **confirmed-fresh MCP server process** — checked `Get-CimInstance Win32_Process` creation timestamps for both `mcp_server.py` PIDs (11:29:56 AM 2026-07-30) against the last fix commit `438feab` (6:45:57 PM 2026-07-29): process postdates the fix, so this is a real test, not the "assumed fixed, never confirmed" trap from the prior two sessions.

**Result: completed successfully, no hang.** Returned 25 findings — the exact same count and rule set already triaged as false positives via the direct-semgrep workaround on 2026-07-29 (safe `spawnSync`-with-array-args patterns, two `dynamic-urllib-use` findings on internal/allowlisted URLs). Tool moved the call to background after 120s (real scan time on a repo this size, not a freeze — no progress stall, no idle-timeout kill).

This closes the 4th-fix-attempt thread from 2026-07-29 late night. Root cause (FastMCP blocking the event loop on sync tool calls) was correctly diagnosed; the async/anyio conversion (`438feab`) was the actual fix, live-confirmed above. The `scanner.py` manual Popen/thread pipe-draining diagnostic from the same night was built on a disproven theory (a pipe-buffer deadlock inside `subprocess.run`, which `Popen.communicate()` already prevents) and was reverted 2026-07-30 rather than committed — only `stdin=subprocess.DEVNULL` was kept, since it fixes a real, independent concern. Marked resolved in memory (`vuln-hunter-mcp-scan-repo-still-hangs`).

### 2026-07-29 — Real root cause of the recurring MCP hang: FastMCP blocks the event loop on sync tools

Third documented occurrence of `scan_repo` hanging with zero response/progress until Claude Code's own idle-timeout killed it ("sent no response or progress for 1800s") — this time on `last30days-skill`, a 421-file repo, not unusually large. Prior fixes (semgrep timeout bump, EXCLUDE_DIRS reaching semgrep) were both real but didn't address this.

**Root cause, confirmed by reading the installed `mcp` SDK's own source** (`mcp/server/fastmcp/utilities/func_metadata.py:92-95`): FastMCP calls synchronous tool functions *directly inline* on the server's single asyncio event loop — it does not thread-offload them. `scan_repo`/`scan_diff` were plain `def`, not `async def`. While `run_scan()`'s `subprocess.run()` and `triage_all()`'s `ThreadPoolExecutor.map()` were running, the entire event loop was frozen — the server could not send or receive *any* protocol traffic, including a heartbeat, for the whole duration. That's a structural guarantee of a client-side idle-timeout eventually firing, independent of how long the real work takes or what vuln-hunter's own internal timeouts are set to.

**Fix:** converted both tools to `async def` with a `Context` parameter; the actual blocking calls (`run_scan`, `triage_all`, `get_changed_files`, `business_logic.review_files`) now run via `anyio.to_thread.run_sync(...)`, keeping the event loop free. Added `ctx.report_progress()` calls at each stage boundary (semgrep start, triage start, done) — a no-op if the client didn't request progress tracking, but the correct mechanism if it did.

**Verified:** added `test_event_loop_not_blocked_manual.py` — mocks the blocking calls with real `time.sleep()`, runs a concurrent asyncio heartbeat task, asserts the event loop kept ticking throughout (17 ticks during a 1s simulated scan; a blocked loop would show 0-1). All existing manual tests (`test_exclude_dirs_manual.py`, `test_never_read_manual.py`, `test_diff_scan_manual.py`, `test_resolve_repo_dir.py`) still pass. Semgrep security scan of the diff itself: 0 findings.

**Not yet verified:** same gap as every prior fix in this thread — the live MCP server process needs a restart to pick up the new code. Standalone-Python-level proof is solid; the actual `scan_repo`/`scan_diff` tool calls through Claude Code haven't been re-run against a real repo since this landed. Do that before calling this thread closed.

### 2026-07-28 — Real (likely primary) cause of the semgrep-phase hang: EXCLUDE_DIRS never reached semgrep

`EXCLUDE_DIRS` (node_modules, .venv, venv, dist, build, __pycache__, .git) was defined and used by `_is_never_read()` to filter findings *after* a scan completed, but `run_scan()`'s actual semgrep command only ever passed `--exclude` for `NEVER_READ_PATTERNS` (credential-pattern files) — never for these directories. So every scan fully crawled node_modules/.venv/etc. on every run. This is the likely real (or at least major contributing) cause of the "near-zero CPU, no progress" hang found live on kungfu-systems/kungfu (2026-07-27), worked around that session by manually excluding its generated-artifact dirs (`.buildchain`, `.kungfu`, `.xinfa`) via direct semgrep flags — never root-caused until now.

**Fix:** loop `EXCLUDE_DIRS` into `--exclude` flags alongside `NEVER_READ_PATTERNS` in `run_scan()`. One line added to an existing loop pattern.

**Verified live, not just constructed:** built a real temp dir with the same vulnerable file both at top level and duplicated inside `node_modules/vendor/` — before the fix semgrep found both, after the fix only the top-level file is found (confirmed via semgrep's own JSON output, not just post-filtered). Added `test_exclude_dirs_manual.py` as a permanent regression check; confirmed `test_diff_scan_manual.py` still passes. Committed (`197254e`), pushed.

Doesn't rule out kungfu's custom dirs (`.buildchain`/`.kungfu`/`.xinfa`) needing their own project-specific exclusion too — `EXCLUDE_DIRS` is a fixed generic list, not dynamic — but the standard vendor-dir case (the overwhelmingly common one) is now genuinely fixed.

**Caveat found same day:** ran the live `scan_diff` MCP tool against this exact commit (scanning vuln-hunter's own repo, which has a large `backend/venv`) as this session's security-quality-gate check — it hung and timed out after 30 minutes, the same symptom this fix targets. Root cause: the tool's MCP server subprocess was already warm/running *before* the scanner.py edit landed this session, and Python doesn't hot-reload an already-imported module — same "needs a restart to pick up the fix" gap documented on 2026-07-18/2026-07-25 for earlier scanner.py changes. Not evidence the fix is wrong (the standalone Python-level test above proves the logic works); it's evidence the live MCP tool specifically hasn't picked it up yet. **Still needs a real restart-and-rerun to confirm the live tool path is fixed, not just the underlying function.**

### 2026-07-27 — Real root cause of the still-unresolved hang: unbounded Anthropic client timeout

- **Bug:** the 2026-07-26 fix (below) bumped semgrep's own subprocess timeout, but `scan_repo` still hung live afterward against a trivial repo, even with a fresh MCP process (duplicate-child-process theory investigated and disproven same night). Root-caused this session: `triage.py`'s `triage_finding()` and `business_logic.py`'s `review_file()` both instantiate `anthropic.Anthropic(api_key=...)` with no explicit `timeout=`, so each inherits the SDK default — a 600s read timeout with 2 retries (confirmed directly: `Timeout(connect=5.0, read=600, write=600, pool=600)`, `max_retries=2` on SDK 0.116.0). Since `triage_all`/`review_files` both call `ThreadPoolExecutor.map()`, the whole `scan_repo`/`scan_diff` response blocks until *every* concurrent call finishes — one slow or stuck API call (network blip, transient overload) can silently stall the entire tool response for up to ~30 minutes. Indistinguishable from a hang from the caller's side.
- **Fix:** bounded both client instantiations to `timeout=60.0`. Worst case for one stuck call is now ~3 minutes (60s × up to 3 attempts with retries), not up to 30.
- **Verified:** instantiated both clients directly and confirmed `.timeout == 60.0` (down from the implicit 600s default) on both. Full live repro wasn't possible — the specific test repo (smart-job-cli) is no longer cloned locally — but the mechanism (SDK default timeout, blocking `pool.map`) was confirmed directly against the actual SDK, not inferred.
- Not yet committed/pushed as of this entry — see next commit.

### 2026-07-26 — Fix the hardcoded 300s scan_repo timeout on larger repos

- **Bug:** `scan_repo` (`backend/scanner.py:107`) hardcoded `subprocess.run(cmd, ..., timeout=300)` around the semgrep call, with no way to override it. Hit live tonight against `claw-code` (194k-star repo, large enough that a single-pass semgrep scan didn't finish in 300s) — the known workaround (call `semgrep.exe` directly via `run_in_background`) was already documented as a stopgap, this fixes the actual tool. Separately, semgrep's own internal per-rule timeout (`--timeout`, defaults to 5s, never set by `scanner.py`) was causing "fixpoint timeout" false-inconclusives on several files during taint analysis on the same repo.
- **Fix:** bumped the outer subprocess timeout to 1800s (30 min), and added an explicit `--timeout 30` flag to the semgrep invocation itself for the per-rule limit. Checked the full call chain (`main.py`, `mcp_server.py`) for any other wrapping timeout that would still cut the scan off early — there isn't one; `scanner.py`'s subprocess call was the single choke point.
- **Verified:** re-ran `scan_repo` against `claw-code` after the fix; previously failed at exactly 300s, now completed with the 8 previously-inconclusive files confirmed clean. Also confirmed via direct `semgrep.exe` runs against two smaller unrelated repos (smart-job-cli, the_silver_searcher) on 2026-07-26 — both completed in seconds with the same config.
- Committed and pushed 2026-07-26 — the live MCP server process needs a restart to actually pick this up (a same-named duplicate-process issue is being investigated separately, see below if resolved).

### 2026-07-09 — Fix the recurring "hang" (real bug: no concurrency, not an infinite loop)
- **Bug:** Chris reported `scan_diff` running for ~2 hours the previous day with no visible progress — this had come up twice before (mcp-observatory and apify-mcp-server sessions) as an unresolved "lockup," always deferred. Actually investigated this time instead of deferring again.
- **Root cause:** `triage.py`'s `triage_all` and `business_logic.py`'s `review_files` both processed items in a plain sequential loop — one Claude API call per finding/file, no concurrency, no cap, no progress reporting back through the MCP connection. On a scan with many findings or a `deep_review` pass over many changed files, this is pure serial API latency that can add up to hours with zero visibility. It wasn't stuck — it was making real but invisible one-at-a-time progress. (Claude Code's own cosmetic spinner words like "nesting" that Chris saw cycling are unrelated UI flavor text, not a vuln-hunter status signal.)
- **Fix:** both functions now use `concurrent.futures.ThreadPoolExecutor` with a bounded worker pool (`MAX_CONCURRENT_TRIAGE` / `MAX_CONCURRENT_REVIEWS`, both 5) instead of a plain `for` loop — same bounded-concurrency pattern applied to job-hunter's `_validate_urls` and its Go port earlier the same night. `pool.map` preserves result order.
- **Verified** with a mocked-latency test (no real API calls): 10 items at 0.3s simulated latency each completed in ~0.6s (concurrent) vs. the ~3.0s serial time would have taken, with results correctly order-preserved.

### 2026-07-05 — Backend core: scanner + triage, verified end to end

- **`backend/scanner.py`**: wraps `semgrep scan` as a subprocess (resolves the
  venv's `semgrep.exe` next to the running interpreter — plain `"semgrep"` isn't
  on PATH outside the venv). Parses JSON output into findings enriched with the
  real source snippet around each match (so triage is grounded in actual code,
  not just a rule ID).
- **`backend/rules/custom-python-security.yml`**: 3 custom rules written after
  discovering the public `p/security-audit` + `p/secrets` community packs miss
  common raw-Python (no-framework) patterns entirely — SQL injection via string
  concat/f-string into `cursor.execute()` (including the two-step "build query
  variable, then execute" idiom), shell injection via `os.system()` with
  concatenated input, and hardcoded secrets by variable-name heuristic. Verified
  against a planted 4-vulnerability sample file: 1 finding with community packs
  alone → 4/4 with custom rules added, 0 false positives on a matched clean
  (safe) version of the same file.
- **`backend/triage.py`**: Claude triage layer, system prompt explicitly
  constrains it to explain/rate/fix only the given finding, not hunt for new
  ones. **Real bug caught during testing**: Claude ignored "respond with only
  JSON" often enough to wrap responses in ` ```json ` fences, and the original
  parser had no fence-stripping — `json.loads()` failed silently into a
  fallback that dumped raw text into `explanation` and left `suggested_fix`
  empty. Fixed with defensive fence-stripping in `_parse_json_response()`.
  Verified after the fix: all 4 planted findings return clean, well-formed
  `explanation` / `exploitability` / `suggested_fix` fields.
- **`backend/test_pipeline_manual.py`**: end-to-end smoke test (scan → triage),
  not part of a formal test suite yet.

## Known limitations
- Only Python rules written/tested so far (community packs cover other
  languages but custom rules are Python-only)
- Semgrep's `p/security-audit` + `p/secrets` community packs require network
  access to fetch rule packs on first run
- No test suite yet (manual smoke test only)

### 2026-07-05 — FastAPI endpoint + Next.js dashboard, verified end to end

- **`backend/main.py`**: `POST /scan {repo_path}` -> triaged findings. **Real bug
  caught**: Pydantic `Finding` model declared `cwe`/`owasp` as `str | None`, but
  semgrep's community rule metadata returns these as *lists* (custom rules
  return strings) — request crashed with a validation error. Fixed by
  normalizing both to a joined string in `scanner.py` (`_as_string()`) rather
  than loosening the API contract to accept either shape.
- **`frontend/`**: Next.js 16 + Tailwind 4 dashboard (same stack as rag-system).
  Repo-path input, Scan button, findings list with exploitability-colored
  badges, expandable per-finding detail (real source snippet, explanation,
  markdown-rendered suggested fix, CWE/OWASP).
- **Hydration false-positive caught and fixed**: a browser extension injects
  `fdprocessedid` into the path `<input>` after SSR, tripping React's hydration
  mismatch check — same root cause as the Grammarly hydration warning fixed
  earlier in the Skinstric/rag-system layouts, not a real app bug. Fixed with
  `suppressHydrationWarning` directly on the input.
- **Verified fully working** via real HTTP (`curl /scan`) and a real browser:
  typed a path, clicked Scan, expanded a finding, confirmed the real source
  snippet + explanation + fix + CWE/OWASP all render correctly for the
  planted 4-vulnerability sample. (Browser's screenshot tool intermittently
  timed out mid-session — verified via `get_page_text` instead, which
  confirmed the page itself was rendering fine; the screenshot mechanism was
  the only thing stuck.)

**Status**: backend + frontend both run and are verified correct locally.
Not deployed, not on GitHub yet.

### 2026-07-05 — Never-read guarantee for credential files

Before pointing this at other real repos (job-hunter, rag-system, etc.), added
an explicit, defense-in-depth guarantee that sensitive files are never read —
not just relied on `.gitignore` being correct in the target repo, which isn't
a real guarantee (a `.env` could exist un-gitignored, or the target might not
even be a git repo).

- **`scanner.py`**: `NEVER_READ_PATTERNS` (`.env`, `.env.*`, `*.pem`, `*.key`,
  `*.pfx`, `*.p12`, `id_rsa`/`id_ed25519` (+ `.pub`), `credentials.json`,
  `secrets.json`/`.yml`/`.yaml`, `.npmrc`, `.git-credentials`, `known_hosts`).
  Enforced at **three layers**: (1) passed as `--exclude` flags to semgrep
  itself, so the file's content is never read into the analysis engine at
  all — confirmed via semgrep's own `paths.scanned` list, not just our
  results; (2) a defensive filter on returned findings in case anything
  slipped past layer 1; (3) the same check directly at the source-snippet
  read call site in `_enrich_with_source()`.
- **`test_never_read_manual.py`**: automated regression test — creates fake
  `.env`/`credentials.json`/`id_rsa` fixtures in a temp dir (not committed,
  so nothing secret-shaped ends up in git), scans it, asserts the real
  vulnerability is still caught while none of the sensitive files appear in
  any finding. Verified passing.

### 2026-07-05 — Closing the gap with commercial tools: SARIF, ignore-list, diff scanning, AI reasoning pass

Researched how this compares to Semgrep's own "Multimodal" (formerly Assistant), Snyk, GitHub Copilot Autofix, Corgea, and recent hybrid-SAST research (AGHAST, SAST-Genius, ZeroFalse). Core architecture call (rules for detection, AI for triage) matches how the market leader does it. Closed four concrete gaps identified from that research, all built and verified this session:

**1. SARIF 2.1.0 output** (`sarif.py`, `POST /scan/sarif`) — the industry-standard format GitHub's Security tab and most CI tooling consume. Maps Claude's contextual `exploitability` rating to SARIF's `level` (more meaningful than the scanner's generic ERROR/WARNING). **Rigorously validated, not just eyeballed**: fetched the real official schema (`schemastore.org/sarif-2.1.0.json` — the first URL tried, `raw.githubusercontent.com/oasis-tcs/...`, 404'd) and validated actual output against it with `jsonschema`. Automated regression test (`test_sarif_manual.py`) does the same live schema fetch + validation.

**2. Suppression/ignore mechanism** (`ignore_store.py`, `POST /ignore`, `DELETE /ignore/{fp}`, `GET /ignored`) — persistent per-repo `.vulnhunter-ignore.json`, content-based fingerprint (not line-number-based) so marking something safe survives unrelated edits. **Real bug caught during testing**: the first fingerprint design hashed the *padded display snippet* (3 lines of context before/after), so edits *near* — not even in — a finding could still change its fingerprint and silently un-ignore it. Fixed by fingerprinting only the exact matched code lines (new `matched_code` field, separate from the padded `snippet` used for display) and re-verified: 4/4 fingerprints now stable across a 6-line unrelated insertion, where 3/4 were stable and 1/4 broke before the fix. Frontend got a "Mark safe / ignore" button wired to the same API.

**3. Diff-only scanning** (`get_changed_files()`, `POST /scan/diff {repo_path, base_ref}`) — scans only files changed vs a ref instead of the whole repo every time, for practical CI/PR use. **Real bug caught during testing**: `git diff` alone only reports changes to already-tracked files — a brand-new, never-`git add`ed file is invisible to it by git's own design. First test run failed exactly this way. Fixed by unioning in `git ls-files --others --exclude-standard` (untracked files) alongside the diff. Verified: a full scan of vuln-hunter's own repo found 5 findings (including the committed `vulnerable.py` fixture); the diff-scan correctly found 0 when nothing had changed, then correctly found exactly 1 (and only 1) after introducing a real vulnerability via an uncommitted edit — proving it neither re-scans unchanged files nor misses new ones.

**4. Second AI reasoning pass for business-logic issues** (`business_logic.py`, wired into `/scan/diff` via `deep_review: bool`) — the most novel and highest false-positive-risk addition, mirroring where the research (AGHAST, Semgrep Multimodal) says the field is heading: a pass that reasons about *intent* (missing authorization/ownership checks) rather than matching syntax patterns, which is structurally invisible to rule-based scanning. Kept strictly separate and honestly labeled: every finding is tagged `finding_type: "ai_reasoning"` (vs `"rule_confirmed"` for everything from the Semgrep path), shown with a distinct "AI review" badge in the frontend, and the system prompt is built around "return `[]` if you can't ground a concern in a quote — do not manufacture findings." **Scoped to diff-scan only** (not whole-repo `/scan`) since it's a per-file Claude call and needs to stay cost-bounded, same reasoning as why diff-only scanning exists at all.

Verified with three real fixtures (`test_sample/business_logic/`), not just trusted: (1) `vulnerable_idor.py` — a delete/update handler with zero ownership check on a caller-supplied resource ID — correctly caught, 2/2 findings, high confidence, accurate reasoning. (2) `safe_with_ownership_check.py` — the *identical* function shapes but with a real ownership check added — correctly produced **zero** findings, proving it's reasoning about the actual check rather than pattern-matching function names. (3) `clean.py` (unrelated existing fixture) — zero findings, no manufactured noise.

**A real vulnerability this pass found in vuln-hunter's own code**: running it against this repo's own uncommitted changes flagged five well-reasoned, accurate concerns in `main.py` — no ownership check on `/ignore`/`/scan` endpoints accepting an arbitrary `repo_path`, the ignore-list leaking suppressed-finding info to any caller, `base_ref` passed unvalidated to `git diff`. None of these are rule-matchable patterns; all are true statements about the code as written. Checking *why* they'd matter surfaced a real, separate bug: **the server was bound to `host="0.0.0.0"`** (all network interfaces), not just localhost, meaning anyone else on the same network could have reached these unauthenticated endpoints and used them to scan arbitrary paths on the host or tamper with the ignore list. Fixed: defaults to `127.0.0.1` now (override via `API_HOST` env var), matching the "local-only, nothing leaves the machine" design intent stated everywhere else in this project. Verified via `Get-NetTCPConnection` that the port is actually bound to `127.0.0.1` only post-fix, not just trusting the code change.

**requirements.txt created** (never existed before this — was pip-installing ad hoc). Frontend rebuilt clean after all changes (`npm run build`).

### 2026-07-06 — MCP server layer, wired into Claude Code globally

- **`backend/mcp_server.py`**: exposes `scan_repo`, `scan_diff`, `ignore_finding`,
  `list_ignored` as MCP tools (same `FastMCP` pattern as `rag-system/mcp_server.py`),
  importing directly from `scanner.py`/`triage.py`/`business_logic.py`/`ignore_store.py`
  rather than going through the FastAPI HTTP layer. Mirrors the SonarQube-via-MCP
  demo (ByteMonk video, 2026-07-06 session) that inspired this.
- Registered globally in `~/.claude.json` `mcpServers` (available in every Claude
  Code session, not just this repo), alongside jcodemunch/jdocmunch/etc.
- **Verified end to end, not just imported**: ran `scan_repo` against the planted
  4-vulnerability fixture (`test_sample/vulnerable.py`) through real Anthropic API
  calls — found all 4 (shell injection, SQL injection, eval, hardcoded secret),
  each with a real triage explanation/fix. Also verified `ignore_finding` +
  `list_ignored` round-trip correctly, then cleaned up the test artifact
  (`.vulnhunter-ignore.json`) so it doesn't linger in `test_sample/`.
- `mcp` added to `requirements.txt` (was already present in the venv as a
  transitive dependency, now declared explicitly since it's directly used).

### 2026-07-23 — fixed the real "gets stuck" bug, commit bc1fce4

Chris reported vuln-hunter frequently "gets stuck" on real contribution scans.
Root-caused 3 genuine bugs in `scanner.py`, each reproduced live before and
after the fix (not just unit-tested):

1. **`get_changed_files` HEAD-diff trap** — defaulted to `git diff HEAD`,
   which only shows uncommitted work. A committed contribution (the normal
   edit→commit→test flow) leaves the tree clean, so this silently returned
   `[]` — looked exactly like the scanner did nothing. Fixed with a fallback
   to diffing `HEAD~1` when the tree is clean. Reproduced live against rtk's
   real committed VERSIONINFO fix (commit `6caf3bf`): old logic returns `[]`,
   new logic correctly finds the 4 real changed files and scans them.
2. **`_is_never_read` directory-exclusion gap** — only checked `path.name`
   against `NEVER_READ_PATTERNS`, so files inside `node_modules`/`.venv`/etc.
   were never excluded by directory, only by exact filename match. Added
   `EXCLUDE_DIRS` checked against `path.parts`.
3. **Unhandled 300s semgrep timeout** — `subprocess.run(cmd, ..., timeout=300)`
   had no `except subprocess.TimeoutExpired`, so a scan that ran long raised
   an unhandled exception indistinguishable from a hang. Now caught and
   re-raised as a clear `RuntimeError`.

Speed-verified at real scale (not just the planted fixture): herdr
(993 files) in 11.0s, a fresh `freeCodeCamp/freeCodeCamp` clone (19,443
files) in 72.5s, zero stalls — confirms the original "stuck" reports were
the silent-failure bug above, not a raw performance ceiling.

**Rejected a flawed "corrected scanner.py"** sourced from an earlier Gemini
second-opinion Google Doc: verified all 5 of its claimed bugs against the
real code before touching anything. 2 were genuinely real (match fixes #1/#2
above — independent confirmation they were worth fixing). But it repeated
the *exact* same semgrep exit-code mistake already debunked the night before
(real semgrep: exit 1 = findings, exit 2 = fatal error — the doc claimed the
reverse), and 2 described code/fixes that don't exist anywhere in the actual
file (fabricated). Only the 2 verified-real issues got fixed, hand-written
and hand-tested — did not apply the doc's rewrite wholesale.

Committed and pushed to `albatrossflyon-coder/vuln-hunter` master:
commit `bc1fce4`.

### 2026-07-24 — path-traversal fix on every repo_path endpoint, commit 27f3e83

A second Gemini review round (planning the next batch of additions — YARA,
Gitleaks, pip-audit/Trivy, Presidio) flagged that `main.py` never validated
`repo_path` before using it: every endpoint (`scan`, `scan/diff`,
`scan/sarif`, `ignore`, `unignore`, `list_ignored`) passed the raw request
string straight through to file I/O and subprocess calls.

Verified the gap was real by reading the code directly before fixing
anything — `_rule_based_findings` only did `Path(repo_path).exists()`, no
`.resolve()`, no directory check, no bounds check at all.

**Deviated from the suggested fix on purpose**: the suggestion was a single
allowed-root + `is_relative_to()` check, but vuln-hunter scans arbitrary
local repos by design (job-hunter, rag-system, this repo, etc. all live in
different places) — there's no single jail directory that fits without
breaking normal usage. Added `_resolve_repo_dir()` instead: canonicalize
with `.resolve()`, require `.is_dir()`, reject otherwise. Closes the real
gap (unvalidated raw strings) without inventing a root restriction that
doesn't match the tool's actual usage.

Checked `ignore_store._store_path` first to confirm resolving the path
wouldn't orphan existing `.vulnhunter-ignore.json` files — it writes
directly into the target directory, not keyed by the literal string, so
resolving is safe.

Added `test_resolve_repo_dir.py` — plain assert-based script (no pytest in
this project yet, didn't want to add it as a dependency for one function).
Covers: valid dir, traversal-segment normalization, nonexistent-path
rejection, file-vs-directory rejection. All pass. Confirmed the app still
loads all 11 routes cleanly post-refactor.

Also verified (before touching anything) that the "unbounded concurrent
LLM calls" item from the same review round is **already handled**:
`triage.py` (`MAX_CONCURRENT_TRIAGE = 5`) and `business_logic.py`
(`MAX_CONCURRENT_REVIEWS = 5`) both already bound their `ThreadPoolExecutor`
pools. A global cross-module cap is a reasonable future refinement, not an
open gap — left undone for now.

### 2026-07-24 — Gitleaks git-history secret scanning, commit 80418aa

First of the "New Capabilities" batch from the review round (YARA, Gitleaks,
pip-audit/Trivy, Presidio). Closes a real gap: `NEVER_READ_PATTERNS` in
`scanner.py` only guards the present working tree — a secret committed once
and later removed from the tree is still readable in git's object history
until purged. Not hypothetical: Universal-Brain's own history has a
live-looking Figma token that reached `origin/main` before anyone caught it.

`gitleaks.py` mirrors `scanner.py`'s shape (`run_gitleaks_scan(repo_path) ->
List[Dict]`), same Finding schema. Deterministic findings only — skips
`triage.py` entirely (no LLM call needed to explain "this is a hardcoded
secret"), same reasoning `business_logic.py` already uses for its own
findings. Tagged `finding_type="secret_leak"`.

Verified against the real binary (gitleaks v8.30.1, already installed on
this machine), not mocked:
- `--redact` confirmed to mask the secret inside gitleaks itself, before the
  JSON ever reaches this process — simpler and safer than app-level
  redaction after the fact.
- `--exit-code 0` override confirmed: findings are read from the report
  file, not the exit code, avoiding the same "does non-zero mean findings or
  a real error" ambiguity semgrep's exit codes caused a few days ago.
- Full integration-tested through `_finalize`/`ignore_store`: a gitleaks
  finding flows correctly through the fingerprint-based suppression system —
  marking it safe correctly filters it out on the next scan.

Wired into `/scan` and `/scan/sarif`. Deliberately **not** wired into
`/scan/diff` — "diff-only" doesn't map cleanly onto history scanning, since
an old secret from 5 commits back has nothing to do with what changed in the
current diff. Doing it properly needs gitleaks scoped to a commit range via
`--log-opts`; marked with a `ponytail:` comment as a follow-up, not silently
skipped.

**Real near-miss caught mid-build**: the first version of `test_gitleaks.py`
used a hardcoded fixture reusing a known-leaked token string from another
repo's history (the same Figma token above) — GitHub's push protection
correctly blocked the push before it ever reached the remote. Fixed by
generating the test fixture with `secrets.token_hex()` at runtime instead of
any fixed literal, confirmed it still triggers gitleaks' detection, then
amended the (never-pushed) commit before it went out. Self-scanned this
repo with gitleaks itself post-fix to confirm clean before pushing.

### 2026-07-24 — pip-audit dependency CVE scanning, commit 83439e7

Second of the "New Capabilities" batch. Scans `requirements.txt` against
PyPA's own `pip-audit` tool (PyPI Advisory DB + OSV) — a library-level CVE
exists even if your own code is flawless, and Semgrep never looks at
third-party dependencies at all. `dep_scan.py` mirrors `gitleaks.py`'s
shape, deterministic findings, skips `triage.py`.

**Named `dep_scan.py`, not `pip_audit.py`**: the obvious name collides with
the actual installed `pip_audit` PyPA package in this venv (needed to run
it as a subprocess). It happened to resolve correctly via local-directory
import precedence when tested in isolation, but that's fragile across
different invocation contexts — caught and renamed before wiring it into
`main.py`, not after something broke.

Verified against the real binary + live PyPI/OSV data (`urllib3==1.26.4`,
real long-patched CVEs), not mocked. Confirmed `pip-audit` has no
`--exit-code` override like `gitleaks` does — exit 1 means both "vulns
found" and "a real failure," so disambiguated by whether stdout parses as
valid JSON instead.

**Real bug the integration test caught, not assumed away**: `pip-audit`
genuinely double-reports some advisories — `PYSEC-2021-108` came back twice
for the exact same fixture, once with a short description and once with
the full GHSA text (almost certainly OSV + PyPI sources both flagging the
same ID). First integration-test run caught this directly: ignoring one
finding suppressed *two* on rescan, not one. Fixed with per-vuln-id dedup
(keep whichever copy has the longer description); test now asserts no
duplicate `rule_id`s so it can't silently regress.

Wired into `/scan` and `/scan/sarif`. Also wired into `/scan/diff` — unlike
gitleaks, this genuinely is diff-scoped (only worth re-running when
`requirements.txt` itself changed), gated on that file being among the
changed files.

Added `pip-audit>=2.7.0` to `requirements.txt`.

## Pending

### Deploy — DONE 2026-08-06, see that changelog entry for full detail

Live at `https://frontend-beta-eight-46.vercel.app` (Vercel) + `https://vuln-hunter-backend.onrender.com` (Render, not Fly.io — changed mid-build, see changelog). API-key gate + password-gated public scan box shipped instead of the originally-planned allowlist-scope decision.

**Still genuinely open:**
1. **No rate limiting yet.** The password gate prevents casual public use, but if the password ever leaks there's still no per-IP/per-key cap on scan volume — real cost exposure (Anthropic API + compute) stays technically uncapped. Worth adding before this gets linked anywhere public-facing.
2. **Cost-tiering for the triage LLM never got built** — free tier still uses the same Claude call as everything else, since public access is gated rather than open. Only becomes relevant if the scope ever changes to open public access.
3. **Not linked from the GitHub profile/README yet** — deploy is live but not yet publicized.
4. GitHub profile "watch it scan live" theatrical demo effect — a separate, bigger piece, explicitly deferred by Chris, not started.

### Future: trufflehog as a verified-secrets pass alongside gitleaks — candidate only, not started

Discovered 2026-08-09 already installed on this machine (`C:\tools\trufflehog\trufflehog.exe`, v3.95.9) but never wired into vuln-hunter's scanner suite — confirmed via `all_scanners.py`, `FULL_SCAN_SCANNERS` only lists `["semgrep", "gitleaks", "pip-audit", "trivy"]`, no trufflehog reference anywhere in the codebase. Real, actively maintained (27k+ stars, pushed hours before this check), official trufflesecurity project.

**Why it's worth adding, not just a duplicate of gitleaks:** trufflehog's `--results=verified` mode actually tests a found credential against the real provider API (confirms an AWS key is genuinely live, returns account ID/ARN/user ID) rather than pattern-matching like gitleaks. Directly relevant to real friction hit twice today (2026-08-09, Octop and Anthropic-Cybersecurity-Skills evaluations): several gitleaks "high exploitability" secret findings turned out to be a documented public signing constant and JWT/AWS-key placeholder examples, each needing a manual file read to rule out. A verified-secrets pass would auto-resolve cases like those — confirmed-live escalates hard, unverified deprioritizes — cutting manual triage on every future scan's secret findings.

**Proposed shape, not decided:** complementary to gitleaks, not a replacement — gitleaks still catches broad patterns trufflehog might miss; trufflehog's verification becomes an automatic triage layer on top of gitleaks' hits, not a separate full scanner pass.

### Future: TOON-encode scan output — candidate only, not started, broader than just vuln-hunter

2026-08-09: `toon-format/toon` (MIT, 25k★, scan clean — zero findings) evaluated as a token-savings candidate for `claude-token-operator-kit`. It's a compact encoding of the **JSON data model** specifically — not a general text compressor, so it only applies where a pipeline already emits structured JSON, not free-form text (e.g. the repo-update-automation mailbox's raw CHANGELOG diffs get no benefit from it).

**Why vuln-hunter is the concrete first target, not the only one:** hard evidence from today — `scan_repo` returned 62,970 raw characters for Octop and 316,079 for Anthropic-Cybersecurity-Skills, both requiring the harness's auto-save-to-file fallback and a subagent delegation just to keep them out of context. That's vuln-hunter's own output format (`backend/mcp_server.py`, `backend/main.py`), fully ours to change.

**Broader scope, each needs individual wiring — not a blanket switch:**
- **vuln-hunter's scan output — ours, lowest-risk.** Read-only report data, no downstream consumer depends on the exact format. The clear first integration point.
- **job-hunter's `pipeline_log.jsonl`, career-ops's `remote_ratio_snapshots.json`/`source_progress.json` — ours, higher-risk.** These aren't just reporting output — job-hunter's own Python pipeline reads them back programmatically, so changing format touches real automation logic, not just a report layer. Separate piece of work, needs its own testing, don't conflate with the vuln-hunter change.
- **GitHub API, Supabase API, the harness's own oversized-response auto-save mechanism — NOT ours to wire.** These are external wire formats we don't control; TOON doesn't apply there. The only lever on that side is querying more narrowly, not re-encoding.

**Decision:** documenting now so it isn't lost, not implementing tonight — this is real engineering work (output-format change + verification that nothing downstream breaks) better suited to a dedicated session than tacked onto an already-long one. When it happens, start with vuln-hunter's scan output specifically, since it's ours, lowest-risk, and has hard numbers already proving the need.

### Future: scanner-stack architecture review (Zizmor/Checkov/Scorecard/Syft/OSV-Scanner) + finding-dedup layer — candidate only, not started

2026-08-09: ran a structured architecture-review brief (not a "what tools should we add" shopping-list ask) past two independent AI brainstormers, then verified every claimed tool against live GitHub metadata (license/stars/last-push) before trusting either summary. Findings below are what survived verification.

**Verified real, correctly licensed, actively maintained (all pushed within days of the check):**
- **Zizmor** (`woodruffw/zizmor`, MIT, 5,998★) — GitHub Actions workflow security: dangerous permissions, credential persistence, template injection, suspicious refs. Genuinely new territory — none of the current four scanners look at `.github/workflows/` at all.
- **Checkov** (`bridgecrewio/checkov`, Apache-2.0, 8,922★) — IaC/cloud config scanner (Terraform, K8s, CloudFormation, Dockerfiles). Same story: genuinely new coverage, zero overlap with semgrep/gitleaks/pip-audit/trivy.
- **OpenSSF Scorecard** (`ossf/scorecard`, Apache-2.0, 5,624★) — repo security-posture scoring (branch protection, review requirements, CI practices), not a traditional vuln scanner. **Caveat neither brainstormer stated clearly:** most checks query the GitHub API directly (needs a `GITHUB_TOKEN`), so it's not purely local the way semgrep/gitleaks are — fine given vuln-hunter always scans GitHub-hosted repos, but worth knowing before assuming it's a drop-in local scanner.
- **Syft** (`anchore/syft`, Apache-2.0, 9,367★) — SBOM generation (CycloneDX/SPDX). Pure inventory, no false-positive risk, useful groundwork even before any dedup layer exists.
- **OSV-Scanner** (`google/osv-scanner`, Apache-2.0, 10,792★) — both brainstormers independently landed on "benchmark against Trivy/pip-audit before adding, don't blindly stack it on" — that's a real signal worth trusting since it wasn't prompted.
- **OWASP ZAP** — correctly scoped by both as a future-phase DAST addition, not part of the base repo scan (needs a live running target, same authorization boundary as the dalfox candidate above).

**License note:** ShellCheck and Hadolint (mentioned by the second brainstormer) are both **GPL-3.0**, not MIT/Apache like the rest of this list. Still fine to shell out to as an external subprocess, but a different license category worth tracking if vuln-hunter's own docs ever need to account for what it bundles vs. invokes.

**Correction, same day: the "Muninn" claim below was wrongly flagged as fabricated — it's real.** The first brainstormer cited "Muninn," an existing open-source stack combining Gitleaks+Semgrep+Zizmor+actionlint+poutine+OSV-Scanner+Trivy+Checkov with cross-scanner dedup, as external validation. Initial broad `gh search repos "muninn"` came back with only unrelated noise, wrongly read as "doesn't exist." Re-verified via direct `gh api repos/SkaldLab/Muninn` (exact path, not search) and its actual README: real project, matches the citation exactly — all 8 scanners, cross-scanner dedup by advisory ID, GitHub Action with SARIF/JSON/PR-comment output, AGPL v3, actively maintained. The brainstormer's "Muninn" citation was valid prior art after all — the Zizmor/Checkov/dedup-layer recommendations were independently well-founded either way, but this specific citation should be treated as confirmed real, not disputed.

**The priority call, not just another scanner:** cross-scanner finding correlation/deduplication matters more than adding tools. Hit this exact friction twice on 2026-08-09 (Octop and Anthropic-Cybersecurity-Skills scans both needed manual triage to rule out false-positive secret findings). A dedup/aggregation layer makes every existing scanner more useful; another scanner without one just means more noise to manually sort.

**Nothing decided or built.** Chris's explicit instruction: bring recommendations back for comparison, don't implement yet.

### Future: dalfox as an optional DAST scan mode — candidate only, not started

Cloned `hahwul/dalfox` to `C:\Repos\dalfox` (2026-08-08) as a real candidate for a future capability, not a decision to build it. Dalfox is a DAST XSS scanner (Rust, official releases, real project) — sends actual test payloads at a *live* URL and checks for reflected/stored/DOM-based XSS. Fundamentally different from everything vuln-hunter currently does: Semgrep/gitleaks/pip-audit/trivy are all static (read source, no running app needed); dalfox needs a live target and is the one class of bug (context-dependent runtime XSS) static analysis structurally can't reliably catch. The idea, if pursued: an optional dynamic-scan mode for any live URL vuln-hunter is given, alongside the existing static scanners — SAST+DAST together is a materially stronger security-tool story than SAST alone. Real caution that isn't hypothetical: DAST sends actual exploit-attempt payloads, so it's only ever appropriate against Chris's own sites or something explicitly authorized — same boundary vuln-hunter's static scanners don't need to worry about but this would.

### Dashboard: repo names + per-repo findings — deferred 2026-08-08, not started

Chris flagged live, using the real dashboard against real scans (dalfox, testsprite-cli, brainoutside): two real usability gaps, explicitly deferred to a future session, not tonight.

1. **Repo staleness shows meaningless temp paths.** `main.py`'s `/scan/url` clones to `tempfile.mkdtemp(prefix="vuln-hunter-scan-")` and records *that* as the repo identity in telemetry — `/tmp/vuln-hunter-scan-xqr4dar1` instead of `github.com/hahwul/dalfox`, even though the handler has the real URL right there. Small, real fix: pass the actual URL through to `telemetry.start_scan` instead of the temp path.
2. **Findings are only ever shown as a global 24h rolling aggregate** (the gauges, the scanner bar chart) — there's no way to see "what did dalfox specifically find" separate from every other repo scanned that day. Bigger, real feature: a per-scan/per-repo findings view, not just a global rollup. Needs a new endpoint (findings scoped to one `scan_id`) plus UI to select/view it.

### Other pending
- [ ] `mcp_process_count` read 2 live during dashboard testing (2026-08-04) — corroborates the unconfirmed "6 simultaneous processes" lead from the same night's earlier crash investigation; now has a real-time indicator instead of a one-off observation
- [ ] Frontend: bump Next.js 16.2.6→16.3.0 to clear 3 high-severity `npm audit` findings (next/postcss/sharp) — deliberately not force-applied alongside the dashboard's `framer-motion` addition, needs its own review since it's outside the currently pinned range
- [ ] Wire the dashboard's telemetry into `scan_diff`'s `deep_review` path too if that ever gets frontend UI (currently only `run_full_scan`/`run_diff_scan` are instrumented, matching what actually calls them)
- [ ] Extend custom rules beyond Python (JS/TS at minimum, given the frontend-dev angle)
- [ ] Wire `deep_review` into the frontend (currently API-only; diff-scan itself has no frontend UI yet either — dashboard only calls whole-repo `/scan`)
- [ ] Decide whether to merge ponytail-style code cleanup into vuln-hunter for a sellable product — recommended AGAINST a single merged tool (security detection and cleanup are different judgment calls); a two-product/two-mode suite is the likelier path if pursued
