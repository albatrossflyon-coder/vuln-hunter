# Build Log — vuln-hunter

**Repo**: C:\Repos\vuln-hunter | github.com/albatrossflyon-coder/vuln-hunter (public)

AI-assisted security code reviewer. Hybrid architecture: real static analysis
(Semgrep) for ground-truth vulnerability detection, Claude for triage,
exploitability assessment, and fix suggestions.

**Rule: Update this file every time a file is added, changed, or a feature ships.**

---

## Why hybrid, not pure-LLM

Asking an LLM to freely hunt for vulnerabilities produces too many false
positives/negatives to be credible — that's the classic failure mode of "AI
security tools." Instead: Semgrep (a real, widely-used static analysis engine)
does detection against known rule patterns — that's the ground truth. Claude's
job is strictly downstream of that: explain *why* a specific matched finding is
risky in context, rate exploitability, and suggest a concrete fix. Claude never
invents a finding that Semgrep didn't already flag.

## Changelog

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

## Pending
- [ ] Push to GitHub
- [ ] Deploy backend + frontend (now safer to do, given the localhost-binding fix — but still needs real auth if ever exposed beyond localhost)
- [ ] Extend custom rules beyond Python (JS/TS at minimum, given the frontend-dev angle)
- [ ] Run against other real repos (job-hunter, rag-system, skinstric, etc.) now that the never-read guarantee is in place
- [ ] Add authentication before ever binding to anything beyond 127.0.0.1
- [ ] Wire `deep_review` into the frontend (currently API-only; diff-scan itself has no frontend UI yet either — dashboard only calls whole-repo `/scan`)
- [ ] Reconcile `backend/mcp_server.py` (untracked) and modified `requirements.txt` sitting in the working tree from a prior session — not yet committed or discarded
- [ ] Decide whether to merge ponytail-style code cleanup into vuln-hunter for a sellable product — recommended AGAINST a single merged tool (security detection and cleanup are different judgment calls); a two-product/two-mode suite is the likelier path if pursued
