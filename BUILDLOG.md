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

## Pending
- [ ] Push to GitHub
- [ ] Consider an MCP server layer (same pattern as rag-system) if useful
- [ ] Deploy backend + frontend
- [ ] Extend custom rules beyond Python (JS/TS at minimum, given the frontend-dev angle)
