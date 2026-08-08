<p align="center">
  <img src="assets/banner.png" alt="vuln-hunter" width="100%"/>
</p>
<p align="center"><sub>Golden Eagle photo: <a href="https://commons.wikimedia.org/wiki/File:Golden_Eagle_in_flight_-_5.jpg">Tony Hisgett</a>, CC BY 2.0</sub></p>

AI-assisted security code reviewer, built on a hybrid architecture: **Semgrep does detection, Claude does triage.** Claude never invents a finding Semgrep didn't already flag.

## Live Demo

- **[Scan a public repo](https://frontend-beta-eight-46.vercel.app)** — password-gated, drop in a GitHub URL
- **[Operations Center dashboard](https://frontend-beta-eight-46.vercel.app/dashboard)** — live scan telemetry, gauges, event log

---

## Why hybrid, not pure-LLM

Asking an LLM to freely hunt for vulnerabilities produces too many false positives and false negatives to be credible — that's the classic failure mode of "AI security tools." vuln-hunter splits the job instead:

- **Semgrep** (a real, widely-used static analysis engine) does detection against known rule patterns — the ground truth.
- **Claude** is strictly downstream of that: it explains *why* a matched finding is risky in context, rates exploitability, and suggests a concrete fix. It does not go looking for problems Semgrep didn't already surface.

The one deliberate exception is the **business-logic reasoning pass** (below) — and even that is kept honestly separate and clearly labeled, never mixed in with rule-confirmed findings.

---

## What's Included

### Detection — `scanner.py`
Wraps `semgrep scan`, enriches every finding with the real source snippet around the match. Community rule packs (`p/security-audit`, `p/secrets`) alone missed common raw-Python patterns entirely — three custom rules (`rules/custom-python-security.yml`) close that gap: SQL injection via string concatenation into `cursor.execute()`, shell injection via `os.system()`, and hardcoded secrets by variable-name heuristic. Verified against a planted 4-vulnerability fixture: 1/4 caught with community packs alone → 4/4 with custom rules, 0 false positives on a matched clean file.

### Triage — `triage.py`
Claude explains, rates exploitability, and suggests a fix for each finding Semgrep already flagged — system-prompt-constrained so it can't wander off and invent new ones.

### Business-logic reasoning pass — `business_logic.py`
The most novel piece: a second Claude pass that reasons about *intent* — missing authorization/ownership checks, the kind of bug that's structurally invisible to pattern-matching. Every finding from this pass is tagged `finding_type: "ai_reasoning"` (vs `"rule_confirmed"` from the Semgrep path) and shown with a distinct badge in the frontend — never silently blended in. Verified against three fixtures: a real IDOR bug with zero ownership check (caught, 2/2, high confidence), the identical function shape *with* a real ownership check added (correctly zero findings — proof it's reasoning about the actual check, not the function name), and an unrelated clean fixture (zero manufactured noise).

**This pass found a real bug in vuln-hunter's own code**: no ownership check on the `/ignore` and `/scan` endpoints, plus the ignore-list leaking suppressed-finding info to any caller. Investigating *why* that mattered surfaced a separate, more serious issue — **the server was bound to `0.0.0.0`** (every network interface) instead of localhost, meaning anyone on the same network could have reached those unauthenticated endpoints. Fixed: defaults to `127.0.0.1` now, override via `API_HOST`.

### Git-history secret scanning — `gitleaks.py`
Wraps gitleaks to catch secrets committed at any point in history, not just the current working tree — `NEVER_READ_PATTERNS` in `scanner.py` only guards the present checkout, so a key committed once and later "removed" is still exposed in every clone. `--redact` confirmed to mask the secret inside gitleaks itself, before the finding is even built. Whole-repo scans only (`scan_repo`, not `scan_diff` — see Known Limitations).

### Dependency CVE scanning — `dep_scan.py` (Python) + `trivy_scan.py` (everything else)
Semgrep sees the code you wrote; these see the code you imported. `dep_scan.py` wraps PyPA's own `pip-audit` against `requirements.txt` (PyPI Advisory DB + OSV). `trivy_scan.py` wraps Aqua Security's `trivy` for every other ecosystem a real target repo actually uses — Rust/Cargo, npm/yarn, Go modules, Ruby, Java, and more — plus it independently double-checks Python too. Both are deterministic (a known CVE with a known fix version doesn't need an LLM to explain it) so neither goes through `triage.py`. On `scan_diff`, both only re-run when a lockfile they actually read is among the changed files.

### MCP server — `mcp_server.py`
Exposes `scan_repo`, `scan_diff`, `ignore_finding`, and `list_ignored` as MCP tools, registered globally so any Claude Code session can call them directly — not just this repo. Verified end to end with real Anthropic API calls against a planted vulnerability fixture, not just imported and assumed working.

Both this and the REST API below call one shared function (`all_scanners.py`) to decide which scanners actually run, rather than each maintaining its own list — gitleaks and pip-audit were added to the REST API on 2026-07-24, one day after this MCP server was first created, and never got mirrored over here until 2026-08-03. `all_scanners.py` exists specifically so that class of drift can't happen again: a new scanner only ever needs adding in one place.

### SARIF 2.1.0 output
The format GitHub's Security tab and most CI tooling consume. Output is validated against the real official schema (`schemastore.org/sarif-2.1.0.json`) with `jsonschema`, not eyeballed.

### Suppression / ignore list
Persistent per-repo `.vulnhunter-ignore.json`, fingerprinted on the exact matched code (not line numbers, not the padded display snippet) so marking a finding safe survives unrelated nearby edits.

### Diff-only scanning
Scans only files changed vs. a ref instead of the whole repo — practical for CI/PR use. Unions `git diff` with `git ls-files --others --exclude-standard` so brand-new, never-`git add`-ed files aren't invisible to it.

### Never-read guarantee for credentials
`.env`, `*.pem`, `*.key`, `id_rsa`, `credentials.json`, and similar are excluded at three layers — passed as `--exclude` to Semgrep itself (confirmed via Semgrep's own scanned-paths list, not just trusted), a defensive filter on returned findings, and again at the source-snippet read call site. Regression-tested with fake credential fixtures in a temp dir.

### Frontend
Next.js 16 + Tailwind 4 dashboard — repo-path input, scan button, findings list with exploitability-colored badges, expandable per-finding detail (source snippet, explanation, markdown-rendered fix, CWE/OWASP).

---

## Quick Start

```bash
# Backend
cd backend
pip install -r requirements.txt
python main.py          # binds to 127.0.0.1:8001 by default

# gitleaks and trivy are separate binaries, not pip packages, resolved via
# PATH -- install with whatever package manager you actually have. Examples:
#   gitleaks: winget install Gitleaks.Gitleaks   (or: brew install gitleaks)
#   trivy:    GOEXPERIMENT=jsonv2 go install github.com/aquasecurity/trivy/cmd/trivy@latest
# (trivy needs GOEXPERIMENT=jsonv2 as of this writing -- its latest release
# depends on Go's encoding/json/v2, which is still experimental. Both
# scanners degrade gracefully to "supplementary scan skipped" if their
# binary isn't found on PATH, so the rest of vuln-hunter still works
# without them.)

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

The API is local-only by default — it can scan arbitrary filesystem paths and has no authentication, so it must never be reachable from the network without adding auth first.

---

## Install for Claude Code

Once the backend dependencies above are installed, register it as an MCP server so any Claude Code session can call `scan_repo`, `scan_diff`, `ignore_finding`, and `list_ignored` directly, without you having to run the API separately:

```bash
claude mcp add vuln-hunter -- /path/to/vuln-hunter/backend/venv/Scripts/python.exe /path/to/vuln-hunter/backend/mcp_server.py
```

(On macOS/Linux, use `venv/bin/python` instead of `venv/Scripts/python.exe`.)

Then just ask Claude Code to scan a repo or a diff — it'll call the tool directly. To have Claude Code set this up for you from scratch (clone, install deps, register the MCP server), just tell it:

> "Clone https://github.com/albatrossflyon-coder/vuln-hunter, install its backend dependencies in a venv, and register it as an MCP server named vuln-hunter."

---

## Known Limitations

- `scan_diff` never runs the gitleaks history scan — a whole-git-history secret check doesn't map onto "just this diff" (an old secret from 5 commits back has nothing to do with what changed now); catching secrets introduced by the diff itself specifically would need gitleaks scoped to the commit range, not built yet
- Only Python has custom rules written/tested so far (community packs cover other languages, but with the same blind spots noted above)
- No formal test suite yet — manual smoke tests only (`test_*.py` in `backend/`)
- Not yet deployed anywhere — runs locally
- `deep_review` (the business-logic pass) is API-only right now; no frontend toggle for it yet, and the diff-scan endpoint has no dedicated UI either

---

## License

Not yet licensed — all rights reserved by default until a license is chosen.

## Author

Chris Brown  
[Albatross AI](https://albatrossai.online)  
[Portfolio](https://chrisbrown-dev.vercel.app)
