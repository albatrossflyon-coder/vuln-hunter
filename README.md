<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:7F1D1D,100:DC2626&height=250&section=header&text=vuln-hunter&fontSize=75&fontColor=ffffff&animation=fadeIn&fontAlignY=35&desc=Real%20static%20analysis%20for%20detection%2C%20Claude%20for%20triage%20%E2%80%94%20never%20the%20reverse&descAlignY=58&descSize=18&descColor=ffffff" alt="vuln-hunter" width="100%"/>
</p>

AI-assisted security code reviewer, built on a hybrid architecture: **Semgrep does detection, Claude does triage.** Claude never invents a finding Semgrep didn't already flag.

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

### MCP server — `mcp_server.py`
Exposes `scan_repo`, `scan_diff`, `ignore_finding`, and `list_ignored` as MCP tools, registered globally so any Claude Code session can call them directly — not just this repo. Verified end to end with real Anthropic API calls against a planted vulnerability fixture, not just imported and assumed working.

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

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

The API is local-only by default — it can scan arbitrary filesystem paths and has no authentication, so it must never be reachable from the network without adding auth first.

---

## Known Limitations

- Only Python has custom rules written/tested so far (community packs cover other languages, but with the same blind spots noted above)
- No formal test suite yet — manual smoke tests only (`test_*.py` in `backend/`)
- Not yet deployed anywhere — runs locally
- `deep_review` (the business-logic pass) is API-only right now; no frontend toggle for it yet, and the diff-scan endpoint has no dedicated UI either

---

## License

Not yet licensed — all rights reserved by default until a license is chosen.
