# Backlog Scan — concrete, not-yet-done gaps from BUILDLOG.md / LEARNINGS.md

Compiled by reading both files in full. Excludes speculative "candidate only, not started"
feature ideas (trufflehog verified-secrets pass, TOON-encoding, the scanner-stack/dedup
architecture review, dalfox DAST mode) — those are proposals, not flagged gaps.

1. No rate limiting on the public scan endpoints — if the scan-box password ever leaks, scan
   volume (and Anthropic API / compute cost) is uncapped. — BUILDLOG.md, "Pending" § Deploy, item 1
2. Dashboard severity counter drops trivy findings with severity `"UNKNOWN"` from the
   critical/high/medium/low buckets, even though they're in the total count. — LEARNINGS.md § scanning (2026-08-08)
3. `/scan/url` records the tempdir clone path (e.g. `/tmp/vuln-hunter-scan-xqr4dar1`) in
   telemetry instead of the real scanned URL, so "Repo staleness" entries are meaningless. — LEARNINGS.md § scanning (2026-08-08); BUILDLOG.md "Dashboard: repo names + per-repo findings", item 1
4. No per-scan/per-repo findings view — dashboard only shows a global 24h rolling aggregate;
   needs a scan_id-scoped findings endpoint + UI (same underlying persistence gap as
   `findings_for_scan` in the new GraphQL scaffold). — BUILDLOG.md "Dashboard: repo names + per-repo findings", item 2
5. Untracked stray `vuln-hunter/` nested folder at repo root (own `.git`, old BUILDLOG) —
   flagged "needs a look" 2026-08-06, still present (confirmed in current `git status`). — BUILDLOG.md, 2026-08-06 entry
6. Gitleaks not wired into `/scan/diff` — proper diff-scoped history-secret scanning needs
   `--log-opts` commit-range scoping; marked as a real follow-up, not done. — BUILDLOG.md, 2026-07-24 gitleaks entry
7. Cost-tiering for the triage LLM never built (relevant only if public access ever opens up
   beyond the password-gated box). — BUILDLOG.md "Pending" § Deploy, item 2
8. Frontend Next.js 16.2.6→16.3.0 bump needed to clear 3 high-severity `npm audit` findings
   (next/postcss/sharp) — deliberately deferred, outside the pinned range. — BUILDLOG.md "Other pending"
9. Custom semgrep rules are Python-only; no JS/TS (or other language) coverage written yet. — BUILDLOG.md "Other pending" + "Known limitations"
10. `deep_review` (business-logic AI pass) has no frontend UI — API-only. — BUILDLOG.md "Other pending"
11. Dashboard telemetry not wired into `scan_diff`'s `deep_review` path (only `run_full_scan`/`run_diff_scan` are instrumented). — BUILDLOG.md "Other pending"
12. Live deploy not yet linked from the GitHub profile/README. — BUILDLOG.md "Pending" § Deploy, item 3
13. GitHub-profile "watch it scan live" theatrical demo — explicitly deferred by Chris, not started. — BUILDLOG.md "Pending" § Deploy, item 4
14. `mcp_process_count` "6 simultaneous processes" lead corroborated live but never root-caused. — BUILDLOG.md "Other pending"
15. Undecided: whether to merge ponytail-style cleanup into vuln-hunter (recommended against a
    single merged tool; no final decision made). — BUILDLOG.md "Other pending"
16. Stale `C:\Repos\vuln-hunter.zip` (301MB) confirmed safe to delete, not yet deleted. — BUILDLOG.md, 2026-08-06 entry
