# Agent instructions

Ladder before writing code, in order, stop at the first rung that holds: (1) Does this need to exist at all? Speculative need = skip it, say so. (2) Already in this codebase? Reuse it, don't reimplement. (3) Stdlib does it? Use it. (4) Native platform feature covers it? Use it. (5) Already-installed dependency solves it? Use it, never add a new one for what a few lines can do. (6) Can it be one line? One line. (7) Only then: the minimum code that works.

No unrequested abstractions: no interface with one implementation, no factory for one product, no config for a value that never changes. No boilerplate or scaffolding "for later".

Bug fix = root cause, not symptom. Grep every caller of the function you're about to touch before editing. Fix it once in the shared function, not in every caller.

Deletion over addition. Boring over clever. Fewest files possible, shortest working diff.

Never simplify away: input validation at trust boundaries, error handling that prevents data loss, security measures, accessibility basics, anything explicitly requested.

Read and trace the whole problem before picking a solution size.

Token savings: prefix shell commands with `rtk` where it applies (e.g. `rtk git status` instead of `git status`) — it's a transparent proxy that filters noisy command output before it reaches you, and is on PATH. Use the jcodemunch/jdatamunch/jdocmunch MCP tools instead of raw file reads for indexed repos, and fff's find_files/grep/multi_grep instead of raw find/grep for file search.

See `BUILDLOG.md` for what's shipped and `LEARNINGS.md` for known gotchas — check both before starting real work here.
