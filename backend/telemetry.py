"""SQLite + JSONL telemetry for vuln-hunter's own scan pipeline.

Two writers for every event: SQLite (for queries) and an append-only JSONL
file (for crash survivability -- a corrupted/locked SQLite file or a mid-write
process kill shouldn't erase the record of what just happened, which is
exactly the gap that made last night's scan_repo crash on openwork
undiagnosable: zero traceback captured anywhere).

A "hung" or "crashed" scan can never self-report -- the scanning code that
would call complete_scan() is exactly what stopped running. reconcile_stale()
closes that gap by inferring HUNG/CRASHED from scans still RUNNING past the
MCP idle timeout, using whether an mcp_server.py process is still alive to
tell the two apart. Callers (the telemetry endpoints, the TUI) should call
this before reading summaries so stale rows get resolved instead of showing
as perpetually "RUNNING".
"""

import json
import sqlite3
import time
import traceback
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

import psutil

import ignore_store

DB_PATH = Path(__file__).parent / "vuln_hunter_telemetry.db"
JSONL_PATH = Path(__file__).parent / "vuln_hunter_events.jsonl"

# Matches mcp_server.py's Claude-Code-side idle timeout: past this with no
# end_time, a RUNNING scan is presumed dead, not just slow.
STALL_TIMEOUT_SEC = 1800

SCANNERS = ("semgrep", "gitleaks", "pip-audit", "trivy")


def scanner_for_rule_id(rule_id: str) -> str:
    """Derive which scanner produced a finding from its rule_id prefix --
    see all_scanners.py callers (gitleaks.py/dep_scan.py/trivy_scan.py each
    prefix their rule_id; scanner.py's semgrep findings use the bare
    check_id, no prefix)."""
    for prefix in ("gitleaks.", "pip-audit.", "trivy."):
        if rule_id.startswith(prefix):
            return prefix.rstrip(".")
    return "semgrep"


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with _connect() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            repo_path TEXT NOT NULL,
            tool TEXT NOT NULL,
            status TEXT CHECK(status IN ('RUNNING','COMPLETED','FAILED','HUNG','CRASHED')) NOT NULL,
            start_time REAL NOT NULL,
            end_time REAL,
            duration_sec REAL,
            repo_size_bytes INTEGER,
            language_mix TEXT,
            error_reason TEXT
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS scanner_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
            scanner_name TEXT NOT NULL,
            findings_count INTEGER NOT NULL DEFAULT 0,
            critical_count INTEGER NOT NULL DEFAULT 0,
            high_count INTEGER NOT NULL DEFAULT 0,
            medium_count INTEGER NOT NULL DEFAULT 0,
            low_count INTEGER NOT NULL DEFAULT 0
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT REFERENCES scans(scan_id) ON DELETE SET NULL,
            event_type TEXT CHECK(event_type IN ('INFO','WARN','ERROR','STOPPER_BUG')) NOT NULL,
            component TEXT NOT NULL,
            message TEXT NOT NULL,
            stack_trace TEXT,
            timestamp REAL NOT NULL
        );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_start ON scans(start_time);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(repo_path);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);")


def _append_jsonl(record: Dict[str, Any]) -> None:
    with open(JSONL_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")


def log_event(
    event_type: str,
    component: str,
    message: str,
    scan_id: Optional[str] = None,
    exc: Optional[BaseException] = None,
) -> None:
    stack = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)) if exc else None
    now = time.time()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO events (scan_id, event_type, component, message, stack_trace, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, event_type, component, message, stack, now),
        )
    _append_jsonl({
        "kind": "event", "scan_id": scan_id, "event_type": event_type,
        "component": component, "message": message, "stack_trace": stack, "timestamp": now,
    })


def start_scan(repo_path: str, tool: str, repo_size_bytes: int = 0, language_mix: Optional[Dict[str, float]] = None) -> str:
    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    now = time.time()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO scans (scan_id, repo_path, tool, status, start_time, repo_size_bytes, language_mix) "
            "VALUES (?, ?, ?, 'RUNNING', ?, ?, ?)",
            (scan_id, repo_path, tool, now, repo_size_bytes, json.dumps(language_mix or {})),
        )
    _append_jsonl({"kind": "scan_start", "scan_id": scan_id, "repo_path": repo_path, "tool": tool, "timestamp": now})
    return scan_id


def complete_scan(scan_id: str, status: str = "COMPLETED", error_reason: Optional[str] = None) -> None:
    now = time.time()
    with _connect() as conn:
        row = conn.execute("SELECT start_time FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        duration = now - row["start_time"] if row else None
        conn.execute(
            "UPDATE scans SET status = ?, end_time = ?, duration_sec = ?, error_reason = ? WHERE scan_id = ?",
            (status, now, duration, error_reason, scan_id),
        )
    _append_jsonl({"kind": "scan_end", "scan_id": scan_id, "status": status, "error_reason": error_reason, "timestamp": now})
    log_event("INFO" if status == "COMPLETED" else "ERROR", "orchestrator", f"scan {status}: {error_reason or 'ok'}", scan_id=scan_id)


def log_stopper_bug(scan_id: str, component: str, message: str, exc: Optional[BaseException] = None) -> None:
    log_event("STOPPER_BUG", component, message, scan_id=scan_id, exc=exc)
    complete_scan(scan_id, status="CRASHED", error_reason=message)


def record_scan_results(scan_id: str, invoked_scanners: List[str], findings: List[Dict[str, Any]]) -> None:
    """One scanner_metrics row per scanner in invoked_scanners (all_scanners.py's
    diff-scan path conditionally skips gitleaks/pip-audit/trivy -- pass only
    what this specific scan actually ran). A scanner with zero matching
    findings still gets an explicit 0 row, so get_telemetry_summary's
    silent-zero check can tell "ran clean" apart from "never invoked"."""
    buckets: Dict[str, List[Dict[str, Any]]] = {name: [] for name in invoked_scanners}
    for f in findings:
        buckets.setdefault(scanner_for_rule_id(f.get("rule_id", "")), []).append(f)

    with _connect() as conn:
        for scanner_name, items in buckets.items():
            sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in items:
                key = (f.get("exploitability") or "").lower()
                if key in sev:
                    sev[key] += 1
            conn.execute(
                "INSERT INTO scanner_metrics (scan_id, scanner_name, findings_count, critical_count, high_count, medium_count, low_count) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, scanner_name, len(items), sev["critical"], sev["high"], sev["medium"], sev["low"]),
            )


def list_mcp_pids() -> List[int]:
    pids = []
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            if p.info["cmdline"] and any("mcp_server.py" in part for part in p.info["cmdline"]):
                pids.append(p.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return pids


def reconcile_stale(timeout_sec: int = STALL_TIMEOUT_SEC) -> int:
    """Resolve scans stuck in RUNNING past timeout_sec into HUNG or CRASHED.
    Returns the number resolved. Safe to call on every dashboard poll --
    only touches rows that are actually stale."""
    cutoff = time.time() - timeout_sec
    alive = bool(list_mcp_pids())
    resolved = 0
    with _connect() as conn:
        stale = conn.execute(
            "SELECT scan_id, repo_path, tool FROM scans WHERE status = 'RUNNING' AND start_time < ?", (cutoff,)
        ).fetchall()
        for row in stale:
            status = "HUNG" if alive else "CRASHED"
            reason = (
                "Scan exceeded stall timeout with no completion signal"
                if alive
                else "mcp_server.py process no longer running -- scan lost with it"
            )
            conn.execute(
                "UPDATE scans SET status = ?, end_time = ?, error_reason = ? WHERE scan_id = ?",
                (status, time.time(), reason, row["scan_id"]),
            )
            resolved += 1
    return resolved


def get_telemetry_summary(hours: int = 24) -> Dict[str, Any]:
    reconcile_stale()
    cutoff = time.time() - hours * 3600
    with _connect() as conn:
        scans = conn.execute(
            "SELECT status, duration_sec FROM scans WHERE start_time >= ? AND duration_sec IS NOT NULL",
            (cutoff,),
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) c FROM scans WHERE start_time >= ?", (cutoff,)).fetchone()["c"]
        completed = sum(1 for s in scans if s["status"] == "COMPLETED")
        hung = sum(1 for s in scans if s["status"] == "HUNG")
        crashed = sum(1 for s in scans if s["status"] == "CRASHED")

        durations = sorted(s["duration_sec"] for s in scans if s["duration_sec"] is not None)
        p50 = durations[len(durations) // 2] if durations else 0.0
        p90 = durations[int(len(durations) * 0.9)] if durations else 0.0

        scanner_rows = conn.execute(
            """
            SELECT sm.scanner_name,
                   SUM(sm.findings_count) total_findings,
                   SUM(sm.critical_count) critical, SUM(sm.high_count) high,
                   SUM(sm.medium_count) medium, SUM(sm.low_count) low,
                   COUNT(*) scan_count
            FROM scanner_metrics sm JOIN scans s ON sm.scan_id = s.scan_id
            WHERE s.start_time >= ? GROUP BY sm.scanner_name
            """,
            (cutoff,),
        ).fetchall()
        scanner_volumes = {r["scanner_name"]: r["total_findings"] for r in scanner_rows}
        severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in scanner_rows:
            severity["critical"] += r["critical"] or 0
            severity["high"] += r["high"] or 0
            severity["medium"] += r["medium"] or 0
            severity["low"] += r["low"] or 0

        silent_zero = [
            r["scanner_name"] for r in scanner_rows
            if r["total_findings"] == 0 and r["scan_count"] > 0
        ]

        bugs = conn.execute(
            "SELECT COUNT(*) c FROM events WHERE event_type = 'STOPPER_BUG' AND timestamp >= ?", (cutoff,)
        ).fetchone()["c"]

        repo_paths = {r["repo_path"] for r in conn.execute("SELECT DISTINCT repo_path FROM scans WHERE start_time >= ?", (cutoff,))}

    # ponytail: ignore_store keeps a running per-repo list, not "ignored within
    # this window" -- so this is total-currently-ignored / findings-seen-in-window,
    # an approximation, not a precise per-window ratio. Good enough for a trend
    # indicator; revisit if it ever needs to be exact.
    total_findings = sum(scanner_volumes.values())
    total_ignored = sum(len(ignore_store.load_ignored(rp)) for rp in repo_paths)
    fp_rate = (total_ignored / total_findings * 100.0) if total_findings else 0.0

    success_rate = (completed / total * 100.0) if total else 100.0
    return {
        "window_hours": hours,
        "total_scans": total,
        "completed": completed,
        "hung": hung,
        "crashed": crashed,
        "success_rate": round(success_rate, 1),
        "p50_duration_sec": round(p50, 1),
        "p90_duration_sec": round(p90, 1),
        "p90_near_timeout": p90 > 1200,
        "scanner_volumes": scanner_volumes,
        "silent_zero_scanners": silent_zero,
        "severity_breakdown": severity,
        "fp_rate": round(fp_rate, 1),
        "stopper_bugs_count": bugs,
        "mcp_process_count": len(list_mcp_pids()),
    }


def get_repo_staleness() -> List[Dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT repo_path, MAX(CASE WHEN status = 'COMPLETED' THEN end_time END) last_success,
                   MAX(start_time) last_attempt,
                   (SELECT status FROM scans s2 WHERE s2.repo_path = s1.repo_path ORDER BY start_time DESC LIMIT 1) last_status
            FROM scans s1 GROUP BY repo_path ORDER BY last_attempt DESC
            """
        ).fetchall()
    now = time.time()
    return [
        {
            "repo_path": r["repo_path"],
            "last_success_ago_sec": (now - r["last_success"]) if r["last_success"] else None,
            "last_status": r["last_status"],
        }
        for r in rows
    ]


def get_recent_events(limit: int = 30) -> List[Dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT event_id, scan_id, event_type, component, message, stack_trace, timestamp "
            "FROM events ORDER BY event_id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


init_db()
