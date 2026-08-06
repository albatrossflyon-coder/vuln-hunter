"""FastAPI server: POST /scan {repo_path} -> triaged security findings."""

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import all_scanners
import ignore_store
import telemetry
from sarif import to_sarif
from scanner import get_changed_files

# Only http(s) git URLs -- this box runs on your own machine against your own
# git binary, so it's equivalent to typing `git clone <url>` yourself. This
# just blocks the obviously-wrong inputs (local paths, non-git schemes).
_GIT_URL_RE = re.compile(r"^https?://\S+$")

app = FastAPI(title="vuln-hunter", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_URL", "http://localhost:3000")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def require_scan_key(x_api_key: str | None = Header(default=None)):
    """Gate the scan-triggering endpoints behind SCAN_API_KEY. Unset locally
    on purpose -- local dev/CLI use stays frictionless. Only the hosted
    instance sets this, so only the hosted instance enforces it. Read-only
    /telemetry/* and /health stay open regardless -- that's the public demo.
    """
    expected = os.getenv("SCAN_API_KEY")
    if expected and x_api_key != expected:
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key")


class ScanRequest(BaseModel):
    repo_path: str


class DiffScanRequest(BaseModel):
    repo_path: str
    base_ref: str = "HEAD"
    deep_review: bool = False


class Finding(BaseModel):
    rule_id: str
    path: str
    start_line: int
    end_line: int
    message: str
    severity: str
    cwe: str | None = None
    owasp: str | None = None
    snippet: str
    matched_code: str
    explanation: str
    exploitability: str
    suggested_fix: str
    fingerprint: str
    finding_type: str = "rule_confirmed"


class ScanResponse(BaseModel):
    findings: list[Finding]
    total: int
    ignored_count: int


class IgnoreRequest(BaseModel):
    repo_path: str
    fingerprint: str
    rule_id: str = ""
    path: str = ""
    reason: str = ""


def _resolve_repo_dir(repo_path: str) -> str:
    """Resolve repo_path to a canonical absolute path and verify it's a real
    directory before it's ever used for file I/O or handed to a subprocess.

    Deliberately does not restrict to a single allowed root: scanning
    arbitrary local repos by path is this tool's whole point (job-hunter,
    rag-system, this repo, etc. all live in different places), so there's
    no single jail directory that would fit. Resolving up front still closes
    the real gap: every caller downstream previously received the raw,
    unvalidated request string as-is.
    """
    target = Path(repo_path).resolve()
    if not target.is_dir():
        raise HTTPException(status_code=400, detail=f"Not a directory: {repo_path}")
    return str(target)


def _finalize(repo_path: str, findings: list[dict]) -> tuple[list[dict], int]:
    """Apply the ignore-list filter across all finding types together, return (kept, ignored_count)."""
    raw_total = len(findings)
    kept = ignore_store.filter_ignored(repo_path, findings)
    return kept, raw_total - len(kept)


@app.post("/scan", response_model=ScanResponse, dependencies=[Depends(require_scan_key)])
async def scan(request: ScanRequest):
    repo_path = _resolve_repo_dir(request.repo_path)
    scan_id = telemetry.start_scan(repo_path, tool="rest:/scan")
    try:
        findings = all_scanners.run_full_scan(repo_path)
    except RuntimeError as e:
        telemetry.log_stopper_bug(scan_id, "main./scan", str(e), exc=e)
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        telemetry.log_stopper_bug(scan_id, "main./scan", f"unexpected: {e}", exc=e)
        raise
    telemetry.record_scan_results(scan_id, all_scanners.FULL_SCAN_SCANNERS, findings)
    kept, ignored_count = _finalize(repo_path, findings)
    telemetry.complete_scan(scan_id, status="COMPLETED")
    return ScanResponse(findings=kept, total=len(kept), ignored_count=ignored_count)


class ScanUrlRequest(BaseModel):
    url: str


@app.post("/scan/url", response_model=ScanResponse, dependencies=[Depends(require_scan_key)])
async def scan_url(request: ScanUrlRequest):
    """Clone a git URL into a scratch dir and run the same scan /scan does.
    Local-only feature (this server binds 127.0.0.1) -- equivalent to running
    `git clone` yourself, not a public-facing capability.
    """
    if not _GIT_URL_RE.match(request.url.strip()):
        raise HTTPException(status_code=400, detail="Expected an http(s) git URL")

    dest = tempfile.mkdtemp(prefix="vuln-hunter-scan-")
    try:
        clone = subprocess.run(
            ["git", "clone", "--depth", "1", request.url.strip(), dest],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if clone.returncode != 0:
            raise HTTPException(status_code=400, detail=f"git clone failed: {clone.stderr.strip()[:500]}")

        scan_id = telemetry.start_scan(dest, tool="rest:/scan/url")
        try:
            findings = all_scanners.run_full_scan(dest)
        except RuntimeError as e:
            telemetry.log_stopper_bug(scan_id, "main./scan/url", str(e), exc=e)
            raise HTTPException(status_code=500, detail=str(e))
        except Exception as e:
            telemetry.log_stopper_bug(scan_id, "main./scan/url", f"unexpected: {e}", exc=e)
            raise
        telemetry.record_scan_results(scan_id, all_scanners.FULL_SCAN_SCANNERS, findings)
        kept, ignored_count = _finalize(dest, findings)
        telemetry.complete_scan(scan_id, status="COMPLETED")
        return ScanResponse(findings=kept, total=len(kept), ignored_count=ignored_count)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=400, detail="git clone timed out after 120s")
    finally:
        shutil.rmtree(dest, ignore_errors=True)


@app.post("/scan/diff", response_model=ScanResponse, dependencies=[Depends(require_scan_key)])
async def scan_diff(request: DiffScanRequest):
    """Scan only files changed vs base_ref (default: uncommitted changes) instead
    of the whole repo -- for practical PR/CI use where re-scanning everything
    on every push doesn't scale.

    deep_review=True additionally runs a second AI reasoning pass (business_logic.py)
    per changed file, looking for access-control/business-logic issues rule-matching
    can't express. Kept diff-scan-only since it's per-file-expensive; running it
    against a whole repo on every scan wouldn't scale the same way rule scanning does.

    Scanner selection (which of gitleaks/pip-audit/trivy actually run here) lives
    in all_scanners.run_diff_scan -- see its docstring for the reasoning.
    """
    repo_path = _resolve_repo_dir(request.repo_path)
    try:
        changed_files = get_changed_files(repo_path, request.base_ref)
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))

    scan_id = telemetry.start_scan(repo_path, tool="rest:/scan/diff")
    try:
        findings = all_scanners.run_diff_scan(repo_path, changed_files, deep_review=request.deep_review)
    except RuntimeError as e:
        telemetry.log_stopper_bug(scan_id, "main./scan/diff", str(e), exc=e)
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        telemetry.log_stopper_bug(scan_id, "main./scan/diff", f"unexpected: {e}", exc=e)
        raise

    telemetry.record_scan_results(scan_id, all_scanners.diff_scanners_invoked(changed_files), findings)
    kept, ignored_count = _finalize(repo_path, findings)
    telemetry.complete_scan(scan_id, status="COMPLETED")
    return ScanResponse(findings=kept, total=len(kept), ignored_count=ignored_count)


@app.post("/scan/sarif", dependencies=[Depends(require_scan_key)])
async def scan_sarif(request: ScanRequest):
    """Same scan, returned as SARIF 2.1.0 for GitHub Security tab / CI tooling."""
    repo_path = _resolve_repo_dir(request.repo_path)
    try:
        findings = all_scanners.run_full_scan(repo_path)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    kept, _ = _finalize(repo_path, findings)
    return JSONResponse(content=to_sarif(kept))


@app.post("/ignore", dependencies=[Depends(require_scan_key)])
async def ignore_finding(request: IgnoreRequest):
    """Mark a finding as safe so it doesn't resurface on future scans of this repo."""
    repo_path = _resolve_repo_dir(request.repo_path)
    ignore_store.add_ignore(repo_path, request.fingerprint, request.rule_id, request.path, request.reason)
    return {"status": "ignored", "fingerprint": request.fingerprint}


@app.delete("/ignore/{fingerprint_id}", dependencies=[Depends(require_scan_key)])
async def unignore_finding(fingerprint_id: str, repo_path: str):
    repo_path = _resolve_repo_dir(repo_path)
    removed = ignore_store.remove_ignore(repo_path, fingerprint_id)
    if not removed:
        raise HTTPException(status_code=404, detail="No such ignored finding")
    return {"status": "unignored", "fingerprint": fingerprint_id}


@app.get("/ignored")
async def list_ignored(repo_path: str):
    repo_path = _resolve_repo_dir(repo_path)
    return ignore_store.load_ignored(repo_path)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/telemetry/summary")
async def telemetry_summary(hours: int = 24):
    return telemetry.get_telemetry_summary(hours=hours)


@app.get("/telemetry/repos")
async def telemetry_repos():
    return telemetry.get_repo_staleness()


@app.get("/telemetry/events")
async def telemetry_events(limit: int = 30):
    return telemetry.get_recent_events(limit=limit)


if __name__ == "__main__":
    import uvicorn

    # Local-only by default: this API can scan arbitrary filesystem paths and has
    # no authentication, so it must never be reachable from the network by default.
    uvicorn.run(app, host=os.getenv("API_HOST", "127.0.0.1"), port=int(os.getenv("API_PORT", "8001")))
