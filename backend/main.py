"""FastAPI server: POST /scan {repo_path} -> triaged security findings."""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import business_logic
import ignore_store
from sarif import to_sarif
from scanner import get_changed_files, run_scan
from triage import triage_all

app = FastAPI(title="vuln-hunter", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_URL", "http://localhost:3000")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


def _rule_based_findings(repo_path: str, files: list[str] | None = None) -> list[dict]:
    target = Path(repo_path)
    if not target.exists():
        raise HTTPException(status_code=400, detail=f"Path does not exist: {repo_path}")
    try:
        findings = run_scan(str(target), files=files)
        return triage_all(findings)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


def _finalize(repo_path: str, findings: list[dict]) -> tuple[list[dict], int]:
    """Apply the ignore-list filter across all finding types together, return (kept, ignored_count)."""
    raw_total = len(findings)
    kept = ignore_store.filter_ignored(repo_path, findings)
    return kept, raw_total - len(kept)


@app.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
    findings = _rule_based_findings(request.repo_path)
    kept, ignored_count = _finalize(request.repo_path, findings)
    return ScanResponse(findings=kept, total=len(kept), ignored_count=ignored_count)


@app.post("/scan/diff", response_model=ScanResponse)
async def scan_diff(request: DiffScanRequest):
    """Scan only files changed vs base_ref (default: uncommitted changes) instead
    of the whole repo -- for practical PR/CI use where re-scanning everything
    on every push doesn't scale.

    deep_review=True additionally runs a second AI reasoning pass (business_logic.py)
    per changed file, looking for access-control/business-logic issues rule-matching
    can't express. Kept diff-scan-only since it's per-file-expensive; running it
    against a whole repo on every scan wouldn't scale the same way rule scanning does.
    """
    try:
        changed_files = get_changed_files(request.repo_path, request.base_ref)
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))

    findings = _rule_based_findings(request.repo_path, files=changed_files)
    if request.deep_review:
        findings += business_logic.review_files(changed_files)

    kept, ignored_count = _finalize(request.repo_path, findings)
    return ScanResponse(findings=kept, total=len(kept), ignored_count=ignored_count)


@app.post("/scan/sarif")
async def scan_sarif(request: ScanRequest):
    """Same scan, returned as SARIF 2.1.0 for GitHub Security tab / CI tooling."""
    findings = _rule_based_findings(request.repo_path)
    kept, _ = _finalize(request.repo_path, findings)
    return JSONResponse(content=to_sarif(kept))


@app.post("/ignore")
async def ignore_finding(request: IgnoreRequest):
    """Mark a finding as safe so it doesn't resurface on future scans of this repo."""
    ignore_store.add_ignore(request.repo_path, request.fingerprint, request.rule_id, request.path, request.reason)
    return {"status": "ignored", "fingerprint": request.fingerprint}


@app.delete("/ignore/{fingerprint_id}")
async def unignore_finding(fingerprint_id: str, repo_path: str):
    removed = ignore_store.remove_ignore(repo_path, fingerprint_id)
    if not removed:
        raise HTTPException(status_code=404, detail="No such ignored finding")
    return {"status": "unignored", "fingerprint": fingerprint_id}


@app.get("/ignored")
async def list_ignored(repo_path: str):
    return ignore_store.load_ignored(repo_path)


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    # Local-only by default: this API can scan arbitrary filesystem paths and has
    # no authentication, so it must never be reachable from the network by default.
    uvicorn.run(app, host=os.getenv("API_HOST", "127.0.0.1"), port=int(os.getenv("API_PORT", "8001")))
