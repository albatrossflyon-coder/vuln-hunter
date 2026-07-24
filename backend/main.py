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
from dep_scan import run_pip_audit_scan
from gitleaks import run_gitleaks_scan
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


def _rule_based_findings(repo_path: str, files: list[str] | None = None) -> list[dict]:
    try:
        findings = run_scan(repo_path, files=files)
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
    repo_path = _resolve_repo_dir(request.repo_path)
    findings = _rule_based_findings(repo_path)
    # Git-history secret scan and dependency CVE scan, both deterministic --
    # skip triage.py entirely (see gitleaks.py / dep_scan.py for why).
    findings += run_gitleaks_scan(repo_path)
    findings += run_pip_audit_scan(repo_path)
    kept, ignored_count = _finalize(repo_path, findings)
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

    # ponytail: does NOT run the gitleaks history scan (see /scan and
    # /scan/sarif) -- "diff-only" doesn't map cleanly onto history scanning,
    # since an old secret from 5 commits back has nothing to do with what
    # changed in *this* diff. Doing it properly means scoping gitleaks to the
    # commit range via --log-opts, a separate feature. Add when diff/CI scans
    # specifically need to catch secrets introduced by the diff itself.
    """
    repo_path = _resolve_repo_dir(request.repo_path)
    try:
        changed_files = get_changed_files(repo_path, request.base_ref)
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))

    findings = _rule_based_findings(repo_path, files=changed_files)
    if request.deep_review:
        findings += business_logic.review_files(changed_files)
    # Unlike gitleaks (whole-history scan, doesn't fit diff-only), a
    # dependency CVE check genuinely is diff-scoped: only worth re-running
    # when requirements.txt itself is one of the changed files.
    if any(Path(f).name == "requirements.txt" for f in changed_files):
        findings += run_pip_audit_scan(repo_path)

    kept, ignored_count = _finalize(repo_path, findings)
    return ScanResponse(findings=kept, total=len(kept), ignored_count=ignored_count)


@app.post("/scan/sarif")
async def scan_sarif(request: ScanRequest):
    """Same scan, returned as SARIF 2.1.0 for GitHub Security tab / CI tooling."""
    repo_path = _resolve_repo_dir(request.repo_path)
    findings = _rule_based_findings(repo_path)
    findings += run_gitleaks_scan(repo_path)
    findings += run_pip_audit_scan(repo_path)
    kept, _ = _finalize(repo_path, findings)
    return JSONResponse(content=to_sarif(kept))


@app.post("/ignore")
async def ignore_finding(request: IgnoreRequest):
    """Mark a finding as safe so it doesn't resurface on future scans of this repo."""
    repo_path = _resolve_repo_dir(request.repo_path)
    ignore_store.add_ignore(repo_path, request.fingerprint, request.rule_id, request.path, request.reason)
    return {"status": "ignored", "fingerprint": request.fingerprint}


@app.delete("/ignore/{fingerprint_id}")
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


if __name__ == "__main__":
    import uvicorn

    # Local-only by default: this API can scan arbitrary filesystem paths and has
    # no authentication, so it must never be reachable from the network by default.
    uvicorn.run(app, host=os.getenv("API_HOST", "127.0.0.1"), port=int(os.getenv("API_PORT", "8001")))
