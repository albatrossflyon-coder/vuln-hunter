"""FastAPI server: POST /scan {repo_path} -> triaged security findings."""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from scanner import run_scan
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
    explanation: str
    exploitability: str
    suggested_fix: str


class ScanResponse(BaseModel):
    findings: list[Finding]
    total: int


@app.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
    target = Path(request.repo_path)
    if not target.exists():
        raise HTTPException(status_code=400, detail=f"Path does not exist: {request.repo_path}")

    try:
        findings = run_scan(str(target))
        triaged = triage_all(findings)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

    return ScanResponse(findings=triaged, total=len(triaged))


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("API_PORT", "8001")))
