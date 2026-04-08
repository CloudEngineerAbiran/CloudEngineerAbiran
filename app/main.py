from __future__ import annotations

from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session

from app.models.database import SessionLocal, init_db
from app.services.orchestrator import run_all_scans
from app.services.reporting import generate_report
from app.services.repository import create_findings, list_findings
from app.services.schemas import FindingRead, ScanResponse
from app.utils.logging import configure_logging

configure_logging()
init_db()

app = FastAPI(title="Cloud Vulnerability Scanner", version="1.0.0")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan/run", response_model=ScanResponse)
def run_scan(db: Session = Depends(get_db)) -> ScanResponse:
    findings = run_all_scans()
    count = create_findings(db, findings) if findings else 0
    report_files = generate_report(findings)
    return ScanResponse(message="scan_complete", findings_created=count, report_files=report_files)


@app.get("/findings", response_model=list[FindingRead])
def get_findings(limit: int = 100, db: Session = Depends(get_db)) -> list[FindingRead]:
    return [FindingRead.model_validate(row) for row in list_findings(db, limit=limit)]
