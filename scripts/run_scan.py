from app.models.database import SessionLocal, init_db
from app.services.orchestrator import run_all_scans
from app.services.reporting import generate_report
from app.services.repository import create_findings


if __name__ == "__main__":
    init_db()
    findings = run_all_scans()
    with SessionLocal() as db:
        created = create_findings(db, findings) if findings else 0
    reports = generate_report(findings)
    print(f"Completed. findings={created} reports={reports}")
