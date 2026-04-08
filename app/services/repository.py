from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import Finding
from app.services.schemas import FindingCreate


def create_findings(db: Session, findings: Iterable[FindingCreate]) -> int:
    rows = [Finding(**item.model_dump()) for item in findings]
    db.add_all(rows)
    db.commit()
    return len(rows)


def list_findings(db: Session, limit: int = 100) -> list[Finding]:
    stmt = select(Finding).order_by(Finding.scanned_at.desc()).limit(limit)
    return list(db.scalars(stmt).all())
