from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class FindingCreate(BaseModel):
    resource_type: str
    resource_id: str
    issue: str
    severity: str
    score: float
    details: str


class FindingRead(FindingCreate):
    id: int
    scanned_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanResponse(BaseModel):
    message: str
    findings_created: int
    report_files: list[str]
